"""受控导出的 HTTP 接口（仅依赖标准库）。

适合作为内网边车或参考实现启动：

    python3 -m export_guard.api --db ./guard.db --host 127.0.0.1 --port 8080

接口（:tenant 为 URL 路径中的租户标识）：

- ``POST   /tenants/:tenant/files``                 登记/更新文件台账
- ``POST   /tenants/:tenant/cases``                创建导出申请
- ``POST   /tenants/:tenant/cases/:case/manifest`` 冻结并分级清单
- ``POST   /tenants/:tenant/cases/:case/approvals`` 会签批准
- ``POST   /tenants/:tenant/cases/:case/chunks``    规划/续传分片
- ``POST   /tenants/:tenant/cases/:case/claims``    幂等领取分片
- ``POST   /tenants/:tenant/cases/:case/revoke``    撤销
- ``POST   /admin/sweep-expired``                   过期扫描
- ``GET    /tenants/:tenant/cases/:case``           阶段与当前清单
- ``GET    /tenants/:tenant/cases/:case/entries``   每个文件为何纳入/是否漂移
- ``GET    /tenants/:tenant/cases/:case/approvals`` 批准人与绑定要素
- ``GET    /tenants/:tenant/cases/:case/chunks``    分片与领取状态
- ``GET    /tenants/:tenant/cases/:case/claims``    领取与计费记录
- ``GET    /tenants/:tenant/cases/:case/events``    追加事件流
- ``GET    /tenants/:tenant/cases/:case/audit``     审计轨迹
- ``GET    /tenants/:tenant/cases/:case/verify``    清单与审计摘要对账

HTTP 层用单把请求锁串行化写操作；真正的幂等与互斥由数据库约束保证，
进程重启时调用 ``recover`` 把越过有效期的导出补齐为 expired。
"""
from __future__ import annotations

import argparse
import json
import threading
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .errors import ExportGuardError
from .service import ControlledExportService
from .store import Store
from .time import Clock, SystemClock


class ApiState:
    def __init__(self, db_path: str, clock: Clock | None = None) -> None:
        self.service = ControlledExportService(
            Store(db_path), clock=clock or SystemClock()
        )
        # 同一连接上的请求串行化；并发安全最终由 SQLite 事务与唯一约束兜底。
        self.request_lock = threading.RLock()
        # 重启恢复：状态已持久化，这里只补齐过期事实。
        self.service.recover()


def _iso_dt(raw: str) -> datetime:
    value = datetime.fromisoformat(raw)
    if value.tzinfo is None:
        raise ValueError("valid_until 必须携带时区，例如 2026-09-25T18:00:00+08:00")
    return value


class ExportGuardHandler(BaseHTTPRequestHandler):
    server_version = "ExportGuard/1.0"

    # ---- 工具 -----------------------------------------------------------

    def _state(self) -> ApiState:
        return self.server.state  # type: ignore[attr-defined]

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self._error(HTTPStatus.BAD_REQUEST, f"请求体不是合法 JSON：{exc}")
            raise _Handled()
        if not isinstance(body, dict):
            self._error(HTTPStatus.BAD_REQUEST, "请求体必须是 JSON 对象")
            raise _Handled()
        return body

    def _json(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def log_message(self, fmt: str, *args: Any) -> None:  # 安静化
        return

    # ---- 路由 -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        state = self._state()
        try:
            with state.request_lock:
                self._route(method, parts, state)
        except _Handled:
            return  # 错误响应已经写出
        except ExportGuardError as exc:
            status = _status_for(exc)
            self._error(status, str(exc))
        except (ValueError, KeyError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def _route(self, method: str, parts: list[str], state: ApiState) -> None:
        svc = state.service
        body = self._read_json_safe(method)

        if method == "POST" and parts == ["admin", "sweep-expired"]:
            actor = body.get("actor_id", "admin")
            return self._json(HTTPStatus.OK, {"expired": svc.sweep_expired(actor_id=actor)})

        if len(parts) >= 3 and parts[0] == "tenants":
            tenant = parts[1]
            tail = parts[2:]
            return self._tenant_route(method, tenant, tail, body, svc)

        self._error(HTTPStatus.NOT_FOUND, f"未知路径：{'/'.join(parts)}")

    def _read_json_safe(self, method: str) -> dict[str, Any]:
        if method != "POST":
            return {}
        try:
            return self._read_json()
        except (json.JSONDecodeError, ValueError):
            raise _Handled()

    def _tenant_route(self, method, tenant, tail, body, svc) -> None:
        # /tenants/:t/cases
        if method == "POST" and tail == ["cases"]:
            case = svc.create_request(
                tenant, body["case_id"], body["applicant_id"],
                body["business_purpose"], body["recipient_id"],
                actor_id=body.get("actor_id", body["applicant_id"]),
            )
            return self._json(HTTPStatus.CREATED, case)

        # /tenants/:t/files
        if method == "POST" and tail == ["files"]:
            svc.upsert_file(
                tenant, body["file_id"], body["file_version"], body["content_hash"],
                int(body["size_bytes"]), body["sensitivity"], body["source_location"],
                actor_id=body.get("actor_id", "cataloger"),
            )
            return self._json(HTTPStatus.OK, {"status": "recorded"})

        if len(tail) >= 2 and tail[0] == "cases":
            case_id = tail[1]
            action = tail[2:]
            return self._case_route(method, tenant, case_id, action, body, svc)

        self._error(HTTPStatus.NOT_FOUND, f"未知路径：{'/'.join(tail)}")

    def _case_route(self, method, tenant, case_id, action, body, svc) -> None:
        actor = body.get("actor_id", "admin")

        if method == "GET" and not action:
            return self._json(HTTPStatus.OK, svc.get_case(tenant, case_id))
        if method == "GET" and action == ["entries"]:
            version = body.get("manifest_version")
            return self._json(HTTPStatus.OK, svc.list_entries(tenant, case_id, version))
        if method == "GET" and action == ["approvals"]:
            return self._json(HTTPStatus.OK, svc.list_approvals(tenant, case_id))
        if method == "GET" and action == ["chunks"]:
            return self._json(HTTPStatus.OK, svc.list_chunks(tenant, case_id))
        if method == "GET" and action == ["claims"]:
            return self._json(HTTPStatus.OK, svc.list_claims(tenant, case_id))
        if method == "GET" and action == ["events"]:
            return self._json(HTTPStatus.OK, svc.event_history(tenant, case_id))
        if method == "GET" and action == ["audit"]:
            return self._json(HTTPStatus.OK, svc.audit_trail(tenant, case_id))
        if method == "GET" and action == ["verify"]:
            return self._json(HTTPStatus.OK, svc.verify_consistency(tenant, case_id))

        if method == "POST" and action == ["manifest"]:
            result = svc.freeze_manifest(tenant, case_id, body["entries"], actor_id=actor)
            return self._json(HTTPStatus.CREATED, result)
        if method == "POST" and action == ["approvals"]:
            result = svc.record_approval(
                tenant, case_id, body["role"], body["approver_id"],
                _iso_dt(body["valid_until"]),
                expected_manifest_version=body.get("expected_manifest_version"),
                actor_id=actor,
            )
            return self._json(HTTPStatus.OK, result)
        if method == "POST" and action == ["chunks"]:
            result = svc.prepare_chunks(tenant, case_id, body["chunk_plan"],
                                        actor_id=actor)
            return self._json(HTTPStatus.CREATED, result)
        if method == "POST" and action == ["claims"]:
            result = svc.claim_chunk(
                tenant, case_id, body["chunk_id"], body["recipient_id"],
                body["claim_key"], actor_id=actor,
            )
            return self._json(HTTPStatus.OK, result)
        if method == "POST" and action == ["revoke"]:
            result = svc.revoke(tenant, case_id, actor_id=actor,
                                reason=body.get("reason", ""))
            return self._json(HTTPStatus.OK, result)

        self._error(HTTPStatus.NOT_FOUND, f"未知动作：{'/'.join(action)}")


class _Handled(Exception):
    """错误响应已写出，仅用于跳出分发。"""


def _status_for(exc: ExportGuardError) -> int:
    from .errors import (
        ApprovalClosed,
        ChunkAlreadyClaimed,
        ClaimKeyConflict,
        DeliveryDenied,
        InvalidStateError,
        ManifestStale,
        NotFoundError,
        ScopeError,
    )
    mapping: dict[type[ExportGuardError], int] = {
        NotFoundError: HTTPStatus.NOT_FOUND,
        ScopeError: HTTPStatus.BAD_REQUEST,
        InvalidStateError: HTTPStatus.CONFLICT,
        ApprovalClosed: HTTPStatus.CONFLICT,
        ManifestStale: HTTPStatus.CONFLICT,
        DeliveryDenied: HTTPStatus.FORBIDDEN,
        ChunkAlreadyClaimed: HTTPStatus.CONFLICT,
        ClaimKeyConflict: HTTPStatus.CONFLICT,
    }
    for kind, status in mapping.items():
        if isinstance(exc, kind):
            return status
    return HTTPStatus.UNPROCESSABLE_ENTITY


def build_server(db_path: str, host: str = "127.0.0.1", port: int = 8080,
                 clock: Clock | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), ExportGuardHandler)
    server.state = ApiState(db_path, clock=clock)  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="受控导出授权中枢 HTTP 服务")
    parser.add_argument("--db", default="guard.db", help="SQLite 数据库路径")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    server = build_server(args.db, args.host, args.port)
    print(f"受控导出服务已启动：http://{args.host}:{args.port}（数据库 {args.db}）")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
