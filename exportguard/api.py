"""受控导出服务的 HTTP 接口（仅依赖 Python 标准库）。

路由：

    POST   /exports                                 创建导出申请
    GET    /exports                                 列出本租户申请
    GET    /exports/{case_id}                       导出全貌（状态/清单/批准/事件）
    POST   /exports/{case_id}/manifest              冻结并分级清单
    POST   /exports/{case_id}/approvals             记录批准
    POST   /exports/{case_id}/invalidate            文件变化，作废清单
    POST   /exports/{case_id}/chunks/{i}/claims     领取分片（幂等重试）
    POST   /exports/{case_id}/revoke                撤销
    GET    /exports/{case_id}/chunks                分片领取情况
    GET    /exports/{case_id}/inclusions            每个文件的纳入/批准/领取
    GET    /exports/{case_id}/audit                 审计摘要与一致性结论
    POST   /maintenance/expire                      主动扫描并置过期

租户通过 ``X-Tenant-Id`` 请求头传递；命令幂等键通过 ``Idempotency-Key``
请求头传递。生产部署时应替换为真实的身份与鉴权中间件。
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from datetime import timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .errors import ExportGuardError, NotFoundError, ValidationError
from .service import ExportGuardService
from .storage import EventStore

_CASE = r"(?P<case_id>[^/]+)"
_CHUNK = r"(?P<chunk_index>\d+)"

ROUTES: list[tuple[str, re.Pattern[str], str]] = [
    ("POST", re.compile(r"^/exports/?$"), "create"),
    ("GET", re.compile(r"^/exports/?$"), "list"),
    ("GET", re.compile(rf"^/exports/{_CASE}/?$"), "get"),
    ("POST", re.compile(rf"^/exports/{_CASE}/manifest/?$"), "manifest"),
    ("POST", re.compile(rf"^/exports/{_CASE}/approvals/?$"), "approve"),
    ("POST", re.compile(rf"^/exports/{_CASE}/invalidate/?$"), "invalidate"),
    ("POST", re.compile(rf"^/exports/{_CASE}/chunks/{_CHUNK}/claims/?$"), "claim"),
    ("POST", re.compile(rf"^/exports/{_CASE}/revoke/?$"), "revoke"),
    ("GET", re.compile(rf"^/exports/{_CASE}/chunks/?$"), "chunks"),
    ("GET", re.compile(rf"^/exports/{_CASE}/inclusions/?$"), "inclusions"),
    ("GET", re.compile(rf"^/exports/{_CASE}/audit/?$"), "audit"),
    ("POST", re.compile(r"^/maintenance/expire/?$"), "expire"),
]


class ExportGuardApp:
    """无状态装配对象：一把锁串行化对单个 SQLite 连接的写事务。"""

    def __init__(self, service: ExportGuardService) -> None:
        self.service = service
        self.lock = threading.Lock()

    # ------------------------------------------------------------ 分派

    def handle(
        self, method: str, path: str, headers: Any, body: bytes
    ) -> tuple[int, dict[str, Any]]:
        for route_method, pattern, action in ROUTES:
            if route_method != method:
                continue
            match = pattern.match(path)
            if match is None:
                continue
            tenant = headers.get("X-Tenant-Id")
            if not tenant and action not in ("expire",):
                raise ValidationError("缺少请求头 X-Tenant-Id")
            payload = self._parse_body(body)
            handler: Callable[..., dict[str, Any]] = getattr(self, f"_do_{action}")
            with self.lock:
                data = handler(tenant or "", match.groupdict(), payload, headers)
            return HTTPStatus.OK, data
        raise NotFoundError(f"没有匹配的接口：{method} {path}")

    @staticmethod
    def _parse_body(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"请求体不是合法 JSON：{exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError("请求体必须是 JSON 对象")
        return value

    # ------------------------------------------------------------ 动作

    def _do_create(self, tenant: str, groups: dict, payload: dict, headers: Any):
        result = self.service.create_export(
            tenant_id=tenant,
            applicant_id=payload.get("applicant_id", ""),
            business_purpose=payload.get("business_purpose", ""),
            recipient=payload.get("recipient", ""),
            case_id=payload.get("case_id"),
            idempotency_key=headers.get("Idempotency-Key"),
        )
        return result

    def _do_list(self, tenant: str, groups: dict, payload: dict, headers: Any):
        return {"case_ids": self.service.list_exports(tenant)}

    def _do_get(self, tenant: str, groups: dict, payload: dict, headers: Any):
        return self.service.get_export(groups["case_id"], tenant).to_dict()

    def _do_manifest(self, tenant: str, groups: dict, payload: dict, headers: Any):
        view = self.service.classify_manifest(
            case_id=groups["case_id"],
            tenant_id=tenant,
            actor_id=payload.get("actor_id", "system"),
            entries=payload.get("entries", []),
            chunk_size_bytes=int(payload.get("chunk_size_bytes", 0)),
        )
        return view.to_dict()

    def _do_approve(self, tenant: str, groups: dict, payload: dict, headers: Any):
        valid_for = payload.get("valid_for_seconds")
        view = self.service.record_approval(
            case_id=groups["case_id"],
            tenant_id=tenant,
            role=payload.get("role", ""),
            approver_id=payload.get("approver_id", ""),
            valid_for=None if valid_for is None else timedelta(seconds=int(valid_for)),
        )
        return view.to_dict()

    def _do_invalidate(self, tenant: str, groups: dict, payload: dict, headers: Any):
        view = self.service.invalidate_manifest(
            case_id=groups["case_id"],
            tenant_id=tenant,
            actor_id=payload.get("actor_id", "system"),
            changed_files=payload.get("changed_files", []),
            reason=payload.get("reason", ""),
        )
        return view.to_dict()

    def _do_claim(self, tenant: str, groups: dict, payload: dict, headers: Any):
        claim = self.service.claim_chunk(
            case_id=groups["case_id"],
            tenant_id=tenant,
            chunk_index=int(groups["chunk_index"]),
            claim_key=payload.get("claim_key", "") or headers.get("Idempotency-Key", ""),
            claimed_by=payload.get("claimed_by", ""),
        )
        return claim.to_dict()

    def _do_revoke(self, tenant: str, groups: dict, payload: dict, headers: Any):
        view = self.service.revoke(
            case_id=groups["case_id"],
            tenant_id=tenant,
            actor_id=payload.get("actor_id", "security"),
            reason=payload.get("reason", ""),
        )
        return view.to_dict()

    def _do_chunks(self, tenant: str, groups: dict, payload: dict, headers: Any):
        return {"chunks": self.service.chunks_status(groups["case_id"], tenant)}

    def _do_inclusions(self, tenant: str, groups: dict, payload: dict, headers: Any):
        items = self.service.file_inclusions(groups["case_id"], tenant)
        return {"inclusions": [item.to_dict() for item in items]}

    def _do_audit(self, tenant: str, groups: dict, payload: dict, headers: Any):
        return self.service.audit_summary(groups["case_id"], tenant)

    def _do_expire(self, tenant: str, groups: dict, payload: dict, headers: Any):
        return {"expired": self.service.expire_due(tenant or None)}


class _HeaderView:
    """对消息头做不区分大小写的查询。"""

    def __init__(self, handler: BaseHTTPRequestHandler) -> None:
        self._handler = handler

    def get(self, name: str) -> str | None:
        return self._handler.headers.get(name)


def make_handler(app: ExportGuardApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ExportGuard/0.1"

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length) if length else b""
            try:
                status, data = app.handle(method, self.path, _HeaderView(self), body)
                self._write(status, data)
            except ExportGuardError as exc:
                self._write(exc.http_status, exc.to_dict())

        def _write(self, status: int, data: dict[str, Any]) -> None:
            raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: Any) -> None:  # 安静一点
            return

    return Handler


def build_app(db_path: str = ":memory:") -> ExportGuardApp:
    store = EventStore(db_path)
    service = ExportGuardService(store)
    return ExportGuardApp(service)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="受控导出授权中枢 HTTP 服务")
    parser.add_argument("--db", default="data/exportguard.db", help="SQLite 数据库路径")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    app = build_app(args.db)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(app))
    print(f"受控导出服务监听 http://{args.host}:{args.port}（数据库：{args.db}）")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        app.service.store.close()


if __name__ == "__main__":
    main()
