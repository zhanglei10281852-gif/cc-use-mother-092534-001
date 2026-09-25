"""HTTP 接口的端到端测试：直接分派 + 真实套接字冒烟。"""
from __future__ import annotations

import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Any

from exportguard.api import ExportGuardApp, make_handler
from exportguard.clock import FixedClock
from exportguard.service import ExportGuardService
from exportguard.storage import EventStore


class Headers:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = {k.lower(): v for k, v in (values or {}).items()}

    def get(self, name: str) -> str | None:
        return self._values.get(name.lower())


def entry(file_id: str, **over: Any):
    data = {
        "file_id": file_id,
        "path": f"/data/{file_id}.dat",
        "file_version": "v1",
        "content_hash": f"hash-{file_id}",
        "sensitivity": "normal",
        "size_bytes": 1,
        "owner_id": "owner-1",
        "included_reason": "范围内文件",
    }
    data.update(over)
    return data


class ApiDirectTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FixedClock()
        self.store = EventStore(":memory:")
        self.app = ExportGuardApp(ExportGuardService(self.store, clock=self.clock))
        self.tenant_headers = Headers({"X-Tenant-Id": "tenant-a"})

    def tearDown(self) -> None:
        self.store.close()

    def call(self, method: str, path: str, payload: dict | None = None,
             headers: Headers | None = None) -> tuple[int, dict]:
        body = json.dumps(payload).encode() if payload is not None else b""
        return self.app.handle(method, path, headers or self.tenant_headers, body)

    def test_full_confidential_flow_over_http(self):
        status, created = self.call("POST", "/exports", {
            "applicant_id": "operator-1",
            "business_purpose": "合规复盘",
            "recipient": "sftp://partner",
        })
        self.assertEqual(status, 200)
        case_id = created["case_id"]

        status, view = self.call("POST", f"/exports/{case_id}/manifest", {
            "actor_id": "reviewer-2",
            "entries": [entry("f1", sensitivity="confidential")],
            "chunk_size_bytes": 10_000,
        })
        self.assertEqual(view["state"], "awaiting_approval")

        status, view = self.call("POST", f"/exports/{case_id}/approvals", {
            "role": "data_owner", "approver_id": "owner-9",
        })
        status, view = self.call("POST", f"/exports/{case_id}/approvals", {
            "role": "security_officer", "approver_id": "soc-7",
        })
        self.assertEqual(view["state"], "approved")

        # 第一次领取与同键重试。
        status, first = self.call("POST", f"/exports/{case_id}/chunks/0/claims", {
            "claim_key": "claim-1", "claimed_by": "operator-1",
        })
        self.assertEqual(status, 200)
        self.assertFalse(first["retried"])
        status, replay = self.call("POST", f"/exports/{case_id}/chunks/0/claims", {
            "claim_key": "claim-1", "claimed_by": "operator-1",
        })
        self.assertTrue(replay["retried"])
        self.assertEqual(first["delivery_id"], replay["delivery_id"])
        self.assertEqual(first["billing_record_id"], replay["billing_record_id"])

        status, chunks = self.call("GET", f"/exports/{case_id}/chunks")
        self.assertEqual(status, 200)
        self.assertTrue(chunks["chunks"][0]["claimed"])

        status, inclusions = self.call("GET", f"/exports/{case_id}/inclusions")
        self.assertEqual(
            sorted(inclusions["inclusions"][0]["approver_ids"]),
            ["owner-9", "soc-7"],
        )

        status, audit = self.call("GET", f"/exports/{case_id}/audit")
        self.assertTrue(audit["consistent"], audit["checks"])

    def test_revoked_claim_refused(self):
        _, created = self.call("POST", "/exports", {
            "applicant_id": "op", "business_purpose": "p", "recipient": "r",
        })
        case_id = created["case_id"]
        self.call("POST", f"/exports/{case_id}/manifest", {
            "actor_id": "rev", "entries": [entry("f1")], "chunk_size_bytes": 10,
        })
        status, _ = self.call("POST", f"/exports/{case_id}/revoke", {
            "actor_id": "soc-7", "reason": "停止交付",
        })
        self.assertEqual(status, 200)
        from exportguard.errors import ConflictError

        with self.assertRaises(ConflictError) as ctx:
            self.call("POST", f"/exports/{case_id}/chunks/0/claims", {
                "claim_key": "k", "claimed_by": "op",
            })
        self.assertEqual(ctx.exception.code, "revoked")
        self.assertEqual(ctx.exception.http_status, 409)

    def test_missing_tenant_header(self):
        from exportguard.errors import ValidationError

        with self.assertRaises(ValidationError):
            self.app.handle("GET", "/exports", Headers(), b"")

    def test_unknown_route_404(self):
        from exportguard.errors import NotFoundError

        with self.assertRaises(NotFoundError) as ctx:
            self.app.handle("GET", "/nope", self.tenant_headers, b"")
        self.assertEqual(ctx.exception.http_status, 404)

    def test_bad_json(self):
        from exportguard.errors import ValidationError

        with self.assertRaises(ValidationError):
            self.app.handle(
                "POST", "/exports", self.tenant_headers, b"{not-json",
            )


class HttpSocketTest(unittest.TestCase):
    """真实 HTTP 栈冒烟：启动服务、发请求、确认 200 与 JSON。"""

    def setUp(self) -> None:
        self.store = EventStore(":memory:")
        app = ExportGuardApp(ExportGuardService(self.store, clock=FixedClock()))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.store.close()

    def _request(self, method: str, path: str, payload: dict | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "X-Tenant-Id": "tenant-a",
            },
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode())

    def test_create_and_fetch_over_socket(self):
        status, created = self._request("POST", "/exports", {
            "applicant_id": "op", "business_purpose": "p", "recipient": "r",
        })
        self.assertEqual(status, 200)
        status, fetched = self._request("GET", f"/exports/{created['case_id']}")
        self.assertEqual(fetched["state"], "draft")
        self.assertEqual(fetched["recipient"], "r")


if __name__ == "__main__":
    unittest.main()
