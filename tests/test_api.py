"""HTTP 接口的端到端冒烟测试（真实 socket，标准库客户端）。"""
from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from export_guard.api import build_server
from export_guard.time import FixedClock

TENANT = "tenant-a"
T0 = datetime(2026, 9, 25, 9, 0, 0, tzinfo=timezone(timedelta(hours=8)))
# restricted 的策略有效期上限为 24 小时。
VALID_UNTIL = "2026-09-26T08:00:00+08:00"


class ApiClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def call(self, method: str, path: str, body=None):
        data = None
        headers = {"Content-Type": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            payload = json.loads(exc.read().decode("utf-8"))
            return exc.code, payload


class HttpApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "api.db")
        self.server = build_server(self.db, host="127.0.0.1", port=0,
                                             clock=FixedClock(T0))
        self.port = self.server.server_address[1]
        import threading
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.client = ApiClient(f"http://127.0.0.1:{self.port}")

    def test_full_lifecycle_and_idempotent_retry_over_http(self) -> None:
        c = self.client
        for file_id, h, size, level in (
            ("f-a", "h-a-1", 100, "restricted"),
            ("f-b", "h-b-1", 200, "restricted"),
        ):
            status, _ = c.call("POST", f"/tenants/{TENANT}/files", {
                "file_id": file_id, "file_version": "v1", "content_hash": h,
                "size_bytes": size, "sensitivity": level,
                "source_location": f"s3://{file_id}", "actor_id": "cat",
            })
            self.assertEqual(status, 200)

        status, case = c.call("POST", f"/tenants/{TENANT}/cases", {
            "case_id": "case-web", "applicant_id": "op",
            "business_purpose": "线上应急取证", "recipient_id": "rx",
            "actor_id": "op",
        })
        self.assertEqual(status, 201)

        status, case = c.call("POST", f"/tenants/{TENANT}/cases/case-web/manifest", {
            "actor_id": "rev",
            "entries": [
                {"file_id": "f-a", "inclusion_reason": "命中告警"},
                {"file_id": "f-b", "inclusion_reason": "同一会话存储桶"},
            ],
        })
        self.assertEqual(status, 201)
        self.assertEqual(case["state"], "awaiting_approval")
        manifest_hash = case["current_manifest"]["manifest_hash"]

        valid_until = VALID_UNTIL
        for role, approver in (("data_owner", "owner"), ("security_officer", "soc")):
            status, _ = c.call("POST", f"/tenants/{TENANT}/cases/case-web/approvals", {
                "role": role, "approver_id": approver,
                "valid_until": valid_until, "actor_id": approver,
            })
            self.assertEqual(status, 200)

        status, chunks = c.call("POST", f"/tenants/{TENANT}/cases/case-web/chunks", {
            "actor_id": "op", "chunk_plan": [[0], [1]],
        })
        self.assertEqual(status, 201)

        claim_body = {
            "chunk_id": chunks[0]["chunk_id"], "recipient_id": "rx",
            "claim_key": "http-claim-1", "actor_id": "op",
        }
        status, first = c.call("POST", f"/tenants/{TENANT}/cases/case-web/claims",
                               claim_body)
        self.assertEqual(status, 200)
        self.assertFalse(first["replayed"])
        status, retry = c.call("POST", f"/tenants/{TENANT}/cases/case-web/claims",
                               claim_body)
        self.assertEqual(status, 200)
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["manifest_hash"], first["manifest_hash"])

        status, claims = c.call("GET", f"/tenants/{TENANT}/cases/case-web/claims")
        self.assertEqual(status, 200)
        self.assertEqual(len(claims), 1)

        # 撤销后未领取分片被拒（403），已领取的同键重试仍回放。
        status, _ = c.call("POST", f"/tenants/{TENANT}/cases/case-web/revoke",
                           {"actor_id": "soc", "reason": "演练终止"})
        self.assertEqual(status, 200)
        status, payload = c.call("POST", f"/tenants/{TENANT}/cases/case-web/claims", {
            "chunk_id": chunks[1]["chunk_id"], "recipient_id": "rx",
            "claim_key": "http-claim-2", "actor_id": "op",
        })
        self.assertEqual(status, 403)
        self.assertIn("撤销", payload["error"])

        status, verify = c.call("GET", f"/tenants/{TENANT}/cases/case-web/verify")
        self.assertEqual(status, 200)
        self.assertEqual(verify["final_manifest_hash"], manifest_hash)
        self.assertTrue(verify["event_chain_ok"])
        self.assertTrue(verify["billing_ok"])

    def test_stale_approval_version_conflict_and_unknown_case(self) -> None:
        c = self.client
        status, payload = c.call("GET", f"/tenants/{TENANT}/cases/nope")
        self.assertEqual(status, 404)
        status, payload = c.call("POST", f"/tenants/{TENANT}/cases", {
            "case_id": "bad", "applicant_id": "op",
            "business_purpose": "   ", "recipient_id": "rx",
        })
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
