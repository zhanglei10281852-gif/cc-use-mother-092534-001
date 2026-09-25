"""受控导出服务的端到端领域测试。"""
from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from exportguard.aggregate import (
    STATE_APPROVED,
    STATE_AWAITING_APPROVAL,
    STATE_COMPLETED,
    STATE_DELIVERING,
    STATE_EXPIRED,
    STATE_REVOKED,
)
from exportguard.clock import FixedClock
from exportguard.errors import ConflictError, NotFoundError, ValidationError
from exportguard.service import ExportGuardService
from exportguard.storage import EventStore


def entry(file_id: str, *, sensitivity: str = "normal", size: int = 100,
          version: str = "v1", owner: str = "owner-1", reason: str = "范围内文件"):
    return {
        "file_id": file_id,
        "path": f"/data/{file_id}.dat",
        "file_version": version,
        "content_hash": f"hash-{file_id}-{version}",
        "sensitivity": sensitivity,
        "size_bytes": size,
        "owner_id": owner,
        "included_reason": reason,
    }


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FixedClock()
        self.store = EventStore(":memory:")
        self.svc = ExportGuardService(self.store, clock=self.clock)
        self.tenant = "tenant-a"

    def tearDown(self) -> None:
        self.store.close()

    def create_case(self, case_id: str = "case-1", recipient: str = "rt-bucket"):
        result = self.svc.create_export(
            tenant_id=self.tenant,
            applicant_id="operator-1",
            business_purpose="客户空间合规复盘",
            recipient=recipient,
            case_id=case_id,
        )
        return result["case_id"]

    def classify(self, case_id: str, entries, chunk_size: int = 10_000, actor: str = "reviewer-2"):
        return self.svc.classify_manifest(
            case_id=case_id, tenant_id=self.tenant, actor_id=actor,
            entries=entries, chunk_size_bytes=chunk_size,
        )


class LifecycleTest(ServiceTestBase):
    def test_normal_export_auto_approved_and_completes(self):
        case_id = self.create_case()
        view = self.classify(case_id, [entry("f1", size=1), entry("f2", size=1)], chunk_size=1)
        self.assertEqual(view.state, STATE_APPROVED)
        self.assertEqual(view.sensitivity, "normal")
        self.assertEqual(len(view.approvals), 1)
        self.assertEqual(view.approvals[0].role, "system_auto")

        c0 = self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.assertTrue(c0.billed)
        self.assertFalse(c0.retried)
        view = self.svc.get_export(case_id, self.tenant)
        self.assertEqual(view.state, STATE_DELIVERING)

        # 领取最后一片后自动完成。
        c1 = self.svc.claim_chunk(case_id, self.tenant, 1, "key-1", "operator-1")
        view = self.svc.get_export(case_id, self.tenant)
        self.assertEqual(view.state, STATE_COMPLETED)
        self.assertNotEqual(c0.delivery_id, c1.delivery_id)

    def test_confidential_requires_dual_approval(self):
        case_id = self.create_case()
        view = self.classify(case_id, [entry("f1", sensitivity="confidential")])
        self.assertEqual(view.state, STATE_AWAITING_APPROVAL)
        with self.assertRaises(ConflictError):
            self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")

        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        with self.assertRaises(ConflictError):  # 仅所有者批准仍不足
            self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.svc.record_approval(case_id, self.tenant, "security_officer", "soc-7")
        claim = self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.assertTrue(claim.billed)

    def test_unknown_approval_role_rejected(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", sensitivity="confidential")])
        with self.assertRaises(ValidationError):
            self.svc.record_approval(case_id, self.tenant, "system_auto", "system")
        # normal 等级不允许人工角色混入。
        other = self.create_case("case-2")
        self.classify(other, [entry("g1")])
        with self.assertRaises(ValidationError):
            self.svc.record_approval(other, self.tenant, "data_owner", "owner-9")

    def test_approval_replay_same_approver_is_idempotent(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", sensitivity="confidential")])
        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        # 同人重复批准不增加事件；换人则冲突。
        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        with self.assertRaises(ConflictError):
            self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-10")


class ManifestVersioningTest(ServiceTestBase):
    def test_file_change_invalidates_old_approvals(self):
        case_id = self.create_case()
        view = self.classify(case_id, [entry("f1", sensitivity="confidential", size=100)])
        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        self.svc.record_approval(case_id, self.tenant, "security_officer", "soc-7")
        old_hash = view.manifest_hash

        # 等待期间文件变化：作废 → 重新分级（新哈希）。
        self.svc.invalidate_manifest(
            case_id, self.tenant, "reviewer-2", ["f1"], "文件内容更新"
        )
        view = self.svc.get_export(case_id, self.tenant)
        self.assertIsNone(view.manifest_hash)
        self.assertEqual(view.state, STATE_AWAITING_APPROVAL)

        view = self.svc.classify_manifest(
            case_id, self.tenant, "reviewer-2",
            [entry("f1", sensitivity="confidential", size=100, version="v2")],
            chunk_size_bytes=10_000,
        )
        self.assertNotEqual(old_hash, view.manifest_hash)
        self.assertEqual(view.manifest_version, 2)
        # 旧批准绑定旧哈希，不能领取，必须重新共同批准。
        with self.assertRaises(ConflictError) as ctx:
            self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.assertEqual(ctx.exception.code, "approval_stale")
        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        self.svc.record_approval(case_id, self.tenant, "security_officer", "soc-7")
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")

    def test_reclassify_without_invalidation_refused(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", sensitivity="confidential")])
        with self.assertRaises(ConflictError):
            self.classify(case_id, [entry("f1", sensitivity="confidential", version="v2")])

    def test_change_after_some_delivery_re_evaluates(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", size=1), entry("f2", size=1)], chunk_size=1)
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.svc.invalidate_manifest(case_id, self.tenant, "soc", ["f2"])
        self.classify(case_id,
                      [entry("f1", size=1), entry("f2", size=1, version="v2")],
                      chunk_size=1)
        # 新清单下所有分片都未领取（旧交付只作为历史保留）。
        status = self.svc.chunks_status(case_id, self.tenant)
        self.assertEqual([row["claimed"] for row in status], [False, False])
        view = self.svc.get_export(case_id, self.tenant)
        self.assertEqual(len(view.claimed_chunks), 1)  # 历史交付仍可审计


class ClaimIdempotencyTest(ServiceTestBase):
    def _ready(self, case_id="case-1"):
        self.create_case(case_id)
        self.classify(
            case_id,
            [entry("f1", size=1), entry("f2", size=1)],
            chunk_size=1,
        )

    def test_retry_same_key_returns_same_delivery_and_billing(self):
        case_id = "case-1"
        self._ready(case_id)
        first = self.svc.claim_chunk(case_id, self.tenant, 0, "same-key", "operator-1")
        second = self.svc.claim_chunk(case_id, self.tenant, 0, "same-key", "operator-1")
        self.assertEqual(first.delivery_id, second.delivery_id)
        self.assertEqual(first.billing_record_id, second.billing_record_id)
        self.assertTrue(second.retried)
        billing = self.store.billing_for_case(case_id)
        self.assertEqual(len(billing), 1)
        events = [e for e in self.store.load_events(case_id) if e.event_type == "chunk.claimed"]
        self.assertEqual(len(events), 1)

    def test_same_key_different_params_conflicts(self):
        case_id = "case-1"
        self._ready(case_id)
        self.svc.claim_chunk(case_id, self.tenant, 0, "dup-key", "operator-1")
        with self.assertRaises(ConflictError) as ctx:
            self.svc.claim_chunk(case_id, self.tenant, 1, "dup-key", "operator-1")
        self.assertEqual(ctx.exception.code, "idempotency_fingerprint_mismatch")

    def test_second_key_on_same_chunk_conflicts(self):
        case_id = "case-1"
        self._ready(case_id)
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-a", "operator-1")
        with self.assertRaises(ConflictError) as ctx:
            self.svc.claim_chunk(case_id, self.tenant, 0, "key-b", "operator-1")
        self.assertEqual(ctx.exception.code, "chunk_already_claimed")
        self.assertEqual(len(self.store.billing_for_case(case_id)), 1)

    def test_create_idempotency_key(self):
        first = self.svc.create_export(
            self.tenant, "operator-1", "目的", "r", case_id="case-x",
            idempotency_key="create-key",
        )
        second = self.svc.create_export(
            self.tenant, "operator-1", "目的", "r", case_id="case-x",
            idempotency_key="create-key",
        )
        self.assertEqual(first["case_id"], second["case_id"])
        self.assertEqual(len(self.store.list_case_ids(self.tenant)), 1)


class RevocationExpiryTest(ServiceTestBase):
    def test_revocation_invalidates_unclaimed_chunks(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", size=1), entry("f2", size=1)], chunk_size=1)
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.svc.revoke(case_id, self.tenant, "soc-7", "客户投诉，立即停止")
        view = self.svc.get_export(case_id, self.tenant)
        self.assertEqual(view.state, STATE_REVOKED)
        with self.assertRaises(ConflictError) as ctx:
            self.svc.claim_chunk(case_id, self.tenant, 1, "key-1", "operator-1")
        self.assertEqual(ctx.exception.code, "revoked")
        # 已领取分片的交付事实保留。
        self.assertEqual(len(self.store.billing_for_case(case_id)), 1)

    def test_expired_approval_blocks_claims(self):
        case_id = self.create_case()
        self.classify(
            case_id, [entry("f1", sensitivity="confidential")],
        )
        self.svc.record_approval(
            case_id, self.tenant, "data_owner", "owner-9",
            valid_for=timedelta(hours=2),
        )
        self.svc.record_approval(
            case_id, self.tenant, "security_officer", "soc-7",
            valid_for=timedelta(hours=2),
        )
        self.clock.advance(3 * 3600)
        with self.assertRaises(ConflictError) as ctx:
            self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        self.assertEqual(ctx.exception.code, "expired")
        self.assertEqual(self.svc.get_export(case_id, self.tenant).state, STATE_EXPIRED)

    def test_expire_due_scan(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1")])  # normal 默认 24h
        self.clock.advance(25 * 3600)
        expired = self.svc.expire_due(self.tenant)
        self.assertEqual(expired, [case_id])
        self.assertEqual(self.svc.get_export(case_id, self.tenant).state, STATE_EXPIRED)

    def test_cannot_revoke_completed(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1")])
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        with self.assertRaises(ConflictError):
            self.svc.revoke(case_id, self.tenant, "soc-7", "迟来的撤销")


class QueryAndAuditTest(ServiceTestBase):
    def test_inclusions_explain_why_and_who(self):
        case_id = self.create_case()
        self.classify(
            case_id,
            [entry("f1", sensitivity="confidential", owner="owner-9",
                   reason="命中客户空间导出范围")],
            chunk_size=10_000,
        )
        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        self.svc.record_approval(case_id, self.tenant, "security_officer", "soc-7")
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        items = self.svc.file_inclusions(case_id, self.tenant)
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.entry.included_reason, "命中客户空间导出范围")
        self.assertEqual(item.entry.owner_id, "owner-9")
        self.assertIn("owner-9", item.approver_ids)
        self.assertIn("soc-7", item.approver_ids)
        self.assertEqual(item.claim_idempotency_key, "key-0")
        self.assertEqual(item.chunk_index, 0)

    def test_audit_summary_consistent(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", size=1), entry("f2", size=1)], chunk_size=1)
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        summary = self.svc.audit_summary(case_id, self.tenant)
        self.assertTrue(summary["consistent"], summary["checks"])
        names = {check["check"] for check in summary["checks"]}
        self.assertEqual(
            names,
            {
                "event_sequence", "event_timezone", "manifest_hash",
                "approval_binding", "approval_complete", "delivery_billing",
                "delivery_progress", "chunk_plan",
            },
        )
        # 全部领取后完成，审计仍一致。
        self.svc.claim_chunk(case_id, self.tenant, 1, "key-1", "operator-1")
        summary = self.svc.audit_summary(case_id, self.tenant)
        self.assertTrue(summary["consistent"])
        self.assertEqual(summary["claim_count"], 2)
        self.assertEqual(summary["billing_count"], 2)

    def test_audit_covers_revision_history(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", sensitivity="confidential")])
        self.svc.invalidate_manifest(case_id, self.tenant, "reviewer-2", ["f1"])
        self.classify(case_id, [entry("f1", sensitivity="confidential", version="v2")])
        self.svc.record_approval(case_id, self.tenant, "data_owner", "owner-9")
        self.svc.record_approval(case_id, self.tenant, "security_officer", "soc-7")
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        summary = self.svc.audit_summary(case_id, self.tenant)
        self.assertTrue(summary["consistent"], summary["checks"])
        self.assertEqual(summary["manifest_version"], 2)

    def test_chunks_status_reports_progress(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", size=60), entry("f2", size=60)], chunk_size=100)
        status = self.svc.chunks_status(case_id, self.tenant)
        self.assertEqual(len(status), 2)
        self.assertTrue(all(not row["claimed"] for row in status))
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        status = self.svc.chunks_status(case_id, self.tenant)
        self.assertTrue(status[0]["claimed"])
        self.assertFalse(status[1]["claimed"])
        self.assertIsNotNone(status[0]["billing_record_id"])

    def test_audit_detects_tampered_event_payload(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1", size=1), entry("f2", size=1)], chunk_size=1)
        self.svc.claim_chunk(case_id, self.tenant, 0, "key-0", "operator-1")
        # 模拟有人直接篡改事件库里的清单条目（纳入原因/文件哈希）。
        conn = self.store.connection
        row = conn.execute(
            "select payload_json from events where event_type = 'manifest.classified'"
        ).fetchone()
        import json as _json

        payload = _json.loads(row[0])
        payload["entries"][0]["content_hash"] = "tampered-hash"
        with conn:
            conn.execute(
                "update events set payload_json = ? where event_type = 'manifest.classified'",
                (_json.dumps(payload, ensure_ascii=False, sort_keys=True),),
            )
        summary = self.svc.audit_summary(case_id, self.tenant)
        self.assertFalse(summary["consistent"])
        failed = {c["check"] for c in summary["checks"] if not c["ok"]}
        self.assertIn("manifest_hash", failed)

    def test_cross_tenant_access_denied(self):
        case_id = self.create_case()
        with self.assertRaises(NotFoundError):
            self.svc.get_export(case_id, "tenant-b")
        with self.assertRaises(NotFoundError):
            self.svc.claim_chunk(case_id, "tenant-b", 0, "k", "operator-1")


class ValidationTest(ServiceTestBase):
    def test_request_requires_purpose_and_recipient(self):
        with self.assertRaises(ValidationError):
            self.svc.create_export(self.tenant, "op", "", "r")
        with self.assertRaises(ValidationError):
            self.svc.create_export(self.tenant, "op", "目的", "")

    def test_manifest_entry_validation(self):
        case_id = self.create_case()
        bad = entry("f1")
        del bad["content_hash"]
        with self.assertRaises(ValidationError):
            self.classify(case_id, [bad])
        with self.assertRaises(ValidationError):
            self.classify(case_id, [entry("f1", sensitivity="secret")])
        with self.assertRaises(ValidationError):
            self.classify(case_id, [entry("f1"), entry("f1")])
        with self.assertRaises(ValidationError):
            self.classify(case_id, [])

    def test_chunk_index_out_of_range(self):
        case_id = self.create_case()
        self.classify(case_id, [entry("f1")])
        with self.assertRaises(ValidationError):
            self.svc.claim_chunk(case_id, self.tenant, 9, "key", "operator-1")


class RestartRecoveryTest(unittest.TestCase):
    def test_state_survives_restart_mid_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "export.db")
            clock = FixedClock()
            store = EventStore(db_path)
            svc = ExportGuardService(store, clock=clock)
            case_id = svc.create_export(
                "tenant-a", "operator-1", "复盘", "rt", case_id="case-r",
            )["case_id"]
            svc.classify_manifest(
                case_id, "tenant-a", "reviewer-2",
                [entry("f1", size=1), entry("f2", size=1)], chunk_size_bytes=1,
            )
            svc.claim_chunk(case_id, "tenant-a", 0, "key-0", "operator-1")
            store.close()

            # 模拟服务重启：新连接、新服务实例，纯靠事件流重建。
            store2 = EventStore(db_path)
            svc2 = ExportGuardService(store2, clock=clock)
            view = svc2.get_export(case_id, "tenant-a")
            self.assertEqual(view.state, STATE_DELIVERING)
            self.assertEqual(len(view.entries), 2)
            self.assertEqual(len(view.claimed_chunks), 1)
            # 续传：重试旧键回放，新键领取下一片。
            replay = svc2.claim_chunk(case_id, "tenant-a", 0, "key-0", "operator-1")
            self.assertTrue(replay.retried)
            self.assertEqual(len(store2.billing_for_case(case_id)), 1)
            svc2.claim_chunk(case_id, "tenant-a", 1, "key-1", "operator-1")
            self.assertEqual(
                svc2.get_export(case_id, "tenant-a").state, STATE_COMPLETED
            )
            store2.close()


if __name__ == "__main__":
    unittest.main()
