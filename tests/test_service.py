"""受控导出服务的端到端规则测试。"""
from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from export_guard import (
    ApprovalClosed,
    ApprovalError,
    ChunkAlreadyClaimed,
    ClaimKeyConflict,
    ControlledExportService,
    DeliveryDenied,
    InvalidStateError,
    ManifestStale,
    ScopeError,
)
from export_guard.policy import DATA_OWNER, SECURITY_OFFICER
from export_guard.time import FixedClock, SystemClock

T0 = datetime(2026, 9, 25, 9, 0, 0, tzinfo=timezone(timedelta(hours=8)))
TENANT = "tenant-a"


def make_service(path: str = ":memory:", step_seconds: float = 1.0):
    clock = FixedClock(T0, step_seconds=step_seconds)
    return ControlledExportService(path, clock=clock), clock


def seed_files(svc: ControlledExportService) -> None:
    catalog = [
        # file_id, version, hash, size, sensitivity
        ("f-pub", "v1", "hash-pub-1", 100, "public"),
        ("f-conf", "v1", "hash-conf-1", 200, "confidential"),
        ("f-restr-a", "v1", "hash-restr-a-1", 300, "restricted"),
        ("f-restr-b", "v1", "hash-restr-b-1", 400, "restricted"),
    ]
    for file_id, version, h, size, level in catalog:
        svc.upsert_file(TENANT, file_id, version, h, size, level,
                        f"s3://bucket/{file_id}", actor_id="cataloger")


def open_restricted_case(svc: ControlledExportService, case_id: str = "case-1"):
    svc.create_request(TENANT, case_id, "operator-1",
                       "安全事件复盘，需要导出审计相关文件",
                       "recipient-x", actor_id="operator-1")
    svc.freeze_manifest(TENANT, case_id, [
        {"file_id": "f-restr-a", "inclusion_reason": "事件时间窗内命中关键字"},
        {"file_id": "f-restr-b", "inclusion_reason": "与命中会话同一存储桶"},
    ], actor_id="reviewer-2")


def approve_restricted(svc: ControlledExportService, case_id: str = "case-1",
                       valid_hours: int = 24):
    deadline = svc.clock.now() + timedelta(hours=valid_hours)
    svc.record_approval(TENANT, case_id, DATA_OWNER, "owner-7", deadline,
                        actor_id="owner-7")
    svc.record_approval(TENANT, case_id, SECURITY_OFFICER, "soc-3", deadline,
                        actor_id="soc-3")


def prepare_two_chunks(svc: ControlledExportService, case_id: str = "case-1"):
    return svc.prepare_chunks(TENANT, case_id, [[0], [1]], actor_id="operator-1")


class HappyPathTest(unittest.TestCase):
    def test_restricted_requires_dual_approval_and_completes(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)

        case = svc.get_case(TENANT, "case-1")
        self.assertEqual(case["state"], "awaiting_approval")
        self.assertEqual(case["current_manifest"]["max_sensitivity"], "restricted")
        self.assertEqual(set(case["current_manifest"]["required_roles"]),
                         {DATA_OWNER, SECURITY_OFFICER})

        # 仅数据所有者批准尚不足以放行。
        deadline = clock.now() + timedelta(hours=24)
        svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                            actor_id="owner-7")
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "awaiting_approval")
        with self.assertRaises(InvalidStateError):
            prepare_two_chunks(svc)

        svc.record_approval(TENANT, "case-1", SECURITY_OFFICER, "soc-3", deadline,
                            actor_id="soc-3")
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "approved")

        chunks = prepare_two_chunks(svc)
        self.assertEqual([c["entry_indexes"] for c in chunks], [[0], [1]])

        r1 = svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                             "recipient-x", "claim-1", actor_id="operator-1")
        self.assertFalse(r1["replayed"])
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "delivering")

        r2 = svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                             "recipient-x", "claim-2", actor_id="operator-1")
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "completed")
        self.assertEqual(r2["billed_bytes"], 400)

        report = svc.verify_consistency(TENANT, "case-1")
        self.assertTrue(report["ok"], report["problems"])

    def test_public_manifest_is_auto_approved(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        svc.create_request(TENANT, "case-p", "operator-1", "公开资料归档", "rx",
                           actor_id="operator-1")
        svc.freeze_manifest(TENANT, "case-p", [
            {"file_id": "f-pub", "inclusion_reason": "公开发布材料"},
        ], actor_id="reviewer-2")
        self.assertEqual(svc.get_case(TENANT, "case-p")["state"], "approved")

    def test_confidential_needs_only_data_owner(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        svc.create_request(TENANT, "case-c", "operator-1", "内审抽样", "rx",
                           actor_id="operator-1")
        svc.freeze_manifest(TENANT, "case-c", [
            {"file_id": "f-conf", "inclusion_reason": "抽中样本"},
        ], actor_id="reviewer-2")
        with self.assertRaises(ApprovalError):
            svc.record_approval(TENANT, "case-c", SECURITY_OFFICER, "soc-3",
                                clock.now() + timedelta(hours=10), actor_id="soc-3")
        svc.record_approval(TENANT, "case-c", DATA_OWNER, "owner-7",
                            clock.now() + timedelta(hours=24), actor_id="owner-7")
        self.assertEqual(svc.get_case(TENANT, "case-c")["state"], "approved")


class ScopeValidationTest(unittest.TestCase):
    def test_purpose_recipient_and_reasons_are_required(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        with self.assertRaises(ScopeError):
            svc.create_request(TENANT, "case-x", "op", "  ", "rx", actor_id="op")
        with self.assertRaises(ScopeError):
            svc.create_request(TENANT, "case-x", "op", "目的", " ", actor_id="op")
        svc.create_request(TENANT, "case-x", "op", "目的", "rx", actor_id="op")
        with self.assertRaises(ScopeError):
            svc.freeze_manifest(TENANT, "case-x", [], actor_id="r")
        with self.assertRaises(ScopeError):
            svc.freeze_manifest(TENANT, "case-x", [{"file_id": "f-pub"}],
                                actor_id="r")
        with self.assertRaises(ScopeError):
            svc.freeze_manifest(TENANT, "case-x",
                                [{"file_id": "ghost", "inclusion_reason": "x"}],
                                actor_id="r")

    def test_chunk_plan_must_cover_every_entry_once(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        with self.assertRaises(ScopeError):
            svc.prepare_chunks(TENANT, "case-1", [[0]], actor_id="op")
        with self.assertRaises(ScopeError):
            svc.prepare_chunks(TENANT, "case-1", [[0, 1], [1]], actor_id="op")
        with self.assertRaises(ScopeError):
            svc.prepare_chunks(TENANT, "case-1", [[0], [2]], actor_id="op")

    def test_plan_chunks_bin_packing(self) -> None:
        plan = ControlledExportService.plan_chunks(4, 10, [6, 5, 4, 3])
        self.assertEqual(plan, [[0], [1, 2], [3]])


class IdempotencyTest(unittest.TestCase):
    def _claimed_case(self, svc):
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        chunks = prepare_two_chunks(svc)
        receipt = svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                                  "recipient-x", "claim-1", actor_id="operator-1")
        return chunks, receipt

    def test_retry_returns_same_receipt_without_double_billing(self) -> None:
        svc, _ = make_service()
        chunks, first = self._claimed_case(svc)
        events_before = len(svc.event_history(TENANT, "case-1"))

        retry = svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                                "recipient-x", "claim-1", actor_id="operator-1")
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["claimed_at"], first["claimed_at"])
        self.assertEqual(retry["content_token"], first["content_token"])

        # 没有第二条 chunk.claimed 事实，也没有第二条计费。
        events = svc.event_history(TENANT, "case-1")
        self.assertEqual(len([e for e in events if e["event_type"] == "chunk.claimed"]), 1)
        self.assertEqual(len(events), events_before)
        claims = svc.list_claims(TENANT, "case-1")
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["billed_bytes"], 300)
        billed = svc.store.fetchall(
            "select * from billing_record where tenant_id=? and case_id=?",
            (TENANT, "case-1"))
        self.assertEqual(len(billed), 1)

    def test_same_key_with_different_semantics_is_conflict(self) -> None:
        svc, _ = make_service()
        chunks, _ = self._claimed_case(svc)
        with self.assertRaises(ClaimKeyConflict):
            svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                            "recipient-x", "claim-1", actor_id="operator-1")
        with self.assertRaises(ClaimKeyConflict):
            svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                            "intruder", "claim-1", actor_id="operator-1")

    def test_chunk_cannot_be_claimed_twice_with_another_key(self) -> None:
        svc, _ = make_service()
        chunks, _ = self._claimed_case(svc)
        with self.assertRaises(ChunkAlreadyClaimed):
            svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                            "recipient-x", "claim-other", actor_id="operator-1")

    def test_wrong_recipient_is_denied(self) -> None:
        svc, _ = make_service()
        chunks, _ = self._claimed_case(svc)
        with self.assertRaises(DeliveryDenied):
            svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                            "someone-else", "claim-9", actor_id="operator-1")

    def test_replay_still_served_after_revoke(self) -> None:
        svc, _ = make_service()
        chunks, receipt = self._claimed_case(svc)
        svc.revoke(TENANT, "case-1", actor_id="soc-3", reason="调查终止")
        replay = svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                                 "recipient-x", "claim-1", actor_id="operator-1")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["claimed_at"], receipt["claimed_at"])
        self.assertEqual(len(svc.list_claims(TENANT, "case-1")), 1)


class ApprovalBindingTest(unittest.TestCase):
    def test_approval_binds_hash_recipient_and_validity(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approvals = svc.list_approvals(TENANT, "case-1")
        self.assertEqual(approvals, [])
        deadline = clock.now() + timedelta(hours=24)
        svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                            actor_id="owner-7")
        approval = svc.list_approvals(TENANT, "case-1")[0]
        manifest_hash = svc.get_case(TENANT, "case-1")["current_manifest"]["manifest_hash"]
        self.assertEqual(approval["bound_manifest_hash"], manifest_hash)
        self.assertEqual(approval["bound_recipient_id"], "recipient-x")

    def test_duplicate_role_approval_rejected(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        deadline = clock.now() + timedelta(hours=24)
        svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                            actor_id="owner-7")
        with self.assertRaises(ApprovalError):
            svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-8", deadline,
                                actor_id="owner-8")

    def test_validity_cannot_exceed_policy_cap_or_be_in_past(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        with self.assertRaises(ApprovalError):
            svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7",
                                clock.now() + timedelta(hours=25), actor_id="owner-7")
        with self.assertRaises(ApprovalError):
            svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7",
                                clock.now() - timedelta(minutes=1), actor_id="owner-7")


class DriftTest(unittest.TestCase):
    def test_drift_while_awaiting_approval_invalidates_manifest(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        deadline = clock.now() + timedelta(hours=24)
        svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                            actor_id="owner-7")

        # 等待期间文件变化。
        svc.upsert_file(TENANT, "f-restr-a", "v2", "hash-restr-a-2", 305,
                        "restricted", "s3://bucket/f-restr-a", actor_id="cataloger")
        with self.assertRaises(ManifestStale):
            svc.record_approval(TENANT, "case-1", SECURITY_OFFICER, "soc-3",
                                deadline, actor_id="soc-3")

        case = svc.get_case(TENANT, "case-1")
        self.assertEqual(case["state"], "classified")
        self.assertEqual(case["current_manifest"]["status"], "superseded")
        invalidated = [e for e in svc.event_history(TENANT, "case-1")
                       if e["event_type"] == "manifest.invalidated"]
        self.assertEqual(len(invalidated), 1)
        self.assertIn("f-restr-a", invalidated[0]["payload"]["changed_files"])

        # 重新评估：冻结新版本，旧批准不携带到新版本。
        svc.freeze_manifest(TENANT, "case-1", [
            {"file_id": "f-restr-a", "inclusion_reason": "事件时间窗内命中关键字（v2 复核）"},
            {"file_id": "f-restr-b", "inclusion_reason": "与命中会话同一存储桶"},
        ], actor_id="reviewer-2")
        case = svc.get_case(TENANT, "case-1")
        self.assertEqual(case["current_manifest"]["manifest_version"], 2)
        # 旧版本上的 data_owner 批准不能当成新版本的批准。
        with self.assertRaises(InvalidStateError):
            prepare_two_chunks(svc)
        approvals = svc.list_approvals(TENANT, "case-1")
        self.assertEqual({a["manifest_version"] for a in approvals}, {1})

    def test_stale_approval_version_returns_closed(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        # 管理员拿着 v1 的号，在重新冻结出 v2 后才提交批准。
        svc.upsert_file(TENANT, "f-restr-a", "v2", "hash-restr-a-2", 305,
                        "restricted", "s3://bucket/f-restr-a", actor_id="cataloger")
        svc.freeze_manifest(TENANT, "case-1", [
            {"file_id": "f-restr-a", "inclusion_reason": "复核 v2"},
            {"file_id": "f-restr-b", "inclusion_reason": "同桶"},
        ], actor_id="reviewer-2")
        with self.assertRaises(ApprovalClosed):
            svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7",
                                clock.now() + timedelta(hours=24),
                                expected_manifest_version=1, actor_id="owner-7")

    def test_drift_during_delivery_kills_unclaimed_chunks(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        chunks = prepare_two_chunks(svc)
        svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                        "recipient-x", "claim-1", actor_id="operator-1")

        svc.upsert_file(TENANT, "f-restr-b", "v2", "hash-restr-b-2", 410,
                        "restricted", "s3://bucket/f-restr-b", actor_id="cataloger")
        with self.assertRaises(ManifestStale):
            svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                            "recipient-x", "claim-2", actor_id="operator-1")
        case = svc.get_case(TENANT, "case-1")
        self.assertEqual(case["state"], "classified")

        # 未领取分片属于落后的批准版本，重新批准前一律拒绝。
        svc.freeze_manifest(TENANT, "case-1", [
            {"file_id": "f-restr-a", "inclusion_reason": "命中关键字"},
            {"file_id": "f-restr-b", "inclusion_reason": "同桶（v2 复核）"},
        ], actor_id="reviewer-2")
        approve_restricted(svc)
        new_chunks = prepare_two_chunks(svc)
        with self.assertRaises(DeliveryDenied):
            svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                            "recipient-x", "claim-old", actor_id="operator-1")
        # 新版本分片可继续领取，且不与 v1 的计费冲突。
        svc.claim_chunk(TENANT, "case-1", new_chunks[0]["chunk_id"],
                        "recipient-x", "claim-3", actor_id="operator-1")
        svc.claim_chunk(TENANT, "case-1", new_chunks[1]["chunk_id"],
                        "recipient-x", "claim-4", actor_id="operator-1")
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "completed")
        report = svc.verify_consistency(TENANT, "case-1")
        self.assertTrue(report["ok"], report["problems"])

    def test_removed_file_is_drift(self) -> None:
        svc, clock = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        svc.store.execute(
            "delete from file_catalog where tenant_id=? and file_id='f-restr-a'",
            (TENANT,))
        svc.store.commit()
        with self.assertRaises(ManifestStale):
            svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7",
                                clock.now() + timedelta(hours=24), actor_id="owner-7")


class RevocationAndExpiryTest(unittest.TestCase):
    def test_revocation_denies_unclaimed_chunks(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        chunks = prepare_two_chunks(svc)
        svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                        "recipient-x", "claim-1", actor_id="operator-1")
        svc.revoke(TENANT, "case-1", actor_id="soc-3", reason="申请人离职")
        with self.assertRaises(DeliveryDenied):
            svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                            "recipient-x", "claim-2", actor_id="operator-1")
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "revoked")
        # 撤销幂等。
        svc.revoke(TENANT, "case-1", actor_id="soc-3")

    def test_lazy_expiry_on_claim(self) -> None:
        svc, clock = make_service(step_seconds=0.0)
        seed_files(svc)
        open_restricted_case(svc)
        deadline = clock.now() + timedelta(hours=1)
        svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                            actor_id="owner-7")
        svc.record_approval(TENANT, "case-1", SECURITY_OFFICER, "soc-3", deadline,
                            actor_id="soc-3")
        chunks = prepare_two_chunks(svc)
        # 时钟越过有效期。
        clock.advance(deadline - clock.now() + timedelta(minutes=1))
        with self.assertRaises(DeliveryDenied):
            svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                            "recipient-x", "claim-1", actor_id="operator-1")
        self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "expired")
        expired_events = [e for e in svc.event_history(TENANT, "case-1")
                          if e["event_type"] == "export.expired"]
        self.assertEqual(len(expired_events), 1)

    def test_sweep_expired_marks_overdue_cases(self) -> None:
        svc, clock = make_service(step_seconds=0.0)
        seed_files(svc)
        open_restricted_case(svc)
        deadline = clock.now() + timedelta(hours=1)
        svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                            actor_id="owner-7")
        svc.record_approval(TENANT, "case-1", SECURITY_OFFICER, "soc-3", deadline,
                            actor_id="soc-3")
        clock.advance(deadline - clock.now() + timedelta(minutes=1))
        self.assertEqual(svc.sweep_expired(), ["case-1"])
        self.assertEqual(svc.sweep_expired(), [])


class ConcurrencyTest(unittest.TestCase):
    def test_parallel_retries_produce_one_claim_and_one_bill(self) -> None:
        """同一领取请求在多连接上并发重试：恰好一次交付事实与一次计费。"""
        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "guard.db")
            setup = ControlledExportService(db, clock=SystemClock())
            for file_id, h, size in (("f-a", "h-a", 100), ("f-b", "h-b", 200)):
                setup.upsert_file(TENANT, file_id, "v1", h, size, "public",
                                  f"s3://{file_id}", actor_id="cat")
            setup.create_request(TENANT, "case-mt", "op", "并发续传验证", "rx",
                                actor_id="op")
            setup.freeze_manifest(TENANT, "case-mt", [
                {"file_id": "f-a", "inclusion_reason": "r"},
                {"file_id": "f-b", "inclusion_reason": "r"},
            ], actor_id="rev")
            chunks = setup.prepare_chunks(TENANT, "case-mt", [[0, 1]],
                                          actor_id="op")

            def attempt(_):
                svc = ControlledExportService(db, clock=SystemClock())
                try:
                    return svc.claim_chunk(TENANT, "case-mt", chunks[0]["chunk_id"],
                                           "rx", "same-claim-key", actor_id="op")
                except Exception as exc:  # noqa: BLE001
                    return exc
                finally:
                    svc.close()

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(attempt, range(8)))

            receipts = [r for r in results if not isinstance(r, Exception)]
            errors = [r for r in results if isinstance(r, Exception)]
            self.assertGreaterEqual(len(receipts), 1)
            # 所有返回的回执必须是同一张（claimed_at 相同）。
            claimed_at = {r["claimed_at"] for r in receipts}
            self.assertEqual(len(claimed_at), 1)
            # 并发下允许其他尝试得到“已被领取”，但绝不允许出现第二条交付事实。
            self.assertTrue(all(isinstance(e, ChunkAlreadyClaimed) for e in errors))
            self.assertEqual(len(setup.list_claims(TENANT, "case-mt")), 1)
            bills = setup.store.fetchall(
                "select * from billing_record where tenant_id=? and case_id=?",
                (TENANT, "case-mt"))
            self.assertEqual(len(bills), 1)
            setup.close()


class RecoveryTest(unittest.TestCase):
    def test_state_survives_restart_and_replay_matches(self) -> None:
        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "guard.db")
            svc, clock = make_service(db)
            seed_files(svc)
            open_restricted_case(svc)
            approve_restricted(svc)
            chunks = prepare_two_chunks(svc)
            svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                            "recipient-x", "claim-1", actor_id="operator-1")
            self.assertEqual(svc.get_case(TENANT, "case-1")["state"], "delivering")
            svc.close()

            # 新进程、无内存状态，重新打开同一数据库。
            restarted, clock2 = make_service(db, step_seconds=0.0)
            self.assertEqual(restarted.get_case(TENANT, "case-1")["state"],
                             "delivering")
            claims = restarted.list_claims(TENANT, "case-1")
            self.assertEqual(len(claims), 1)
            replayed = restarted.replay_case(TENANT, "case-1")
            self.assertEqual(replayed["state"], "delivering")
            self.assertTrue(restarted.verify_consistency(TENANT, "case-1")["ok"])

            # 续传：未领取分片继续领取后完成。
            restarted.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                                  "recipient-x", "claim-2", actor_id="operator-1")
            self.assertEqual(restarted.get_case(TENANT, "case-1")["state"], "completed")

    def test_recover_expires_overdue_after_restart(self) -> None:
        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "guard.db")
            svc, clock = make_service(db, step_seconds=0.0)
            seed_files(svc)
            open_restricted_case(svc)
            deadline = clock.now() + timedelta(hours=1)
            svc.record_approval(TENANT, "case-1", DATA_OWNER, "owner-7", deadline,
                                actor_id="owner-7")
            svc.record_approval(TENANT, "case-1", SECURITY_OFFICER, "soc-3", deadline,
                                actor_id="soc-3")
            svc.close()

            restarted, clock2 = make_service(db, step_seconds=0.0)
            clock2.advance(deadline - clock2.now() + timedelta(minutes=1))
            result = restarted.recover()
            self.assertEqual(result["expired"], ["case-1"])
            self.assertEqual(restarted.get_case(TENANT, "case-1")["state"], "expired")


class AuditAndQueryTest(unittest.TestCase):
    def test_admin_queries_explain_approval_claims_and_entries(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        chunks = prepare_two_chunks(svc)
        svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                        "recipient-x", "claim-1", actor_id="operator-1")

        entries = svc.list_entries(TENANT, "case-1")
        reasons = {e["file_id"]: e["inclusion_reason"] for e in entries}
        self.assertEqual(reasons["f-restr-a"], "事件时间窗内命中关键字")
        self.assertTrue(all(e["drifted_since_freeze"] is False for e in entries))

        approvals = svc.list_approvals(TENANT, "case-1")
        self.assertEqual({a["approver_id"] for a in approvals}, {"owner-7", "soc-3"})

        claims = svc.list_claims(TENANT, "case-1")
        self.assertEqual(claims[0]["chunk_id"], chunks[0]["chunk_id"])
        self.assertEqual(claims[0]["billed_bytes"], 300)

        chunks_view = svc.list_chunks(TENANT, "case-1")
        self.assertEqual([c["claimed"] for c in chunks_view], [True, False])

        trail = svc.audit_trail(TENANT, "case-1")
        kinds = {t["record_type"] for t in trail}
        self.assertIn("export.requested", kinds)
        self.assertIn("approval.recorded", kinds)
        self.assertIn("chunk.claimed", kinds)

    def test_drift_flag_appears_in_entry_view(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        svc.upsert_file(TENANT, "f-restr-a", "v2", "hash-restr-a-2", 305,
                        "restricted", "s3://bucket/f-restr-a", actor_id="cataloger")
        entries = svc.list_entries(TENANT, "case-1")
        flagged = {e["file_id"]: e["drifted_since_freeze"] for e in entries}
        self.assertTrue(flagged["f-restr-a"])
        self.assertFalse(flagged["f-restr-b"])
        self.assertEqual(entries[0]["current_version"], "v2")

    def test_tampering_is_detected_by_consistency_check(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        prepare_two_chunks(svc)
        svc.claim_chunk(TENANT, "case-1", "chunk-1-0", "recipient-x",
                        "claim-1", actor_id="operator-1")

        # 直接篡改底层表中的冻结哈希。
        svc.store.execute(
            "update manifest_entry set content_hash='forged' "
            "where tenant_id=? and case_id='case-1' and file_id='f-restr-a'",
            (TENANT,))
        svc.store.commit()
        report = svc.verify_consistency(TENANT, "case-1")
        self.assertFalse(report["ok"])
        self.assertFalse(report["manifest_hash_ok"])

        # 删除一条事件会断链。
        svc.store.execute(
            "delete from event_log where event_type='approval.recorded' limit 1")
        svc.store.commit()
        report = svc.verify_consistency(TENANT, "case-1")
        self.assertFalse(report["event_chain_ok"])

    def test_audit_summary_matches_final_manifest(self) -> None:
        svc, _ = make_service()
        seed_files(svc)
        open_restricted_case(svc)
        approve_restricted(svc)
        chunks = prepare_two_chunks(svc)
        svc.claim_chunk(TENANT, "case-1", chunks[0]["chunk_id"],
                        "recipient-x", "claim-1", actor_id="operator-1")
        svc.claim_chunk(TENANT, "case-1", chunks[1]["chunk_id"],
                        "recipient-x", "claim-2", actor_id="operator-1")

        first = svc.verify_consistency(TENANT, "case-1")
        second = svc.verify_consistency(TENANT, "case-1")
        self.assertTrue(first["ok"])
        # 摘要对同一事实集可复现。
        self.assertEqual(first["audit_summary_hash"], second["audit_summary_hash"])
        # 每张领取回执绑定的哈希都等于最终清单哈希。
        final_hash = first["final_manifest_hash"]
        for claim in svc.list_claims(TENANT, "case-1"):
            self.assertEqual(claim["manifest_hash_at_claim"], final_hash)


if __name__ == "__main__":
    unittest.main()
