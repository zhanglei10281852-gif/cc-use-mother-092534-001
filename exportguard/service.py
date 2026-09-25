"""受控导出应用服务。

一个用例（申请/分级/批准/作废/领取/撤销）对应一个方法；每个写方法在
单个数据库事务中完成幂等检查、聚合重放、规则校验、事件追加和计费写入。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from .aggregate import (
    STATE_APPROVED,
    STATE_AWAITING_APPROVAL,
    STATE_CLASSIFIED,
    STATE_DELIVERING,
    STATE_DRAFT,
    ExportAggregate,
)
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, ValidationError
from .events import (
    EVENT_APPROVAL_RECORDED,
    EVENT_CHUNK_CLAIMED,
    EVENT_EXPORT_COMPLETED,
    EVENT_EXPORT_EXPIRED,
    EVENT_EXPORT_REQUESTED,
    EVENT_EXPORT_REVOKED,
    EVENT_MANIFEST_CLASSIFIED,
    EVENT_MANIFEST_INVALIDATED,
    Event,
    digest_hex,
    manifest_hash,
)
from .models import (
    ApprovalView,
    ChunkClaim,
    EntryInclusion,
    ExportView,
    ManifestEntry,
)
from .policy import (
    ROLE_SYSTEM_AUTO,
    ApprovalPolicy,
    default_policy,
    highest_level,
)
from .storage import EventStore

_SENSITIVITY_ALLOWED = {"normal", "confidential", "restricted"}
_ENTRY_FIELDS = (
    "file_id",
    "path",
    "file_version",
    "content_hash",
    "size_bytes",
    "sensitivity",
    "owner_id",
    "included_reason",
)


class ExportGuardService:
    def __init__(
        self,
        store: EventStore,
        policy: ApprovalPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.store = store
        self.policy = policy or default_policy()
        self.clock = clock or SystemClock()

    # ============================================================ 读模型

    def _now(self) -> datetime:
        moment = self.clock.now()
        if moment.tzinfo is None:
            raise ValueError("时钟必须返回带时区的时间")
        return moment

    def _replay(self, case_id: str, tenant_id: str | None = None) -> ExportAggregate:
        if not self.store.case_exists(case_id):
            raise NotFoundError(f"导出申请不存在：{case_id}")
        if tenant_id is not None and self.store.tenant_of(case_id) != tenant_id:
            # 不向跨租户调用方透露存在性。
            raise NotFoundError(f"导出申请不存在：{case_id}")
        aggregate = ExportAggregate(case_id=case_id, policy=self.policy)
        for event in self.store.load_events(case_id):
            aggregate.apply(event.event_type, event.payload, event.seq, event.occurred_at)
        return aggregate

    def get_export(self, case_id: str, tenant_id: str) -> ExportView:
        aggregate = self._replay(case_id, tenant_id)
        return self._to_view(aggregate)

    def list_exports(self, tenant_id: str) -> list[str]:
        return self.store.list_case_ids(tenant_id)

    # ------------------------------------------------------------- 查询

    def chunks_status(self, case_id: str, tenant_id: str) -> list[dict[str, Any]]:
        """每个分片是否已领取、由谁、依据哪份清单、计费编号。"""
        aggregate = self._replay(case_id, tenant_id)
        result: list[dict[str, Any]] = []
        for chunk in aggregate.chunks:
            index = chunk["chunk_index"]
            claim = aggregate.claims.get((aggregate.manifest_version, index))
            result.append(
                {
                    "chunk_index": index,
                    "manifest_version": aggregate.manifest_version,
                    "file_ids": list(chunk["file_ids"]),
                    "size_bytes": chunk["size_bytes"],
                    "chunk_hash": chunk["chunk_hash"],
                    "claimed": claim is not None,
                    "delivery_id": None if claim is None else claim.delivery_id,
                    "claimed_by": None if claim is None else claim.claimed_by,
                    "claimed_at": None if claim is None else claim.claimed_at.isoformat(),
                    "billing_record_id": None if claim is None else claim.billing_record_id,
                }
            )
        return result

    def file_inclusions(self, case_id: str, tenant_id: str) -> list[EntryInclusion]:
        """管理员视角：每个文件为何纳入、批准人、所属分片与领取情况。"""
        aggregate = self._replay(case_id, tenant_id)
        approver_ids: dict[str, tuple[str, ...]] = {}
        now = self._now()
        for approval in aggregate.current_approvals(now) if aggregate.has_live_manifest() else []:
            approver_ids.setdefault(approval.role, approval.approver_id)
        role_tuple = tuple(sorted(approver_ids.items()))
        result: list[EntryInclusion] = []
        for raw in aggregate.entries:
            entry = self._entry_from_payload(raw)
            index = aggregate.chunk_of_file(entry.file_id)
            claim = None
            if index is not None:
                claim = aggregate.claims.get((aggregate.manifest_version, index))
            result.append(
                EntryInclusion(
                    entry=entry,
                    chunk_index=-1 if index is None else index,
                    approver_ids=tuple(approver for _, approver in role_tuple),
                    claimed_at=None if claim is None else claim.claimed_at.isoformat(),
                    claimed_by=None if claim is None else claim.claimed_by,
                    claim_idempotency_key=None if claim is None else claim.claim_key,
                )
            )
        return result

    def audit_summary(self, case_id: str, tenant_id: str) -> dict[str, Any]:
        """独立重算并比对，给出最终清单与审计摘要是否一致的结论。"""
        events = self.store.load_events(case_id)
        if not events:
            raise NotFoundError(f"导出申请不存在：{case_id}")
        if events[0].tenant_id != tenant_id:
            raise NotFoundError(f"导出申请不存在：{case_id}")
        aggregate = self._replay(case_id, tenant_id)
        now = self._now()
        checks: list[dict[str, Any]] = []

        def check(name: str, ok: bool, detail: str) -> None:
            checks.append({"check": name, "ok": ok, "detail": detail})

        # 1. 事件流本身：序号连续、事件类型合法、时间带时区。
        seq_ok = [event.seq for event in events] == list(range(1, len(events) + 1))
        check("event_sequence", seq_ok, f"{len(events)} 条事件，序号从 1 连续")
        tz_ok = all(datetime.fromisoformat(e.occurred_at).tzinfo is not None for e in events)
        check("event_timezone", tz_ok, "全部事件时间带时区")

        # 2. 清单哈希：用条目原文重算，与分级事件记录的哈希逐一比对。
        manifest_events = [e for e in events if e.event_type == EVENT_MANIFEST_CLASSIFIED]
        hash_ok = True
        hash_detail: list[str] = []
        for event in manifest_events:
            recomputed = manifest_hash(event.payload["entries"])
            recorded = event.payload["manifest_hash"]
            same = recomputed == recorded
            hash_ok = hash_ok and same
            hash_detail.append(f"v{event.payload['manifest_version']}:{'一致' if same else '不一致'}")
        current_hash_ok = True
        if aggregate.has_live_manifest():
            current_hash_ok = manifest_hash(aggregate.entries) == aggregate.manifest_hash
        check(
            "manifest_hash",
            hash_ok and current_hash_ok,
            "；".join(hash_detail) or "无清单",
        )

        # 3. 批准绑定：每条批准都绑定清单哈希+接收方+有效期，且引用的哈希必须出现过。
        known_hashes = {e.payload["manifest_hash"] for e in manifest_events}
        approvals_ok = True
        approval_detail: list[str] = []
        for event in events:
            if event.event_type != EVENT_APPROVAL_RECORDED:
                continue
            payload = event.payload
            bound = (
                payload["manifest_hash"] in known_hashes
                and bool(payload["recipient"])
                and payload["valid_from"] < payload["valid_until"]
            )
            approvals_ok = approvals_ok and bound
            approval_detail.append(
                f"{payload['role']}/{payload['approver_id']}:"
                f"{'绑定完整' if bound else '绑定异常'}"
            )
        check(
            "approval_binding",
            approvals_ok,
            "；".join(approval_detail) or "无批准",
        )

        # 4. 当前生效批准是否满足分级要求。
        if aggregate.has_live_manifest() and aggregate.state not in ("revoked", "expired"):
            live = aggregate.current_approvals(now)
            roles = {item.role for item in live}
            required = set(aggregate.required_roles())
            check(
                "approval_complete",
                required <= roles,
                f"需要 {sorted(required)}，当前生效 {sorted(roles)}",
            )
        else:
            check("approval_complete", True, "终态或无生效清单，无需生效批准")

        # 5. 交付与计费：每条 chunk.claimed 恰好一条计费，编号互相对应。
        billing = self.store.billing_for_case(case_id)
        claim_events = [e for e in events if e.event_type == EVENT_CHUNK_CLAIMED]
        billing_by_key = {row["claim_key"]: row for row in billing}
        delivery_ok = len(billing) == len(claim_events)
        for event in claim_events:
            row = billing_by_key.get(event.payload["claim_key"])
            if row is None or row["billing_record_id"] != event.payload["billing_record_id"]:
                delivery_ok = False
            # 交付事件记录的批准必须真实存在。
            for ref in event.payload.get("approvers", []):
                if not any(
                    a.role == ref["role"]
                    and a.approver_id == ref["approver_id"]
                    and a.manifest_hash == event.payload["manifest_hash"]
                    for a in aggregate.approvals
                ):
                    delivery_ok = False
        check(
            "delivery_billing",
            delivery_ok,
            f"{len(claim_events)} 次交付 / {len(billing)} 条计费，一一对应",
        )

        # 6. 状态与领取进度一致。
        progress_ok = True
        if aggregate.state == "completed":
            progress_ok = aggregate.all_chunks_claimed()
        claimed_current = sum(
            1 for (version, _) in aggregate.claims if version == aggregate.manifest_version
        )
        check(
            "delivery_progress",
            progress_ok,
            f"状态 {aggregate.state}，当前清单已领取 {claimed_current}/{len(aggregate.chunks)}",
        )

        # 7. 分片计划完整覆盖清单条目且无重复。
        plan_ok = True
        if aggregate.has_live_manifest():
            planned = [fid for chunk in aggregate.chunks for fid in chunk["file_ids"]]
            entry_ids = [entry["file_id"] for entry in aggregate.entries]
            plan_ok = sorted(planned) == sorted(entry_ids) and len(planned) == len(set(planned))
        check("chunk_plan", plan_ok, "分片覆盖全部文件且无重复")

        consistent = all(item["ok"] for item in checks)
        return {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "state": aggregate.state,
            "manifest_version": aggregate.manifest_version,
            "manifest_hash": aggregate.manifest_hash,
            "event_count": len(events),
            "claim_count": len(claim_events),
            "billing_count": len(billing),
            "consistent": consistent,
            "checks": checks,
            "audited_at": now.isoformat(),
        }

    # ============================================================== 命令

    def create_export(
        self,
        tenant_id: str,
        applicant_id: str,
        business_purpose: str,
        recipient: str,
        *,
        case_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """申请人提交业务目的与接收方，创建 draft 申请。"""
        self._require("tenant_id", tenant_id)
        self._require("applicant_id", applicant_id)
        self._require("business_purpose", business_purpose)
        self._require("recipient", recipient)
        case_id = case_id or "case-" + uuid.uuid4().hex
        conn = self.store.connection
        with conn:  # 单事务
            fingerprint = digest_hex(
                {"applicant": applicant_id, "purpose": business_purpose, "recipient": recipient}
            )
            replay = self._idem_start(
                conn, tenant_id, "create", idempotency_key, fingerprint
            )
            if replay is not None:
                return replay
            if self.store.case_exists(case_id):
                raise ConflictError(f"导出申请已存在：{case_id}")
            now = self._now().isoformat()
            event = Event(
                event_id="evt-" + uuid.uuid4().hex,
                event_type=EVENT_EXPORT_REQUESTED,
                aggregate_id=case_id,
                tenant_id=tenant_id,
                seq=1,
                occurred_at=now,
                actor_id=applicant_id,
                payload={
                    "tenant_id": tenant_id,
                    "applicant_id": applicant_id,
                    "business_purpose": business_purpose,
                    "recipient": recipient,
                },
            )
            self.store.append_event(event, conn)
            result = self._to_view(self._replay_readonly(case_id)).to_dict()
            self._idem_finish(
                conn, tenant_id, "create", idempotency_key, case_id,
                fingerprint, result, now,
            )
            return result

    def classify_manifest(
        self,
        case_id: str,
        tenant_id: str,
        actor_id: str,
        entries: list[dict[str, Any]],
        chunk_size_bytes: int,
    ) -> ExportView:
        """冻结不可变清单并按敏感等级分级，决定审批要求。

        首版在 draft 下生成；等待期间文件变化后应先调用 ``invalidate``，
        再用新版本调用本方法重新分级，旧批准因哈希不同不再生效。
        """
        clean_entries = self._validate_entries(entries)
        if not isinstance(chunk_size_bytes, int) or chunk_size_bytes <= 0:
            raise ValidationError("chunk_size_bytes 必须为正整数")
        self._pre_expire(case_id, tenant_id)
        conn = self.store.connection
        with conn:
            aggregate = self._replay(case_id, tenant_id)
            if aggregate.state not in (STATE_DRAFT, STATE_AWAITING_APPROVAL):
                raise ConflictError(
                    f"当前状态 {aggregate.state} 不能冻结清单",
                    code="manifest_not_allowed",
                )
            if aggregate.state == STATE_AWAITING_APPROVAL and aggregate.has_live_manifest():
                raise ConflictError(
                    "现行清单仍然有效；文件确有变化时请先作废再重新分级",
                    code="manifest_not_allowed",
                )
            version = aggregate.manifest_version + 1
            sensitivity = highest_level([item["sensitivity"] for item in clean_entries])
            chunks = plan_chunks(clean_entries, chunk_size_bytes)
            hash_value = manifest_hash(clean_entries)
            now_dt = self._now()
            seq = self.store.next_seq(case_id)
            classified = Event(
                event_id="evt-" + uuid.uuid4().hex,
                event_type=EVENT_MANIFEST_CLASSIFIED,
                aggregate_id=case_id,
                tenant_id=tenant_id,
                seq=seq,
                occurred_at=now_dt.isoformat(),
                actor_id=actor_id,
                payload={
                    "manifest_version": version,
                    "manifest_hash": hash_value,
                    "sensitivity": sensitivity,
                    "entries": clean_entries,
                    "chunks": chunks,
                    "chunk_size_bytes": chunk_size_bytes,
                },
            )
            aggregate.apply(classified.event_type, classified.payload, seq, classified.occurred_at)
            self.store.append_event(classified, conn)

            # normal 等级无需人工共同批准：系统生成与人工批准同构的自动批准。
            if aggregate.state == STATE_CLASSIFIED:
                validity = self.policy.clamp_validity(sensitivity, None)
                auto = self._approval_event(
                    conn, aggregate, ROLE_SYSTEM_AUTO, "system",
                    now_dt, now_dt + validity,
                )
                aggregate.apply(auto.event_type, auto.payload, auto.seq, auto.occurred_at)
                self.store.append_event(auto, conn)
            return self._to_view(self._replay_readonly(case_id))

    def record_approval(
        self,
        case_id: str,
        tenant_id: str,
        role: str,
        approver_id: str,
        valid_for: timedelta | None = None,
    ) -> ExportView:
        """记录一名批准人；批准只对当前清单哈希、接收方和有效期生效。"""
        self._pre_expire(case_id, tenant_id)
        conn = self.store.connection
        with conn:
            aggregate = self._replay(case_id, tenant_id)
            required = aggregate.required_roles()
            if role not in required:
                raise ValidationError(
                    f"等级 {aggregate.sensitivity} 不需要角色 {role} 的批准"
                    f"（需要：{'、'.join(required)}）"
                )
            if not aggregate.has_live_manifest():
                raise ConflictError("清单已作废，无法对旧清单批准", code="manifest_stale")
            now_dt = self._now()
            # 同一角色对同一哈希的批准幂等：同人重试直接回放，换了人则冲突。
            existing = [
                item for item in aggregate.approvals
                if item.role == role and item.manifest_hash == aggregate.manifest_hash
            ]
            if existing:
                if existing[-1].approver_id != approver_id:
                    raise ConflictError(
                        f"角色 {role} 已由 {existing[-1].approver_id} 批准本清单",
                        code="approver_conflict",
                    )
                return self._to_view(aggregate)
            validity = self.policy.clamp_validity(aggregate.sensitivity, valid_for)
            event = self._approval_event(
                conn, aggregate, role, approver_id, now_dt, now_dt + validity,
            )
            aggregate.apply(event.event_type, event.payload, event.seq, event.occurred_at)
            self.store.append_event(event, conn)
            return self._to_view(self._replay_readonly(case_id))

    def invalidate_manifest(
        self,
        case_id: str,
        tenant_id: str,
        actor_id: str,
        changed_files: list[str],
        reason: str = "",
    ) -> ExportView:
        """等待/交付期间文件发生变化：作废现行清单，强制重新评估。"""
        if not changed_files:
            raise ValidationError("作废清单必须指明发生变化的文件")
        conn = self.store.connection
        with conn:
            aggregate = self._replay(case_id, tenant_id)
            if not aggregate.has_live_manifest():
                raise ConflictError("当前没有生效清单，无需作废")
            if aggregate.state not in (STATE_AWAITING_APPROVAL, STATE_APPROVED, STATE_DELIVERING):
                raise ConflictError(f"当前状态 {aggregate.state} 不允许作废清单")
            now = self._now().isoformat()
            seq = self.store.next_seq(case_id)
            event = Event(
                event_id="evt-" + uuid.uuid4().hex,
                event_type=EVENT_MANIFEST_INVALIDATED,
                aggregate_id=case_id,
                tenant_id=tenant_id,
                seq=seq,
                occurred_at=now,
                actor_id=actor_id,
                payload={
                    "manifest_version": aggregate.manifest_version,
                    "manifest_hash": aggregate.manifest_hash,
                    "changed_files": list(changed_files),
                    "reason": reason,
                },
            )
            aggregate.apply(event.event_type, event.payload, seq, now)
            self.store.append_event(event, conn)
            return self._to_view(self._replay_readonly(case_id))

    def claim_chunk(
        self,
        case_id: str,
        tenant_id: str,
        chunk_index: int,
        claim_key: str,
        claimed_by: str,
    ) -> ChunkClaim:
        """领取一个分片（支持续传重试）。

        - 同一 ``claim_key`` 重试：回放同一条交付事实与同一计费编号；
        - 不同 ``claim_key`` 领取已领取分片：冲突；
        - 撤销、过期、清单版本落后：未领取分片一律拒绝。
        """
        self._require("claim_key", claim_key)
        self._require("claimed_by", claimed_by)
        if not isinstance(chunk_index, int):
            raise ValidationError("chunk_index 必须为整数")
        conn = self.store.connection
        with conn:
            fingerprint = digest_hex(
                {"case_id": case_id, "chunk_index": chunk_index, "claimed_by": claimed_by}
            )
            replay = self._idem_start(conn, tenant_id, "claim", claim_key, fingerprint)
            if replay is not None:
                replay["retried"] = True
                return ChunkClaim(**replay)
        self._pre_expire(case_id, tenant_id)
        with conn:
            aggregate = self._replay(case_id, tenant_id)
            approvals = aggregate.ensure_claimable(chunk_index, self._now())
            slot = (aggregate.manifest_version, chunk_index)
            prior = aggregate.claims.get(slot)
            if prior is not None:
                raise ConflictError(
                    f"分片 {chunk_index} 已由领取键 {prior.claim_key} 领取",
                    code="chunk_already_claimed",
                )
            now_dt = self._now()
            now_iso = now_dt.isoformat()
            seq = self.store.next_seq(case_id)
            chunk = aggregate.chunks[chunk_index]
            delivery_id = "dlv-" + uuid.uuid4().hex
            billing_id = self.store.insert_billing(
                tenant_id=tenant_id,
                case_id=case_id,
                manifest_version=aggregate.manifest_version,
                chunk_index=chunk_index,
                claim_key=claim_key,
                amount_units=int(chunk["size_bytes"]),
                now_iso=now_iso,
                conn=conn,
            )
            approver_refs = [
                {
                    "role": item.role,
                    "approver_id": item.approver_id,
                    "approval_id": item.approval_id,
                }
                for item in approvals
            ]
            event = Event(
                event_id="evt-" + uuid.uuid4().hex,
                event_type=EVENT_CHUNK_CLAIMED,
                aggregate_id=case_id,
                tenant_id=tenant_id,
                seq=seq,
                occurred_at=now_iso,
                actor_id=claimed_by,
                payload={
                    "delivery_id": delivery_id,
                    "manifest_version": aggregate.manifest_version,
                    "manifest_hash": aggregate.manifest_hash,
                    "chunk_index": chunk_index,
                    "chunk_hash": chunk["chunk_hash"],
                    "claim_key": claim_key,
                    "claimed_by": claimed_by,
                    "claimed_at": now_iso,
                    "billing_record_id": billing_id,
                    "approvers": approver_refs,
                },
                idempotency_key=claim_key,
            )
            aggregate.apply(event.event_type, event.payload, seq, now_iso)
            self.store.append_event(event, conn)

            follow_events: list[Event] = []
            if aggregate.all_chunks_claimed():
                complete_seq = seq + 1
                complete = Event(
                    event_id="evt-" + uuid.uuid4().hex,
                    event_type=EVENT_EXPORT_COMPLETED,
                    aggregate_id=case_id,
                    tenant_id=tenant_id,
                    seq=complete_seq,
                    occurred_at=now_iso,
                    actor_id=claimed_by,
                    payload={"completed_at": now_iso},
                )
                aggregate.apply(
                    complete.event_type, complete.payload, complete_seq, now_iso
                )
                follow_events.append(complete)
            for item in follow_events:
                self.store.append_event(item, conn)

            result = {
                "delivery_id": delivery_id,
                "case_id": case_id,
                "chunk_index": chunk_index,
                "claim_key": claim_key,
                "claimed_by": claimed_by,
                "claimed_at": now_iso,
                "billing_record_id": billing_id,
                "billed": True,
                "retried": False,
            }
            self._idem_finish(
                conn, tenant_id, "claim", claim_key, case_id,
                fingerprint, result, now_iso,
            )
            return ChunkClaim(**result)

    def revoke(
        self,
        case_id: str,
        tenant_id: str,
        actor_id: str,
        reason: str,
    ) -> ExportView:
        """安全值班员/管理员撤销：此后任何未领取分片立即失效。"""
        self._require("reason", reason)
        conn = self.store.connection
        with conn:
            aggregate = self._replay(case_id, tenant_id)
            if aggregate.state in ("revoked",):
                return self._to_view(aggregate)
            if aggregate.state in ("completed", "expired"):
                raise ConflictError(f"终态 {aggregate.state} 不能撤销")
            now = self._now().isoformat()
            seq = self.store.next_seq(case_id)
            event = Event(
                event_id="evt-" + uuid.uuid4().hex,
                event_type=EVENT_EXPORT_REVOKED,
                aggregate_id=case_id,
                tenant_id=tenant_id,
                seq=seq,
                occurred_at=now,
                actor_id=actor_id,
                payload={"reason": reason},
            )
            aggregate.apply(event.event_type, event.payload, seq, now)
            self.store.append_event(event, conn)
            return self._to_view(self._replay_readonly(case_id))

    def expire_due(self, tenant_id: str | None = None) -> list[str]:
        """把所有已到有效期的申请置为 expired，返回被处理的 case 列表。

        可由定时任务调用；命令路径自身也会惰性过期，因此重启后第一次
        访问同样能得到正确阶段。
        """
        expired: list[str] = []
        for case_id in self.store.list_case_ids(tenant_id):
            conn = self.store.connection
            with conn:
                aggregate = self._replay(case_id)
                if self._expire_if_due(conn, aggregate):
                    expired.append(case_id)
        return expired

    # ============================================================ 内部

    def _pre_expire(self, case_id: str, tenant_id: str) -> None:
        """在命令事务之前用独立事务完成惰性过期。

        过期事件必须独立提交：若与随后被拒绝的命令在同一事务里，命令抛出
        冲突会连带回滚过期事实，重启后阶段就会错误地"复活"。
        """
        conn = self.store.connection
        with conn:
            aggregate = self._replay(case_id, tenant_id)
            self._expire_if_due(conn, aggregate)

    def _expire_if_due(self, conn, aggregate: ExportAggregate) -> bool:
        """已过批准有效期则追加 expired 事件；返回是否发生了过期。"""
        end = aggregate.validity_end()
        if end is None or aggregate.state in ("completed", "revoked", "expired"):
            return False
        if self._now() <= end:
            return False
        now_iso = self._now().isoformat()
        seq = self.store.next_seq(aggregate.case_id)
        event = Event(
            event_id="evt-" + uuid.uuid4().hex,
            event_type=EVENT_EXPORT_EXPIRED,
            aggregate_id=aggregate.case_id,
            tenant_id=aggregate.tenant_id,
            seq=seq,
            occurred_at=now_iso,
            actor_id="system",
            payload={"valid_until": end.isoformat()},
        )
        aggregate.apply(event.event_type, event.payload, seq, now_iso)
        self.store.append_event(event, conn)
        return True

    def _approval_event(
        self,
        conn,
        aggregate: ExportAggregate,
        role: str,
        approver_id: str,
        valid_from: datetime,
        valid_until: datetime,
    ) -> Event:
        assert aggregate.manifest_hash is not None
        seq = self.store.next_seq(aggregate.case_id)
        return Event(
            event_id="evt-" + uuid.uuid4().hex,
            event_type=EVENT_APPROVAL_RECORDED,
            aggregate_id=aggregate.case_id,
            tenant_id=aggregate.tenant_id,
            seq=seq,
            occurred_at=valid_from.isoformat(),
            actor_id=approver_id,
            payload={
                "approval_id": "apr-" + uuid.uuid4().hex,
                "role": role,
                "approver_id": approver_id,
                "manifest_hash": aggregate.manifest_hash,
                "manifest_version": aggregate.manifest_version,
                "recipient": aggregate.recipient,
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_until.isoformat(),
            },
        )

    # ---------------------------------------------------------- 幂等辅助

    def _idem_start(self, conn, tenant_id: str, scope: str, key: str | None,
                    fingerprint: str | None = None):
        """命中幂等键时返回首次响应；同键指纹不同则判为冲突。"""
        if key is None:
            return None
        row = self.store.idempotency_lookup(tenant_id, scope, key, conn)
        if row is None:
            return None
        if fingerprint is not None and row["fingerprint"] != fingerprint:
            raise ConflictError(
                "幂等键已用于不同的请求参数", code="idempotency_fingerprint_mismatch"
            )
        import json as _json

        return _json.loads(row["response_json"])

    def _idem_finish(
        self, conn, tenant_id, scope, key, case_id, fingerprint, response, now_iso
    ) -> None:
        if key is None:
            return
        self.store.idempotency_store(
            tenant_id, scope, key, case_id, fingerprint, response, now_iso, conn
        )

    # ---------------------------------------------------------- 组装视图

    def _replay_readonly(self, case_id: str) -> ExportAggregate:
        aggregate = ExportAggregate(case_id=case_id, policy=self.policy)
        for event in self.store.load_events(case_id):
            aggregate.apply(event.event_type, event.payload, event.seq, event.occurred_at)
        return aggregate

    def _to_view(self, aggregate: ExportAggregate) -> ExportView:
        events = [
            event.to_dict()
            for event in self.store.load_events(aggregate.case_id)
        ]
        approvals = [
            ApprovalView(
                approval_id=item.approval_id,
                role=item.role,
                approver_id=item.approver_id,
                manifest_hash=item.manifest_hash,
                recipient=item.recipient,
                valid_from=item.valid_from.isoformat(),
                valid_until=item.valid_until.isoformat(),
                record_seq=item.seq,
            )
            for item in aggregate.approvals
        ]
        claimed = [
            {
                "manifest_version": claim.manifest_version,
                "chunk_index": claim.chunk_index,
                "delivery_id": claim.delivery_id,
                "claim_key": claim.claim_key,
                "claimed_by": claim.claimed_by,
                "claimed_at": claim.claimed_at.isoformat(),
                "billing_record_id": claim.billing_record_id,
            }
            for claim in sorted(aggregate.claims.values(), key=lambda c: (c.manifest_version, c.chunk_index))
        ]
        return ExportView(
            case_id=aggregate.case_id,
            tenant_id=aggregate.tenant_id,
            applicant_id=aggregate.applicant_id,
            business_purpose=aggregate.business_purpose,
            recipient=aggregate.recipient,
            state=aggregate.state,
            sensitivity=aggregate.sensitivity,
            created_at=aggregate.created_at.isoformat() if aggregate.created_at else "",
            updated_at=aggregate.updated_at.isoformat() if aggregate.updated_at else "",
            manifest_hash=aggregate.manifest_hash,
            manifest_version=aggregate.manifest_version,
            entries=[self._entry_from_payload(raw) for raw in aggregate.entries],
            chunk_count=len(aggregate.chunks),
            chunk_size_bytes=aggregate.chunk_size_bytes,
            approvals=approvals,
            claimed_chunks=claimed,
            events=events,
        )

    @staticmethod
    def _entry_from_payload(raw: dict[str, Any]) -> ManifestEntry:
        return ManifestEntry(
            file_id=raw["file_id"],
            path=raw["path"],
            file_version=raw["file_version"],
            content_hash=raw["content_hash"],
            sensitivity=raw["sensitivity"],
            size_bytes=raw["size_bytes"],
            owner_id=raw["owner_id"],
            included_reason=raw["included_reason"],
        )

    @staticmethod
    def _require(name: str, value: Any) -> None:
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValidationError(f"缺少必填字段：{name}")

    @staticmethod
    def _validate_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not isinstance(entries, list) or not entries:
            raise ValidationError("清单至少包含一个文件")
        clean: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in entries:
            if not isinstance(raw, dict):
                raise ValidationError("清单条目必须是对象")
            missing = [field for field in _ENTRY_FIELDS if field not in raw]
            if missing:
                raise ValidationError("清单条目缺少字段：" + "、".join(missing))
            if raw["sensitivity"] not in _SENSITIVITY_ALLOWED:
                raise ValidationError(
                    f"非法敏感等级：{raw['sensitivity']}（允许 normal/confidential/restricted）"
                )
            if not isinstance(raw["size_bytes"], int) or raw["size_bytes"] < 0:
                raise ValidationError("size_bytes 必须为非负整数")
            for field_name in ("file_id", "path", "file_version", "content_hash", "included_reason"):
                if not isinstance(raw[field_name], str) or not raw[field_name].strip():
                    raise ValidationError(f"字段 {field_name} 必须是非空字符串")
            if raw["file_id"] in seen:
                raise ValidationError(f"清单内文件重复：{raw['file_id']}")
            seen.add(raw["file_id"])
            clean.append({field: raw[field] for field in _ENTRY_FIELDS})
        clean.sort(key=lambda item: item["file_id"])
        return clean


def plan_chunks(entries: list[dict[str, Any]], chunk_size_bytes: int) -> list[dict[str, Any]]:
    """按大小上限确定性地切分清单。

    文件已按 file_id 排序；小文件顺序装箱，超大文件独占一片并在
    ``oversized`` 中标记，结果对同一份清单永远一致。
    """
    chunks: list[dict[str, Any]] = []
    current_ids: list[str] = []
    current_size = 0

    def flush() -> None:
        nonlocal current_ids, current_size
        if not current_ids:
            return
        index = len(chunks)
        chunks.append(
            {
                "chunk_index": index,
                "file_ids": list(current_ids),
                "size_bytes": current_size,
                "oversized": current_size > chunk_size_bytes,
                "chunk_hash": digest_hex(
                    {
                        "index": index,
                        "files": [
                            {"file_id": e["file_id"], "content_hash": e["content_hash"]}
                            for e in entries
                            if e["file_id"] in current_ids
                        ],
                    }
                ),
            }
        )
        current_ids = []
        current_size = 0

    for entry in entries:  # entries 已排序
        size = int(entry["size_bytes"])
        if size > chunk_size_bytes and current_ids:
            flush()
        if current_size + size > chunk_size_bytes and current_ids:
            flush()
        current_ids.append(entry["file_id"])
        current_size += size
        if size > chunk_size_bytes:
            flush()
    flush()
    return chunks
