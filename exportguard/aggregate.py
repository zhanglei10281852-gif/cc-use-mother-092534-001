"""导出申请聚合：从事件流重建状态并执行状态机规则。

状态集合来自 ``domain/contract.json``：

    draft → classified → awaiting_approval → approved → delivering → completed
                         任意人工/交付阶段 ↘ invalidated（重新分级后回到审批）
                         任意非终态 ↘ revoked / expired

聚合本身不写库；服务层校验命令、追加事件，聚合只负责 apply 与规则判断，
因此重启后用全部事件重放即可得到完全一致的阶段。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

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
)
from .policy import (
    ROLE_SYSTEM_AUTO,
    ApprovalPolicy,
    default_policy,
    highest_level,
)

STATE_DRAFT = "draft"
STATE_CLASSIFIED = "classified"
STATE_AWAITING_APPROVAL = "awaiting_approval"
STATE_APPROVED = "approved"
STATE_DELIVERING = "delivering"
STATE_COMPLETED = "completed"
STATE_REVOKED = "revoked"
STATE_EXPIRED = "expired"

# 合同未给"清单作废"单独定义状态：作废后回到等待审批，等待重新分级与
# 批准；作废事实本身由 manifest.invalidated 事件永久保留。
STATE_PENDING_REEVALUATION = STATE_AWAITING_APPROVAL

TERMINAL_STATES = frozenset({STATE_COMPLETED, STATE_REVOKED, STATE_EXPIRED})


def _parse(ts: str) -> datetime:
    value = datetime.fromisoformat(ts)
    if value.tzinfo is None:
        raise ValueError(f"时间缺少时区：{ts}")
    return value


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    role: str
    approver_id: str
    manifest_hash: str
    manifest_version: int
    recipient: str
    valid_from: datetime
    valid_until: datetime
    seq: int

    def covers(self, manifest_hash: str, recipient: str, moment: datetime) -> bool:
        return (
            self.manifest_hash == manifest_hash
            and self.recipient == recipient
            and self.valid_from <= moment <= self.valid_until
        )


@dataclass(frozen=True)
class ClaimRecord:
    delivery_id: str
    manifest_version: int
    chunk_index: int
    claim_key: str
    claimed_by: str
    claimed_at: datetime
    billing_record_id: str
    approvers: tuple[tuple[str, str], ...]
    manifest_hash: str
    seq: int

    @property
    def claim_key_tuple(self) -> tuple[int, int]:
        return (self.manifest_version, self.chunk_index)


@dataclass
class ExportAggregate:
    case_id: str
    tenant_id: str = ""
    applicant_id: str = ""
    business_purpose: str = ""
    recipient: str = ""
    state: str = STATE_DRAFT
    sensitivity: str = "normal"
    manifest_version: int = 0
    manifest_hash: str | None = None
    entries: list[dict[str, Any]] = field(default_factory=list)
    chunks: list[dict[str, Any]] = field(default_factory=list)
    chunk_size_bytes: int = 0
    approvals: list[ApprovalRecord] = field(default_factory=list)
    claims: dict[tuple[int, int], ClaimRecord] = field(default_factory=dict)
    revoke_reason: str | None = None
    revoke_seq: int | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_seq: int = 0
    policy: ApprovalPolicy = field(default_factory=default_policy)

    # ------------------------------------------------------------------ apply

    def apply(self, event_type: str, payload: dict[str, Any], seq: int, occurred_at: str) -> None:
        moment = _parse(occurred_at)
        self.last_seq = seq
        self.updated_at = moment
        if event_type == EVENT_EXPORT_REQUESTED:
            self._assert_state(STATE_DRAFT, event_type)
            self.tenant_id = payload["tenant_id"]
            self.applicant_id = payload["applicant_id"]
            self.business_purpose = payload["business_purpose"]
            self.recipient = payload["recipient"]
            self.created_at = moment
        elif event_type == EVENT_MANIFEST_CLASSIFIED:
            # 允许从等待审批重新分级：等待期间文件变化会先作废清单，再重走分级。
            self._assert_state_in(
                (STATE_DRAFT, STATE_CLASSIFIED, STATE_AWAITING_APPROVAL), event_type
            )
            self.manifest_version = payload["manifest_version"]
            self.manifest_hash = payload["manifest_hash"]
            self.entries = list(payload["entries"])
            self.chunks = list(payload["chunks"])
            self.chunk_size_bytes = payload["chunk_size_bytes"]
            self.sensitivity = payload["sensitivity"]
            # 分级后立刻进入等待批准；normal 等级的自动批准事件紧随其后。
            self.state = (
                STATE_AWAITING_APPROVAL
                if self.policy.required_roles(self.sensitivity)
                else STATE_CLASSIFIED
            )
        elif event_type == EVENT_MANIFEST_INVALIDATED:
            self._assert_state_in(
                (STATE_AWAITING_APPROVAL, STATE_APPROVED, STATE_DELIVERING),
                event_type,
            )
            self.manifest_hash = None
            self.entries = []
            self.chunks = []
            # 合同未定义独立作废态：回到等待审批，旧批准因哈希不匹配全部失效。
            self.state = STATE_AWAITING_APPROVAL
        elif event_type == EVENT_APPROVAL_RECORDED:
            self._assert_state_in(
                (STATE_CLASSIFIED, STATE_AWAITING_APPROVAL, STATE_APPROVED, STATE_DELIVERING),
                event_type,
            )
            record = ApprovalRecord(
                approval_id=payload["approval_id"],
                role=payload["role"],
                approver_id=payload["approver_id"],
                manifest_hash=payload["manifest_hash"],
                manifest_version=payload["manifest_version"],
                recipient=payload["recipient"],
                valid_from=_parse(payload["valid_from"]),
                valid_until=_parse(payload["valid_until"]),
                seq=seq,
            )
            self.approvals.append(record)
            if self.state in (STATE_CLASSIFIED, STATE_AWAITING_APPROVAL) and self.is_approved(
                record.valid_from
            ):
                self.state = STATE_APPROVED
        elif event_type == EVENT_CHUNK_CLAIMED:
            self._assert_state_in((STATE_APPROVED, STATE_DELIVERING), event_type)
            claim = ClaimRecord(
                delivery_id=payload["delivery_id"],
                manifest_version=payload["manifest_version"],
                chunk_index=payload["chunk_index"],
                claim_key=payload["claim_key"],
                claimed_by=payload["claimed_by"],
                claimed_at=_parse(payload["claimed_at"]),
                billing_record_id=payload["billing_record_id"],
                approvers=tuple(
                    (item["role"], item["approver_id"]) for item in payload.get("approvers", [])
                ),
                manifest_hash=payload["manifest_hash"],
                seq=seq,
            )
            if claim.claim_key_tuple in self.claims:
                raise ConflictError(
                    f"分片 {claim.chunk_index}（清单 v{claim.manifest_version}）已被领取"
                )
            self.claims[claim.claim_key_tuple] = claim
            self.state = STATE_DELIVERING
        elif event_type == EVENT_EXPORT_COMPLETED:
            self._assert_state(STATE_DELIVERING, event_type)
            self.completed_at = _parse(payload["completed_at"])
            self.state = STATE_COMPLETED
        elif event_type == EVENT_EXPORT_REVOKED:
            self._assert_state_in(
                (
                    STATE_CLASSIFIED,
                    STATE_AWAITING_APPROVAL,
                    STATE_APPROVED,
                    STATE_DELIVERING,
                ),
                event_type,
            )
            self.revoke_reason = payload.get("reason")
            self.revoke_seq = seq
            self.state = STATE_REVOKED
        elif event_type == EVENT_EXPORT_EXPIRED:
            self._assert_state_in(
                (STATE_AWAITING_APPROVAL, STATE_APPROVED, STATE_DELIVERING),
                event_type,
            )
            self.state = STATE_EXPIRED
        else:  # pragma: no cover - 未知事件应在入库前拦截
            raise ValidationError(f"未知事件类型：{event_type}")

    # ------------------------------------------------------------- 规则判断

    def _assert_state(self, expected: str, event_type: str) -> None:
        if self.state != expected:
            raise ConflictError(
                f"当前状态 {self.state} 不接受事件 {event_type}（应为 {expected}）"
            )

    def _assert_state_in(self, allowed: tuple[str, ...], event_type: str) -> None:
        if self.state not in allowed:
            raise ConflictError(
                f"当前状态 {self.state} 不接受事件 {event_type}（允许：{'、'.join(allowed)}）"
            )

    def has_live_manifest(self) -> bool:
        return self.manifest_hash is not None and bool(self.entries)

    def required_roles(self) -> tuple[str, ...]:
        roles = self.policy.required_roles(self.sensitivity)
        return roles if roles else (ROLE_SYSTEM_AUTO,)

    def current_approvals(self, moment: datetime) -> list[ApprovalRecord]:
        """当前清单哈希、接收方、在有效期内的批准。"""
        assert self.manifest_hash is not None
        return [
            item
            for item in self.approvals
            if item.covers(self.manifest_hash, self.recipient, moment)
        ]

    def is_approved(self, moment: datetime) -> bool:
        if not self.has_live_manifest():
            return False
        by_role = {item.role: item for item in self.current_approvals(moment)}
        return all(role in by_role for role in self.required_roles())

    def validity_end(self) -> datetime | None:
        """当前生效批准的最早失效时间；超过它整个导出应转为 expired。"""
        if not self.has_live_manifest() or self.state in TERMINAL_STATES:
            return None
        assert self.manifest_hash is not None
        bound = [
            item
            for item in self.approvals
            if item.manifest_hash == self.manifest_hash and item.recipient == self.recipient
        ]
        if not bound:
            return None
        return min(item.valid_until for item in bound)

    def ensure_claimable(self, chunk_index: int, moment: datetime) -> list[ApprovalRecord]:
        """领取前的全部硬性校验，返回本次交付所依据的批准集合。"""
        if self.state == STATE_REVOKED:
            raise ConflictError("导出已被撤销，未领取分片全部失效", code="revoked")
        if self.state == STATE_EXPIRED:
            raise ConflictError("批准已过期，未领取分片全部失效", code="expired")
        if self.state not in (STATE_APPROVED, STATE_DELIVERING):
            raise ConflictError(
                f"当前状态 {self.state} 不允许领取分片：批准缺失、版本落后或已失效",
                code="approval_stale",
            )
        if not self.has_live_manifest():
            raise ConflictError("清单已作废，需重新分级审批", code="manifest_stale")
        if chunk_index < 0 or chunk_index >= len(self.chunks):
            raise ValidationError(
                f"分片序号超出范围：{chunk_index}（共 {len(self.chunks)} 片）"
            )
        claim_slot = (self.manifest_version, chunk_index)
        if claim_slot in self.claims:
            raise ConflictError(
                f"分片 {chunk_index} 已被领取", code="chunk_already_claimed"
            )
        approvals = self.current_approvals(moment)
        by_role = {item.role: item for item in approvals}
        missing = [role for role in self.required_roles() if role not in by_role]
        if missing:
            raise ConflictError(
                "当前批准缺失或已不覆盖此清单/接收方/时刻：" + "、".join(missing),
                code="approval_stale",
            )
        return approvals

    def all_chunks_claimed(self) -> bool:
        if not self.chunks:
            return False
        current = {
            index
            for (version, index) in self.claims
            if version == self.manifest_version
        }
        return len(current) == len(self.chunks)

    def chunk_of_file(self, file_id: str) -> int | None:
        for chunk in self.chunks:
            if file_id in chunk["file_ids"]:
                return chunk["chunk_index"]
        return None

    def expected_sensitivity(self) -> str:
        return highest_level([entry["sensitivity"] for entry in self.entries])
