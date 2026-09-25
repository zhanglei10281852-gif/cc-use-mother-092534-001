"""只读数据模型。

这些是查询返回的视图对象（不是聚合根）。写入路径只产生事件，
聚合状态由 ``aggregate`` 模块从事件流重建。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# 敏感等级由低到高，顺序即比较顺序，供分级审批策略使用。
SENSITIVITY_LEVELS = ("normal", "confidential", "restricted")

# 需要数据所有者与安全值班员共同批准的最低等级。
DUAL_APPROVAL_LEVEL = "confidential"


@dataclass(frozen=True)
class ManifestEntry:
    """清单中的一个文件行。

    ``file_version`` 是等待期间检测变化的依据：内容哈希或版本号任一
    变化都会产生新版本号，旧清单随之作废。
    """

    file_id: str
    path: str
    file_version: str
    content_hash: str
    sensitivity: str
    size_bytes: int
    owner_id: str
    included_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_id": self.file_id,
            "path": self.path,
            "file_version": self.file_version,
            "content_hash": self.content_hash,
            "sensitivity": self.sensitivity,
            "size_bytes": self.size_bytes,
            "owner_id": self.owner_id,
            "included_reason": self.included_reason,
        }


@dataclass(frozen=True)
class EntryInclusion:
    """管理视角：单个文件为什么被纳入、被谁批准、领取到哪个分片。"""

    entry: ManifestEntry
    chunk_index: int
    approver_ids: tuple[str, ...]
    claimed_at: str | None
    claimed_by: str | None
    claim_idempotency_key: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry.to_dict(),
            "chunk_index": self.chunk_index,
            "approver_ids": list(self.approver_ids),
            "claimed_at": self.claimed_at,
            "claimed_by": self.claimed_by,
            "claim_idempotency_key": self.claim_idempotency_key,
        }


@dataclass(frozen=True)
class ChunkClaim:
    """分片领取结果。

    重试同一幂等键时返回的仍是同一条交付事实：同一个 ``delivery_id``、
    同一份计费记录，绝不产生第二份。
    """

    delivery_id: str
    case_id: str
    chunk_index: int
    claim_key: str
    claimed_by: str
    claimed_at: str
    billing_record_id: str
    billed: bool
    retried: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "case_id": self.case_id,
            "chunk_index": self.chunk_index,
            "claim_key": self.claim_key,
            "claimed_by": self.claimed_by,
            "claimed_at": self.claimed_at,
            "billing_record_id": self.billing_record_id,
            "billed": self.billed,
            "retried": self.retried,
        }


@dataclass(frozen=True)
class ApprovalView:
    approval_id: str
    role: str
    approver_id: str
    manifest_hash: str
    recipient: str
    valid_from: str
    valid_until: str
    record_seq: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "role": self.role,
            "approver_id": self.approver_id,
            "manifest_hash": self.manifest_hash,
            "recipient": self.recipient,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "record_seq": self.record_seq,
        }


@dataclass(frozen=True)
class ExportView:
    """导出申请的完整管理视图。"""

    case_id: str
    tenant_id: str
    applicant_id: str
    business_purpose: str
    recipient: str
    state: str
    sensitivity: str
    created_at: str
    updated_at: str
    manifest_hash: str | None
    manifest_version: int
    entries: list[ManifestEntry] = field(default_factory=list)
    chunk_count: int = 0
    chunk_size_bytes: int = 0
    approvals: list[ApprovalView] = field(default_factory=list)
    claimed_chunks: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "applicant_id": self.applicant_id,
            "business_purpose": self.business_purpose,
            "recipient": self.recipient,
            "state": self.state,
            "sensitivity": self.sensitivity,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "manifest_hash": self.manifest_hash,
            "manifest_version": self.manifest_version,
            "entries": [entry.to_dict() for entry in self.entries],
            "chunk_count": self.chunk_count,
            "chunk_size_bytes": self.chunk_size_bytes,
            "approvals": [item.to_dict() for item in self.approvals],
            "claimed_chunks": list(self.claimed_chunks),
            "events": list(self.events),
        }
