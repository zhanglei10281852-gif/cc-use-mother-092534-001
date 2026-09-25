"""领域事件定义。

事件是只追加（append-only）的事实：状态可以重建，事件永不修改。
每个事件携带业务发生时间、操作者、聚合版本与载荷，``event_id`` 在
租户内全局唯一，既是去重键也是审计凭据。
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .time import normalize

# 与 domain/contract.json 中的 event_types 对齐。
EXPORT_REQUESTED = "export.requested"
MANIFEST_CLASSIFIED = "manifest.classified"
APPROVAL_RECORDED = "approval.recorded"
MANIFEST_INVALIDATED = "manifest.invalidated"
CHUNK_CLAIMED = "chunk.claimed"
EXPORT_COMPLETED = "export.completed"
EXPORT_REVOKED = "export.revoked"
EXPORT_EXPIRED = "export.expired"

EVENT_TYPES = frozenset(
    {
        EXPORT_REQUESTED,
        MANIFEST_CLASSIFIED,
        APPROVAL_RECORDED,
        MANIFEST_INVALIDATED,
        CHUNK_CLAIMED,
        EXPORT_COMPLETED,
        EXPORT_REVOKED,
        EXPORT_EXPIRED,
    }
)


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    tenant_id: str
    aggregate_id: str
    occurred_at: datetime
    actor_id: str
    aggregate_version: int
    payload: dict[str, Any]

    def to_row(self) -> tuple[str, str, str, str, str, str, int, str]:
        return (
            self.event_id,
            self.event_type,
            self.tenant_id,
            self.aggregate_id,
            normalize(self.occurred_at).isoformat(),
            self.actor_id,
            self.aggregate_version,
            json.dumps(self.payload, ensure_ascii=False, sort_keys=True),
        )

    @staticmethod
    def new_event_id() -> str:
        return f"evt-{uuid.uuid4().hex}"
