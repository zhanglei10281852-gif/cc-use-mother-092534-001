"""事件定义、规范序列化与清单哈希。

合同（``domain/contract.json``）规定：已发布事实通过新版本追加，不覆盖
历史。本模块的事件即唯一事实来源；哈希采用确定性的规范 JSON 序列化，
保证不同进程/重启后重算结果一致。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

# 事件类型必须与 domain/contract.json 的 event_types 一一对应。
EVENT_EXPORT_REQUESTED = "export.requested"
EVENT_MANIFEST_CLASSIFIED = "manifest.classified"
EVENT_APPROVAL_RECORDED = "approval.recorded"
EVENT_MANIFEST_INVALIDATED = "manifest.invalidated"
EVENT_CHUNK_CLAIMED = "chunk.claimed"
EVENT_EXPORT_COMPLETED = "export.completed"
EVENT_EXPORT_REVOKED = "export.revoked"
EVENT_EXPORT_EXPIRED = "export.expired"

ALL_EVENT_TYPES: tuple[str, ...] = (
    EVENT_EXPORT_REQUESTED,
    EVENT_MANIFEST_CLASSIFIED,
    EVENT_MANIFEST_INVALIDATED,
    EVENT_APPROVAL_RECORDED,
    EVENT_CHUNK_CLAIMED,
    EVENT_EXPORT_COMPLETED,
    EVENT_EXPORT_REVOKED,
    EVENT_EXPORT_EXPIRED,
)


def canonical_json(value: Any) -> bytes:
    """把对象序列化成跨进程稳定的字节串。

    - 键按字典序排序，避免插入顺序差异；
    - 不保留空白；
    - 非 ASCII 字符原样输出（UTF-8），不转义；
    - 不允许 ``ensure_ascii`` 带来的转义差异。
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def manifest_hash(entries: list[dict[str, Any]]) -> str:
    """清单哈希：对全部条目按规范形式计算 SHA-256。

    条目的路径、版本、内容哈希、大小、敏感等级与纳入原因都参与摘要，
    任何一项变化都会得到不同哈希，使旧批准因哈希不匹配而失效。
    """
    ordered = [dict(sorted(entry.items())) for entry in entries]
    return digest_hex({"manifest_version_payload": ordered})


@dataclass(frozen=True)
class Event:
    """一条不可变领域事件。"""

    event_id: str
    event_type: str
    aggregate_id: str
    tenant_id: str
    seq: int
    occurred_at: str  # ISO 8601 带时区
    actor_id: str
    payload: dict[str, Any]
    idempotency_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "aggregate_id": self.aggregate_id,
            "tenant_id": self.tenant_id,
            "seq": self.seq,
            "occurred_at": self.occurred_at,
            "actor_id": self.actor_id,
            "payload": self.payload,
        }
        if self.idempotency_key is not None:
            data["idempotency_key"] = self.idempotency_key
        return data

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Event":
        payload = row["payload_json"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        return cls(
            event_id=row["event_id"],
            event_type=row["event_type"],
            aggregate_id=row["aggregate_id"],
            tenant_id=row["tenant_id"],
            seq=row["seq"],
            occurred_at=row["occurred_at"],
            actor_id=row["actor_id"],
            payload=payload,
            idempotency_key=row["idempotency_key"],
        )
