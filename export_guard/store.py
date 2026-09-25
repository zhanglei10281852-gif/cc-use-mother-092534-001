"""SQLite 存储层。

只负责表结构与基础读写，不包含业务判定。所有时间以 UTC ISO 字符串保存，
所有业务标识在 ``(tenant_id, ...)`` 维度内唯一。事件表只追加，
并通过 ``prev_hash`` 形成哈希链，任何事后篡改都会在审计对账时暴露。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Sequence

SCHEMA = """
create table if not exists file_catalog (
    tenant_id      text not null,
    file_id        text not null,
    file_version   text not null,
    content_hash   text not null,
    size_bytes     integer not null check (size_bytes >= 0),
    sensitivity    text not null,
    source_location text not null,
    updated_at     text not null,
    primary key (tenant_id, file_id)
);

create table if not exists export_request (
    tenant_id        text not null,
    case_id          text not null,
    applicant_id     text not null,
    business_purpose text not null,
    recipient_id     text not null,
    state            text not null,
    aggregate_version integer not null default 0,
    created_at       text not null,
    updated_at       text not null,
    primary key (tenant_id, case_id)
);

-- 每次冻结产生一条新版本，历史版本永不覆盖。
create table if not exists manifest_version (
    tenant_id        text not null,
    case_id          text not null,
    manifest_version integer not null,
    manifest_hash    text not null,
    max_sensitivity  text not null,
    required_roles_json text not null,
    status           text not null,            -- pending | active | superseded
    frozen_at        text not null,
    valid_until      text,
    superseded_at    text,
    primary key (tenant_id, case_id, manifest_version)
);

create table if not exists manifest_entry (
    tenant_id        text not null,
    case_id          text not null,
    manifest_version integer not null,
    entry_index      integer not null,
    file_id          text not null,
    file_version     text not null,
    content_hash     text not null,
    size_bytes       integer not null,
    sensitivity      text not null,
    source_location  text not null,
    inclusion_reason text not null,
    primary key (tenant_id, case_id, manifest_version, entry_index)
);

-- 审批绑定具体清单版本（哈希）、接收方与有效期。
create table if not exists approval (
    tenant_id         text not null,
    case_id           text not null,
    manifest_version  integer not null,
    role              text not null,
    approver_id       text not null,
    bound_manifest_hash text not null,
    bound_recipient_id text not null,
    valid_from        text not null,
    valid_until       text not null,
    recorded_at       text not null,
    primary key (tenant_id, case_id, manifest_version, role)
);

create table if not exists delivery_chunk (
    tenant_id        text not null,
    case_id          text not null,
    chunk_id         text not null,
    manifest_version integer not null,
    seq              integer not null,
    entry_indexes_json text not null,
    size_bytes       integer not null,
    content_token    text not null,
    primary key (tenant_id, case_id, chunk_id)
);

-- claim_key 是领取幂等键；同一 case 内唯一。
create table if not exists chunk_claim (
    tenant_id        text not null,
    case_id          text not null,
    claim_key        text not null,
    chunk_id         text not null,
    recipient_id     text not null,
    manifest_version integer not null,
    manifest_hash_at_claim text not null,
    state            text not null,            -- delivered
    claimed_at       text not null,
    primary key (tenant_id, case_id, claim_key)
);

-- 每个分片至多被领取一次（跨不同 claim_key 也不行）。
create unique index if not exists ux_chunk_claim_chunk
    on chunk_claim(tenant_id, case_id, chunk_id);

-- 每个首次成功领取恰好一条计费记录，重试不插入。
create table if not exists billing_record (
    tenant_id   text not null,
    case_id     text not null,
    claim_key   text not null,
    chunk_id    text not null,
    bytes       integer not null,
    charged_at  text not null,
    primary key (tenant_id, case_id, claim_key)
);

create table if not exists event_log (
    event_id          text primary key,
    event_type        text not null,
    tenant_id         text not null,
    aggregate_id      text not null,
    occurred_at       text not null,
    actor_id          text not null,
    aggregate_version integer not null,
    prev_hash         text not null,
    payload_json      text not null
);
create index if not exists ix_event_aggregate
    on event_log(tenant_id, aggregate_id, aggregate_version);

create table if not exists audit_record (
    tenant_id   text not null,
    record_id   text not null,
    case_id     text,
    at          text not null,
    actor_id    text not null,
    record_type text not null,
    detail_json text not null,
    primary key (tenant_id, record_id)
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        # check_same_thread=False 后由调用方保证事务边界；单服务使用足够。
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("pragma journal_mode=wal")
        self._conn.execute("pragma foreign_keys=on")
        self._conn.execute("pragma busy_timeout=10000")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        self._conn.close()

    def begin(self) -> sqlite3.Connection:
        """开启立即事务，获取写锁以保证领取等操作的串行化。"""
        self._conn.execute("begin immediate")
        return self._conn

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    # ---- 便捷查询 -------------------------------------------------------

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return list(self._conn.execute(sql, params))

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)


def canonical_json(payload: Any) -> str:
    """稳定的规范化 JSON，用于哈希计算。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
