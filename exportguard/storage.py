"""SQLite 持久化：事件流、幂等键、计费记录。

只用 Python 标准库。每条命令在单个事务里完成"校验→追加事件→写幂等/
计费"，因此领取重试不可能写出第二份交付或第二条计费。重启后聚合由
事件流重放重建，幂等与计费表作为唯一性约束的最后一道防线。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Iterable

from .events import Event

SCHEMA = """
create table if not exists events (
    event_id        text primary key,
    event_type      text not null,
    aggregate_id    text not null,
    tenant_id       text not null,
    seq             integer not null,
    occurred_at     text not null,
    actor_id        text not null,
    payload_json    text not null,
    idempotency_key text,
    unique (aggregate_id, seq),
    unique (tenant_id, idempotency_key)
);

create index if not exists events_tenant_idx
    on events (tenant_id, aggregate_id, seq);

-- 命令级幂等：同一 (租户, 键) 只登记一次，响应原样回放给重试方。
create table if not exists idempotency (
    idem_key      text not null,
    tenant_id     text not null,
    scope         text not null,
    case_id       text not null,
    fingerprint   text not null,
    response_json text not null,
    created_at    text not null,
    primary key (tenant_id, scope, idem_key)
);

-- 计费事实：同一清单版本下一个分片最多一条计费。
create table if not exists billing (
    billing_record_id text primary key,
    tenant_id         text not null,
    case_id           text not null,
    manifest_version  integer not null,
    chunk_index       integer not null,
    claim_key         text not null unique,
    amount_units      integer not null,
    created_at        text not null,
    unique (case_id, manifest_version, chunk_index)
);
"""


class EventStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # HTTP 服务在工作线程中复用同一连接；api 层已用锁串行化全部写事务，
        # 且事务以 with conn 显式界定，因此允许跨线程使用。
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("pragma foreign_keys = on")
        self._conn.execute("pragma journal_mode = wal")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.commit()
        self._conn.close()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    # --------------------------------------------------------------- events

    def load_events(self, case_id: str) -> list[Event]:
        rows = self._conn.execute(
            "select * from events where aggregate_id = ? order by seq", (case_id,)
        ).fetchall()
        return [Event.from_row(dict(row)) for row in rows]

    def list_case_ids(self, tenant_id: str | None = None) -> list[str]:
        if tenant_id is None:
            rows = self._conn.execute(
                "select distinct aggregate_id from events order by aggregate_id"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "select distinct aggregate_id from events where tenant_id = ? order by aggregate_id",
                (tenant_id,),
            ).fetchall()
        return [row[0] for row in rows]

    def next_seq(self, case_id: str) -> int:
        row = self._conn.execute(
            "select coalesce(max(seq), 0) + 1 from events where aggregate_id = ?",
            (case_id,),
        ).fetchone()
        return int(row[0])

    def case_exists(self, case_id: str) -> bool:
        row = self._conn.execute(
            "select 1 from events where aggregate_id = ? limit 1", (case_id,)
        ).fetchone()
        return row is not None

    def tenant_of(self, case_id: str) -> str | None:
        row = self._conn.execute(
            "select tenant_id from events where aggregate_id = ? order by seq limit 1",
            (case_id,),
        ).fetchone()
        return None if row is None else row[0]

    def append_event(
        self,
        event: Event,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        target = conn or self._conn
        target.execute(
            "insert into events(event_id, event_type, aggregate_id, tenant_id, seq, "
            "occurred_at, actor_id, payload_json, idempotency_key) "
            "values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.event_type,
                event.aggregate_id,
                event.tenant_id,
                event.seq,
                event.occurred_at,
                event.actor_id,
                json.dumps(event.payload, ensure_ascii=False, sort_keys=True),
                event.idempotency_key,
            ),
        )

    def append_many(self, events: Iterable[Event]) -> None:
        with self._conn:  # 自动提交/回滚
            cursor = self._conn.cursor()
            for event in events:
                self.append_event(event, cursor)

    # ---------------------------------------------------------- idempotency

    def idempotency_lookup(
        self, tenant_id: str, scope: str, key: str, conn: sqlite3.Connection
    ) -> sqlite3.Row | None:
        return conn.execute(
            "select * from idempotency where tenant_id = ? and scope = ? and idem_key = ?",
            (tenant_id, scope, key),
        ).fetchone()

    def idempotency_store(
        self,
        tenant_id: str,
        scope: str,
        key: str,
        case_id: str,
        fingerprint: str,
        response: dict[str, Any],
        now_iso: str,
        conn: sqlite3.Connection,
    ) -> None:
        conn.execute(
            "insert into idempotency(idem_key, tenant_id, scope, case_id, fingerprint, "
            "response_json, created_at) values (?, ?, ?, ?, ?, ?, ?)",
            (
                key,
                tenant_id,
                scope,
                case_id,
                fingerprint,
                json.dumps(response, ensure_ascii=False, sort_keys=True),
                now_iso,
            ),
        )

    # -------------------------------------------------------------- billing

    def billing_for_case(self, case_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "select * from billing where case_id = ? order by manifest_version, chunk_index",
            (case_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def insert_billing(
        self,
        tenant_id: str,
        case_id: str,
        manifest_version: int,
        chunk_index: int,
        claim_key: str,
        amount_units: int,
        now_iso: str,
        conn: sqlite3.Connection,
    ) -> str:
        record_id = "bill-" + uuid.uuid4().hex
        conn.execute(
            "insert into billing(billing_record_id, tenant_id, case_id, manifest_version, "
            "chunk_index, claim_key, amount_units, created_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record_id,
                tenant_id,
                case_id,
                manifest_version,
                chunk_index,
                claim_key,
                amount_units,
                now_iso,
            ),
        )
        return record_id
