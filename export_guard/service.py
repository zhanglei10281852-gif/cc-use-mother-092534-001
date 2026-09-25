"""受控导出领域服务。

一个 ``ControlledExportService`` 实例对应一个 SQLite 数据库文件；除注入的
时钟与策略外不持有可变运行时状态，因此进程重启后所有未完成导出都停留在
正确阶段（``recover`` 仅把越过有效期的事实补齐为 expired）。

关键不变量：

1. 清单一旦冻结即不可变；文件漂移只会产生新版本，旧版本标记 superseded。
2. 审批绑定 (manifest_version, manifest_hash, recipient, valid_until)。
3. 领取以 claim_key 幂等：重试返回同一张回执，不重复计费、不产生第二条事实。
4. 每个 chunk_id 全生命周期只能被领取一次。
5. 撤销、过期或批准版本落后，未领取分片一律拒绝。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any, Sequence

from .errors import (
    ApprovalClosed,
    ApprovalError,
    ChunkAlreadyClaimed,
    ClaimKeyConflict,
    DeliveryDenied,
    InvalidStateError,
    ManifestStale,
    NotFoundError,
    ScopeError,
)
from .events import (
    APPROVAL_RECORDED,
    CHUNK_CLAIMED,
    EXPORT_COMPLETED,
    EXPORT_EXPIRED,
    EXPORT_REQUESTED,
    EXPORT_REVOKED,
    MANIFEST_CLASSIFIED,
    MANIFEST_INVALIDATED,
    Event,
)
from .policy import ApprovalPolicy, Sensitivity
from .store import Store, canonical_json, digest
from .time import Clock, SystemClock, normalize, parse_iso

# 导出状态机
DRAFT = "draft"
CLASSIFIED = "classified"
AWAITING_APPROVAL = "awaiting_approval"
APPROVED = "approved"
DELIVERING = "delivering"
COMPLETED = "completed"
REVOKED = "revoked"
EXPIRED = "expired"

TERMINAL_STATES = frozenset({COMPLETED, REVOKED, EXPIRED})


class _GateFailure(Exception):
    """交付/审批闸门失败，但失效事实必须先落库再对外拒绝。"""

    def __init__(self, public: Exception) -> None:
        super().__init__(str(public))
        self.public = public


class ControlledExportService:
    def __init__(
        self,
        store: Store | str = ":memory:",
        policy: ApprovalPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.store = store if isinstance(store, Store) else Store(store)
        self.policy = policy or ApprovalPolicy()
        self.clock = clock or SystemClock()

    def close(self) -> None:
        self.store.close()

    # ==================================================================
    # 文件目录（平台侧资产台账）
    # ==================================================================

    def upsert_file(
        self,
        tenant_id: str,
        file_id: str,
        file_version: str,
        content_hash: str,
        size_bytes: int,
        sensitivity: str,
        source_location: str,
        *,
        actor_id: str,
    ) -> None:
        """登记或更新一个文件的当前版本与敏感等级。"""
        level = Sensitivity.parse(sensitivity)
        now = self._now_iso()
        con = self.store.begin()
        try:
            con.execute(
                """
                insert into file_catalog(tenant_id, file_id, file_version, content_hash,
                                         size_bytes, sensitivity, source_location, updated_at)
                values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(tenant_id, file_id) do update set
                    file_version=excluded.file_version,
                    content_hash=excluded.content_hash,
                    size_bytes=excluded.size_bytes,
                    sensitivity=excluded.sensitivity,
                    source_location=excluded.source_location,
                    updated_at=excluded.updated_at
                """,
                (tenant_id, file_id, file_version, content_hash, size_bytes,
                 level.name.lower(), source_location, now),
            )
            self._audit(con, tenant_id, case_id=None, actor_id=actor_id,
                        record_type="file.upserted",
                        detail={"file_id": file_id, "file_version": file_version,
                                "content_hash": content_hash, "sensitivity": level.name.lower()})
            self.store.commit()
        except BaseException:
            self.store.rollback()
            raise

    # ==================================================================
    # 申请
    # ==================================================================

    def create_request(
        self,
        tenant_id: str,
        case_id: str,
        applicant_id: str,
        business_purpose: str,
        recipient_id: str,
        *,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        """申请人提交业务目的、范围接收方。目的与接收方不可为空。"""
        if not business_purpose or not business_purpose.strip():
            raise ScopeError("业务目的必须明确填写")
        if not recipient_id or not recipient_id.strip():
            raise ScopeError("必须指定数据接收方")
        if not case_id or not tenant_id:
            raise ScopeError("租户与业务单号不可为空")
        now = self._now_iso()
        con = self.store.begin()
        try:
            exists = con.execute(
                "select 1 from export_request where tenant_id=? and case_id=?",
                (tenant_id, case_id),
            ).fetchone()
            if exists:
                raise ScopeError(f"导出单已存在：{case_id}")
            con.execute(
                """
                insert into export_request(tenant_id, case_id, applicant_id,
                                           business_purpose, recipient_id, state,
                                           aggregate_version, created_at, updated_at)
                values (?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (tenant_id, case_id, applicant_id, business_purpose.strip(),
                 recipient_id, DRAFT, now, now),
            )
            self._append_event(con, EXPORT_REQUESTED, tenant_id, case_id,
                               actor_id or applicant_id,
                               {"applicant_id": applicant_id,
                                "business_purpose": business_purpose.strip(),
                                "recipient_id": recipient_id})
            self._audit(con, tenant_id, case_id, actor_id or applicant_id,
                        "export.requested",
                        {"business_purpose": business_purpose.strip(),
                         "recipient_id": recipient_id})
            self.store.commit()
        except BaseException:
            self.store.rollback()
            raise
        return self.get_case(tenant_id, case_id)

    # ==================================================================
    # 清单冻结与分级
    # ==================================================================

    def freeze_manifest(
        self,
        tenant_id: str,
        case_id: str,
        entries: Sequence[dict[str, Any]],
        *,
        actor_id: str,
    ) -> dict[str, Any]:
        """冻结清单快照。

        entries 每项必须包含 file_id，并可显式给出 inclusion_reason；
        文件版本、哈希、大小、敏感等级、来源以冻结瞬间的目录为准快照，
        这保证“每个文件为何纳入”可回答且不可被后续目录变更篡改。
        冻结新版本会自动作废旧版本。
        """
        if not entries:
            raise ScopeError("清单不允许为空")
        con = self.store.begin()
        try:
            case = self._require_case(con, tenant_id, case_id)
            if case["state"] not in (DRAFT, CLASSIFIED, AWAITING_APPROVAL):
                raise InvalidStateError(
                    f"状态 {case['state']} 下不能（重新）冻结清单；"
                    "交付中发现文件变化应在拒绝交付并作废旧版本后重新评估"
                )
            next_version = self._next_manifest_version(con, tenant_id, case_id)

            snapshot: list[dict[str, Any]] = []
            for index, raw in enumerate(entries):
                file_id = raw.get("file_id")
                if not file_id:
                    raise ScopeError(f"第 {index} 项缺少 file_id")
                row = con.execute(
                    "select * from file_catalog where tenant_id=? and file_id=?",
                    (tenant_id, file_id),
                ).fetchone()
                if row is None:
                    raise ScopeError(f"文件不在租户目录中：{file_id}")
                reason = (raw.get("inclusion_reason") or "").strip()
                if not reason:
                    raise ScopeError(f"文件 {file_id} 必须说明纳入理由")
                snapshot.append({
                    "entry_index": index,
                    "file_id": file_id,
                    "file_version": row["file_version"],
                    "content_hash": row["content_hash"],
                    "size_bytes": row["size_bytes"],
                    "sensitivity": row["sensitivity"],
                    "source_location": row["source_location"],
                    "inclusion_reason": reason,
                })

            max_level = max(Sensitivity.parse(e["sensitivity"]) for e in snapshot)
            required_roles = self.policy.roles_for(max_level)
            manifest_hash = self._compute_manifest_hash(
                tenant_id, case_id, next_version, case["recipient_id"], snapshot
            )
            now = self._now()

            # 作废旧版本（等待期间重新评估）。
            con.execute(
                "update manifest_version set status='superseded', superseded_at=? "
                "where tenant_id=? and case_id=? and status in ('pending','active')",
                (self._iso(now), tenant_id, case_id),
            )

            if required_roles:
                status, state, valid_until = "pending", AWAITING_APPROVAL, None
            else:
                status, state = "active", APPROVED
                valid_until = now + timedelta(hours=self.policy.ttl_hours_for(max_level))

            con.execute(
                """
                insert into manifest_version(tenant_id, case_id, manifest_version,
                    manifest_hash, max_sensitivity, required_roles_json, status,
                    frozen_at, superseded_at, valid_until)
                values (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (tenant_id, case_id, next_version, manifest_hash, max_level.name.lower(),
                 json.dumps(list(required_roles)), status, self._iso(now),
                 self._iso(valid_until) if valid_until else None),
            )
            for e in snapshot:
                con.execute(
                    """
                    insert into manifest_entry(tenant_id, case_id, manifest_version,
                        entry_index, file_id, file_version, content_hash, size_bytes,
                        sensitivity, source_location, inclusion_reason)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (tenant_id, case_id, next_version, e["entry_index"], e["file_id"],
                     e["file_version"], e["content_hash"], e["size_bytes"],
                     e["sensitivity"], e["source_location"], e["inclusion_reason"]),
                )

            self._set_state(con, tenant_id, case_id, state)
            self._append_event(con, MANIFEST_CLASSIFIED, tenant_id, case_id, actor_id, {
                "manifest_version": next_version,
                "manifest_hash": manifest_hash,
                "max_sensitivity": max_level.name.lower(),
                "required_roles": list(required_roles),
                "entry_count": len(snapshot),
                "status": status,
            })
            self._audit(con, tenant_id, case_id, actor_id, "manifest.classified", {
                "manifest_version": next_version,
                "manifest_hash": manifest_hash,
                "max_sensitivity": max_level.name.lower(),
                "required_roles": list(required_roles),
                "entries": [{"file_id": e["file_id"], "reason": e["inclusion_reason"]}
                            for e in snapshot],
            })
            self.store.commit()
        except BaseException:
            self.store.rollback()
            raise
        return self.get_case(tenant_id, case_id)

    # ==================================================================
    # 会签批准
    # ==================================================================

    def record_approval(
        self,
        tenant_id: str,
        case_id: str,
        role: str,
        approver_id: str,
        valid_until: datetime,
        *,
        expected_manifest_version: int | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        """记录一个审批角色的批准。

        批准只对当前待批清单版本的哈希、接收方与给定有效期生效；
        若清单在等待期间已被新版本替换，则抛 :class:`ApprovalClosed`。
        """
        valid_until = normalize(valid_until)
        con = self.store.begin()
        try:
            case = self._require_case(con, tenant_id, case_id)
            manifest = self._current_manifest(con, tenant_id, case_id)
            if manifest is None or manifest["status"] != "pending":
                raise InvalidStateError("当前没有等待会签的清单版本")
            version = int(manifest["manifest_version"])
            if expected_manifest_version is not None and expected_manifest_version != version:
                raise ApprovalClosed(
                    f"批准针对版本 {expected_manifest_version}，当前待批版本为 {version}"
                )
            if case["state"] != AWAITING_APPROVAL:
                raise InvalidStateError(f"当前状态 {case['state']} 不接受审批")

            required = tuple(json.loads(manifest["required_roles_json"]))
            if role not in required:
                raise ApprovalError(f"该清单等级不需要角色 {role} 的批准")
            ttl_limit = self._now() + timedelta(
                hours=self.policy.ttl_hours_for(Sensitivity.parse(manifest["max_sensitivity"]))
            )
            if valid_until <= self._now():
                raise ApprovalError("有效期必须晚于当前时间")
            if valid_until > ttl_limit:
                raise ApprovalError(
                    f"批准有效期超出策略上限（不得晚于 {ttl_limit.isoformat()}）"
                )

            # 等待期间文件一旦变化，旧版本不得继续被批准。
            drift = self._detect_drift(con, tenant_id, case_id, version)
            if drift:
                self._invalidate(con, case, manifest, actor_id or approver_id,
                                 reason="approval_time_drift", changed=drift)
                raise _GateFailure(ManifestStale(
                    f"文件已变化：{', '.join(drift)}，请重新评估清单"))

            duplicated = con.execute(
                "select 1 from approval where tenant_id=? and case_id=? "
                "and manifest_version=? and role=?",
                (tenant_id, case_id, version, role),
            ).fetchone()
            if duplicated:
                raise ApprovalError(f"角色 {role} 已对该版本批准，不可重复批准")

            con.execute(
                """
                insert into approval(tenant_id, case_id, manifest_version, role,
                    approver_id, bound_manifest_hash, bound_recipient_id,
                    valid_from, valid_until, recorded_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant_id, case_id, version, role, approver_id,
                 manifest["manifest_hash"], case["recipient_id"],
                 self._now_iso(), self._iso(valid_until), self._now_iso()),
            )
            self._append_event(con, APPROVAL_RECORDED, tenant_id, case_id,
                               actor_id or approver_id, {
                                   "manifest_version": version,
                                   "role": role,
                                   "approver_id": approver_id,
                                   "bound_manifest_hash": manifest["manifest_hash"],
                                   "bound_recipient_id": case["recipient_id"],
                                   "valid_until": self._iso(valid_until),
                               })
            self._audit(con, tenant_id, case_id, actor_id or approver_id,
                        "approval.recorded", {
                            "manifest_version": version, "role": role,
                            "approver_id": approver_id,
                            "bound_manifest_hash": manifest["manifest_hash"],
                            "valid_until": self._iso(valid_until),
                        })

            # 会签是否集齐？
            recorded = {r["role"] for r in con.execute(
                "select role from approval where tenant_id=? and case_id=? and manifest_version=?",
                (tenant_id, case_id, version),
            ).fetchall()}
            if set(required) <= recorded:
                deadline = min(
                    parse_iso(row["valid_until"]) for row in con.execute(
                        "select valid_until from approval where tenant_id=? and case_id=? "
                        "and manifest_version=?",
                        (tenant_id, case_id, version),
                    ).fetchall()
                )
                con.execute(
                    "update manifest_version set status='active', valid_until=? "
                    "where tenant_id=? and case_id=? and manifest_version=?",
                    (self._iso(deadline), tenant_id, case_id, version),
                )
                self._set_state(con, tenant_id, case_id, APPROVED)
                self._audit(con, tenant_id, case_id, actor_id or approver_id,
                            "approval.quorum_reached",
                            {"manifest_version": version, "valid_until": self._iso(deadline)})
            self.store.commit()
        except _GateFailure as gate:
            # 失效事实先落库，再向调用方返回拒绝。
            self.store.commit()
            raise gate.public
        except BaseException:
            self.store.rollback()
            raise
        return self.get_case(tenant_id, case_id)

    # ==================================================================
    # 分片规划与续传
    # ==================================================================

    @staticmethod
    def plan_chunks(entry_count: int, max_bytes_per_chunk: int,
                    entry_sizes: Sequence[int]) -> list[list[int]]:
        """按字节上限把条目顺序切分为分片，返回每组的 entry_index。"""
        if entry_count != len(entry_sizes):
            raise ScopeError("条目数量与大小列表不一致")
        chunks: list[list[int]] = []
        current: list[int] = []
        used = 0
        for index, size in enumerate(entry_sizes):
            if size < 0:
                raise ScopeError("分片大小不能为负")
            if current and used + size > max_bytes_per_chunk:
                chunks.append(current)
                current, used = [], 0
            current.append(index)
            used += size
        if current:
            chunks.append(current)
        return chunks

    def prepare_chunks(self, tenant_id: str, case_id: str,
                       chunk_plan: Sequence[Sequence[int]], *,
                       actor_id: str) -> list[dict[str, Any]]:
        """依据分片计划生成可领取分片；计划必须恰好覆盖清单全部条目一次。"""
        con = self.store.begin()
        try:
            case = self._require_case(con, tenant_id, case_id)
            if case["state"] not in (APPROVED, DELIVERING):
                raise InvalidStateError(f"状态 {case['state']} 下不能规划分片")
            manifest = self._active_manifest(con, tenant_id, case_id)
            version = int(manifest["manifest_version"])
            entries = self._entries(con, tenant_id, case_id, version)
            total = len(entries)
            # 续传场景下允许重复下发同一份分片计划；已经产生领取事实的分片
            # 必须保持原分组不变，否则会破坏计费与交付对账。
            existing_rows = con.execute(
                "select * from delivery_chunk where tenant_id=? and case_id=? "
                "and manifest_version=? order by seq",
                (tenant_id, case_id, version),
            ).fetchall()
            existing_groups = [json.loads(r["entry_indexes_json"]) for r in existing_rows]
            new_groups = [[int(i) for i in group] for group in chunk_plan]
            claimed_rows = con.execute(
                "select chunk_id from chunk_claim where tenant_id=? and case_id=? "
                "and manifest_version=?",
                (tenant_id, case_id, version),
            ).fetchall()
            if claimed_rows and existing_groups != new_groups:
                raise ScopeError("已有分片被领取，分片计划只能按原计划重复下发，不能重新切分")

            seen: set[int] = set()
            plan_rows: list[tuple[int, list[int], int, str]] = []
            for seq, indexes in enumerate(new_groups):
                if not indexes:
                    raise ScopeError(f"分片 {seq} 为空")
                for idx in indexes:
                    if idx < 0 or idx >= total:
                        raise ScopeError(f"分片 {seq} 引用了不存在的条目 {idx}")
                    if idx in seen:
                        raise ScopeError(f"条目 {idx} 被重复纳入分片")
                    seen.add(idx)
                size_total = sum(entries[i]["size_bytes"] for i in indexes)
                chunk_id = f"chunk-{version}-{seq}"
                token = digest(canonical_json({
                    "manifest_hash": manifest["manifest_hash"],
                    "chunk_id": chunk_id,
                    "entry_indexes": indexes,
                }))
                plan_rows.append((seq, indexes, size_total, chunk_id, token))
            if seen != set(range(total)):
                missing = sorted(set(range(total)) - seen)
                raise ScopeError(f"分片计划未完整覆盖清单，缺少条目 {missing}")

            result: list[dict[str, Any]] = []
            for seq, indexes, size_total, chunk_id, token in plan_rows:
                con.execute(
                    """
                    insert into delivery_chunk(tenant_id, case_id, chunk_id,
                        manifest_version, seq, entry_indexes_json, size_bytes, content_token)
                    values (?, ?, ?, ?, ?, ?, ?, ?)
                    on conflict(tenant_id, case_id, chunk_id) do update set
                        manifest_version=excluded.manifest_version,
                        seq=excluded.seq,
                        entry_indexes_json=excluded.entry_indexes_json,
                        size_bytes=excluded.size_bytes,
                        content_token=excluded.content_token
                    """,
                    (tenant_id, case_id, chunk_id, version, seq,
                     json.dumps(indexes), size_total, token),
                )
                result.append({"chunk_id": chunk_id, "seq": seq,
                               "entry_indexes": indexes, "size_bytes": size_total,
                               "content_token": token})
            self._audit(con, tenant_id, case_id, actor_id, "chunks.prepared",
                        {"manifest_version": version, "chunk_count": len(result)})
            self.store.commit()
        except BaseException:
            self.store.rollback()
            raise
        return result

    def claim_chunk(
        self,
        tenant_id: str,
        case_id: str,
        chunk_id: str,
        recipient_id: str,
        claim_key: str,
        *,
        actor_id: str,
    ) -> dict[str, Any]:
        """领取一个分片。

        claim_key 是调用方生成的幂等键：同键重试返回首次回执，
        既不重复计费也不产生第二条 chunk.claimed 事实；换键重复领取同一
        分片会被拒绝。撤销、过期、版本落后或文件漂移一律拒绝交付。
        """
        if not claim_key:
            raise ScopeError("claim_key 不可为空")
        con = self.store.begin()
        try:
            case = self._require_case(con, tenant_id, case_id)

            # 1) 幂等重放：同一领取请求重试。
            prior = con.execute(
                "select * from chunk_claim where tenant_id=? and case_id=? and claim_key=?",
                (tenant_id, case_id, claim_key),
            ).fetchone()
            if prior is not None:
                if prior["chunk_id"] != chunk_id or prior["recipient_id"] != recipient_id:
                    raise ClaimKeyConflict("claim_key 已绑定其他分片或接收方")
                receipt = self._receipt(con, tenant_id, case_id, prior, replayed=True)
                self._audit(con, tenant_id, case_id, actor_id, "chunk.claim_replayed",
                            {"claim_key": claim_key, "chunk_id": chunk_id})
                self.store.commit()
                return receipt

            # 2) 交付闸门：状态、有效期、版本绑定、文件漂移。
            self._assert_deliverable(con, case, actor_id)
            manifest = self._active_manifest(con, tenant_id, case_id)
            version = int(manifest["manifest_version"])

            if recipient_id != case["recipient_id"]:
                raise DeliveryDenied("接收方与批准绑定的接收方不一致")

            chunk = con.execute(
                "select * from delivery_chunk where tenant_id=? and case_id=? and chunk_id=?",
                (tenant_id, case_id, chunk_id),
            ).fetchone()
            if chunk is None:
                raise NotFoundError(f"分片不存在：{chunk_id}")
            if int(chunk["manifest_version"]) != version:
                # 规划于旧版本上的分片：随旧批准一并失效。
                raise DeliveryDenied("分片属于已失效的清单版本")

            other_claim = con.execute(
                "select claim_key from chunk_claim where tenant_id=? and case_id=? and chunk_id=?",
                (tenant_id, case_id, chunk_id),
            ).fetchone()
            if other_claim is not None:
                raise ChunkAlreadyClaimed(
                    f"分片已被领取请求 {other_claim['claim_key']} 领取"
                )

            now = self._now_iso()
            try:
                con.execute(
                    """
                    insert into chunk_claim(tenant_id, case_id, claim_key, chunk_id,
                        recipient_id, manifest_version, manifest_hash_at_claim, state, claimed_at)
                    values (?, ?, ?, ?, ?, ?, ?, 'delivered', ?)
                    """,
                    (tenant_id, case_id, claim_key, chunk_id, recipient_id, version,
                     manifest["manifest_hash"], now),
                )
            except sqlite3.IntegrityError as exc:
                # 并发窗口：两个不同 claim_key 同时领取同一分片，只允许一个成功。
                raise ChunkAlreadyClaimed(
                    f"分片 {chunk_id} 已被并发领取请求领取"
                ) from exc
            # 首次成功领取恰好一次计费（主键即 claim_key，天然防重复）。
            con.execute(
                "insert into billing_record(tenant_id, case_id, claim_key, chunk_id, bytes, charged_at) "
                "values (?, ?, ?, ?, ?, ?)",
                (tenant_id, case_id, claim_key, chunk_id, chunk["size_bytes"], now),
            )
            self._append_event(con, CHUNK_CLAIMED, tenant_id, case_id, actor_id, {
                "claim_key": claim_key,
                "chunk_id": chunk_id,
                "recipient_id": recipient_id,
                "manifest_version": version,
                "manifest_hash": manifest["manifest_hash"],
                "size_bytes": chunk["size_bytes"],
            })
            self._audit(con, tenant_id, case_id, actor_id, "chunk.claimed", {
                "claim_key": claim_key, "chunk_id": chunk_id,
                "manifest_version": version, "size_bytes": chunk["size_bytes"],
            })

            if case["state"] == APPROVED:
                self._set_state(con, tenant_id, case_id, DELIVERING)

            if self._all_claimed(con, tenant_id, case_id, version):
                self._set_state(con, tenant_id, case_id, COMPLETED)
                self._append_event(con, EXPORT_COMPLETED, tenant_id, case_id, actor_id, {
                    "manifest_version": version,
                    "manifest_hash": manifest["manifest_hash"],
                })
                self._audit(con, tenant_id, case_id, actor_id, "export.completed",
                            {"manifest_version": version})

            self.store.commit()
        except _GateFailure as gate:
            # 过期/失效事实先落库，再向调用方返回拒绝。
            self.store.commit()
            raise gate.public
        except BaseException:
            self.store.rollback()
            raise
        row = self.store.fetchone(
            "select * from chunk_claim where tenant_id=? and case_id=? and claim_key=?",
            (tenant_id, case_id, claim_key),
        )
        return self._receipt(self.store.connection, tenant_id, case_id, row, replayed=False)

    # ==================================================================
    # 撤销与过期
    # ==================================================================

    def revoke(self, tenant_id: str, case_id: str, *,
               actor_id: str, reason: str = "") -> dict[str, Any]:
        """安全值班员/管理员撤销；撤销后未领取分片全部失效。"""
        con = self.store.begin()
        try:
            case = self._require_case(con, tenant_id, case_id)
            if case["state"] in TERMINAL_STATES:
                if case["state"] == REVOKED:
                    self.store.commit()
                    return self.get_case(tenant_id, case_id)
                raise InvalidStateError(f"导出单已终态（{case['state']}），不能撤销")
            self._set_state(con, tenant_id, case_id, REVOKED)
            self._append_event(con, EXPORT_REVOKED, tenant_id, case_id, actor_id,
                               {"reason": reason})
            self._audit(con, tenant_id, case_id, actor_id, "export.revoked",
                        {"reason": reason})
            self.store.commit()
        except BaseException:
            self.store.rollback()
            raise
        return self.get_case(tenant_id, case_id)

    def sweep_expired(self, *, actor_id: str = "system") -> list[str]:
        """把所有已越过有效期但仍在交付中的导出单标记为过期。"""
        now = self._now()
        con = self.store.begin()
        expired: list[str] = []
        try:
            rows = con.execute(
                """
                select * from export_request
                where state in (?, ?, ?)
                """,
                (AWAITING_APPROVAL, APPROVED, DELIVERING),
            ).fetchall()
            for case in rows:
                manifest = self._current_manifest(con, case["tenant_id"], case["case_id"])
                if manifest is None or manifest["valid_until"] is None:
                    continue
                if parse_iso(manifest["valid_until"]) <= now:
                    self._set_state(con, case["tenant_id"], case["case_id"], EXPIRED)
                    self._append_event(con, EXPORT_EXPIRED, case["tenant_id"],
                                       case["case_id"], actor_id,
                                       {"manifest_version": manifest["manifest_version"],
                                        "valid_until": manifest["valid_until"]})
                    self._audit(con, case["tenant_id"], case["case_id"], actor_id,
                                "export.expired",
                                {"valid_until": manifest["valid_until"]})
                    expired.append(case["case_id"])
            self.store.commit()
        except BaseException:
            self.store.rollback()
            raise
        return expired

    def recover(self) -> dict[str, Any]:
        """重启恢复：状态本身持久化，这里只补齐越过有效期的过期事实。"""
        expired = self.sweep_expired(actor_id="system.recovery")
        return {"expired": expired}

    # ==================================================================
    # 管理员查询与审计对账
    # ==================================================================

    def get_case(self, tenant_id: str, case_id: str) -> dict[str, Any]:
        con = self.store.connection
        case = self._require_case(con, tenant_id, case_id)
        manifest = self._current_manifest(con, tenant_id, case_id)
        result = {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "applicant_id": case["applicant_id"],
            "business_purpose": case["business_purpose"],
            "recipient_id": case["recipient_id"],
            "state": case["state"],
            "aggregate_version": case["aggregate_version"],
            "created_at": case["created_at"],
            "updated_at": case["updated_at"],
            "current_manifest": None,
        }
        if manifest is not None:
            result["current_manifest"] = {
                "manifest_version": manifest["manifest_version"],
                "manifest_hash": manifest["manifest_hash"],
                "max_sensitivity": manifest["max_sensitivity"],
                "required_roles": json.loads(manifest["required_roles_json"]),
                "status": manifest["status"],
                "frozen_at": manifest["frozen_at"],
                "valid_until": manifest["valid_until"],
            }
        return result

    def list_entries(self, tenant_id: str, case_id: str,
                     manifest_version: int | None = None) -> list[dict[str, Any]]:
        """每个文件为何纳入：含纳入理由、冻结时的版本/哈希/等级。"""
        con = self.store.connection
        self._require_case(con, tenant_id, case_id)
        if manifest_version is None:
            manifest = self._current_manifest(con, tenant_id, case_id)
            if manifest is None:
                return []
            manifest_version = int(manifest["manifest_version"])
        rows = con.execute(
            "select * from manifest_entry where tenant_id=? and case_id=? and manifest_version=? "
            "order by entry_index",
            (tenant_id, case_id, manifest_version),
        ).fetchall()
        current = {
            r["file_id"]: r for r in con.execute(
                "select file_id, file_version, content_hash from file_catalog where tenant_id=?",
                (tenant_id,),
            ).fetchall()
        }
        result = []
        for row in rows:
            cur = current.get(row["file_id"])
            drifted = cur is not None and (
                cur["content_hash"] != row["content_hash"]
                or cur["file_version"] != row["file_version"]
            )
            result.append({
                "entry_index": row["entry_index"],
                "file_id": row["file_id"],
                "file_version": row["file_version"],
                "content_hash": row["content_hash"],
                "size_bytes": row["size_bytes"],
                "sensitivity": row["sensitivity"],
                "source_location": row["source_location"],
                "inclusion_reason": row["inclusion_reason"],
                "current_version": cur["file_version"] if cur else None,
                "drifted_since_freeze": drifted,
            })
        return result

    def list_approvals(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        rows = self.store.fetchall(
            "select * from approval where tenant_id=? and case_id=? "
            "order by manifest_version, role",
            (tenant_id, case_id),
        )
        return [{
            "manifest_version": r["manifest_version"],
            "role": r["role"],
            "approver_id": r["approver_id"],
            "bound_manifest_hash": r["bound_manifest_hash"],
            "bound_recipient_id": r["bound_recipient_id"],
            "valid_from": r["valid_from"],
            "valid_until": r["valid_until"],
            "recorded_at": r["recorded_at"],
        } for r in rows]

    def list_claims(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        """哪些分片已经领取、被谁领取，以及计费情况。"""
        rows = self.store.fetchall(
            """
            select c.*, b.bytes as billed_bytes, b.charged_at
            from chunk_claim c
            left join billing_record b
              on b.tenant_id=c.tenant_id and b.case_id=c.case_id and b.claim_key=c.claim_key
            where c.tenant_id=? and c.case_id=?
            order by c.claimed_at
            """,
            (tenant_id, case_id),
        )
        return [{
            "claim_key": r["claim_key"],
            "chunk_id": r["chunk_id"],
            "recipient_id": r["recipient_id"],
            "manifest_version": r["manifest_version"],
            "manifest_hash_at_claim": r["manifest_hash_at_claim"],
            "state": r["state"],
            "claimed_at": r["claimed_at"],
            "billed_bytes": r["billed_bytes"],
            "charged_at": r["charged_at"],
        } for r in rows]

    def list_chunks(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        rows = self.store.fetchall(
            "select * from delivery_chunk where tenant_id=? and case_id=? order by seq",
            (tenant_id, case_id),
        )
        claimed = {r["chunk_id"] for r in self.store.fetchall(
            "select chunk_id from chunk_claim where tenant_id=? and case_id=?",
            (tenant_id, case_id),
        )}
        return [{
            "chunk_id": r["chunk_id"],
            "seq": r["seq"],
            "manifest_version": r["manifest_version"],
            "entry_indexes": json.loads(r["entry_indexes_json"]),
            "size_bytes": r["size_bytes"],
            "content_token": r["content_token"],
            "claimed": r["chunk_id"] in claimed,
        } for r in rows]

    def event_history(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        rows = self.store.fetchall(
            "select * from event_log where tenant_id=? and aggregate_id=? "
            "order by aggregate_version",
            (tenant_id, case_id),
        )
        return [{
            "event_id": r["event_id"],
            "event_type": r["event_type"],
            "occurred_at": r["occurred_at"],
            "actor_id": r["actor_id"],
            "aggregate_version": r["aggregate_version"],
            "prev_hash": r["prev_hash"],
            "payload": json.loads(r["payload_json"]),
        } for r in rows]

    def audit_trail(self, tenant_id: str, case_id: str | None = None) -> list[dict[str, Any]]:
        if case_id is None:
            rows = self.store.fetchall(
                "select * from audit_record where tenant_id=? order by at, record_id",
                (tenant_id,),
            )
        else:
            rows = self.store.fetchall(
                "select * from audit_record where tenant_id=? and case_id=? order by at, record_id",
                (tenant_id, case_id),
            )
        return [{
            "record_id": r["record_id"],
            "case_id": r["case_id"],
            "at": r["at"],
            "actor_id": r["actor_id"],
            "record_type": r["record_type"],
            "detail": json.loads(r["detail_json"]),
        } for r in rows]

    def replay_case(self, tenant_id: str, case_id: str) -> dict[str, Any]:
        """只凭事件流重放聚合状态，用于证明恢复不依赖易失内存。"""
        state: dict[str, Any] = {"state": None, "manifest_version": None,
                                 "manifest_hash": None, "claimed_chunks": []}
        required_by_version: dict[int, set[str]] = {}
        approvals_by_version: dict[int, set[str]] = {}
        for event in self.event_history(tenant_id, case_id):
            kind = event["event_type"]
            payload = event["payload"]
            if kind == EXPORT_REQUESTED:
                state["state"] = DRAFT
                state["recipient_id"] = payload["recipient_id"]
            elif kind == MANIFEST_CLASSIFIED:
                version = payload["manifest_version"]
                state["manifest_version"] = version
                state["manifest_hash"] = payload["manifest_hash"]
                required = set(payload["required_roles"])
                required_by_version[version] = required
                approvals_by_version[version] = set()
                state["state"] = (APPROVED if payload["status"] == "active"
                                  else AWAITING_APPROVAL)
            elif kind == MANIFEST_INVALIDATED:
                state["state"] = CLASSIFIED
            elif kind == APPROVAL_RECORDED:
                version = payload["manifest_version"]
                approvals_by_version.setdefault(version, set()).add(payload["role"])
                if required_by_version.get(version, set()) <= approvals_by_version[version]:
                    state["state"] = APPROVED
            elif kind == CHUNK_CLAIMED:
                state["state"] = DELIVERING
                state["claimed_chunks"].append(payload["chunk_id"])
            elif kind == EXPORT_COMPLETED:
                state["state"] = COMPLETED
            elif kind == EXPORT_REVOKED:
                state["state"] = REVOKED
            elif kind == EXPORT_EXPIRED:
                state["state"] = EXPIRED
        return state

    def verify_consistency(self, tenant_id: str, case_id: str) -> dict[str, Any]:
        """管理员对账：清单哈希、事件哈希链、领取与计费是否互相一致。

        返回结构：

        - ``manifest_hash_ok``：重算哈希与冻结哈希一致（清单不可变）。
        - ``event_chain_ok``：事件 prev_hash 链完整，无篡改或缺环。
        - ``claims_match_manifest``：领取绑定的哈希等于最终清单哈希。
        - ``billing_ok``：每张领取回执恰好一条等额计费，无重复无遗漏。
        - ``delivery_complete``：completed 状态下分片全部领取，反之亦然。
        """
        con = self.store.connection
        case = self._require_case(con, tenant_id, case_id)
        problems: list[str] = []

        manifest = self._current_manifest(con, tenant_id, case_id)
        manifest_hash_ok = True
        if manifest is not None:
            version = int(manifest["manifest_version"])
            entries = self._entries(con, tenant_id, case_id, version)
            recomputed = self._compute_manifest_hash(
                tenant_id, case_id, version, case["recipient_id"],
                [dict(e) for e in entries],
            )
            manifest_hash_ok = recomputed == manifest["manifest_hash"]
            if not manifest_hash_ok:
                problems.append("清单条目重算哈希与冻结哈希不一致")

        # 事件哈希链
        event_chain_ok = True
        rows = con.execute(
            "select * from event_log where tenant_id=? and aggregate_id=? "
            "order by aggregate_version",
            (tenant_id, case_id),
        ).fetchall()
        prev = "GENESIS"
        versions = []
        for row in rows:
            versions.append(row["aggregate_version"])
            if row["prev_hash"] != prev:
                event_chain_ok = False
                problems.append(f"事件 {row['event_id']} 的前向哈希断链")
            prev = self._event_hash(row, prev)
        if versions != list(range(1, len(versions) + 1)):
            event_chain_ok = False
            problems.append("事件聚合版本不连续")

        # 领取 vs 清单哈希
        claims = con.execute(
            "select * from chunk_claim where tenant_id=? and case_id=?",
            (tenant_id, case_id),
        ).fetchall()
        claims_match = True
        if manifest is not None:
            for claim in claims:
                if claim["manifest_version"] == int(manifest["manifest_version"]):
                    if claim["manifest_hash_at_claim"] != manifest["manifest_hash"]:
                        claims_match = False
                        problems.append(f"领取 {claim['claim_key']} 绑定哈希与最终清单不符")
                # 旧版本上的领取只可能出现在重评估之前，属于合法历史。

        # 计费：一条领取恰好一条计费且字节相等。
        billing_ok = True
        if len(claims) != con.execute(
            "select count(*) from billing_record where tenant_id=? and case_id=?",
            (tenant_id, case_id),
        ).fetchone()[0]:
            billing_ok = False
            problems.append("领取记录数与计费记录数不一致")
        for claim in claims:
            bill = con.execute(
                "select * from billing_record where tenant_id=? and case_id=? and claim_key=?",
                (tenant_id, case_id, claim["claim_key"]),
            ).fetchone()
            chunk = con.execute(
                "select size_bytes from delivery_chunk where tenant_id=? and case_id=? and chunk_id=?",
                (tenant_id, case_id, claim["chunk_id"]),
            ).fetchone()
            if bill is None or chunk is None or bill["bytes"] != chunk["size_bytes"]:
                billing_ok = False
                problems.append(f"领取 {claim['claim_key']} 的计费缺失或金额不符")

        # 完成态与领取进度一致（只看当前清单版本；被作废版本上的历史领取合法）。
        delivery_complete = True
        current_version = int(manifest["manifest_version"]) if manifest else None
        if current_version is not None:
            total_chunks = con.execute(
                "select count(*) from delivery_chunk where tenant_id=? and case_id=? "
                "and manifest_version=?",
                (tenant_id, case_id, current_version),
            ).fetchone()[0]
            current_claims = con.execute(
                "select count(*) from chunk_claim where tenant_id=? and case_id=? "
                "and manifest_version=?",
                (tenant_id, case_id, current_version),
            ).fetchone()[0]
            if case["state"] == COMPLETED and current_claims < total_chunks:
                delivery_complete = False
                problems.append("状态为 completed 但当前版本仍有未领取分片")
            if total_chunks and current_claims == total_chunks and case["state"] != COMPLETED:
                delivery_complete = False
                problems.append("当前版本分片已全部领取但状态未到 completed")

        summary = digest(canonical_json({
            "state": case["state"],
            "manifest_hash": manifest["manifest_hash"] if manifest else None,
            "claims": sorted(c["claim_key"] for c in claims),
            "event_chain_tip": prev,
        }))
        return {
            "ok": not problems,
            "manifest_hash_ok": manifest_hash_ok,
            "event_chain_ok": event_chain_ok,
            "claims_match_manifest": claims_match,
            "billing_ok": billing_ok,
            "delivery_complete": delivery_complete,
            "final_manifest_hash": manifest["manifest_hash"] if manifest else None,
            "audit_summary_hash": summary,
            "problems": problems,
        }

    # ==================================================================
    # 内部辅助
    # ==================================================================

    def _assert_deliverable(self, con, case, actor_id: str) -> None:
        state = case["state"]
        if state == REVOKED:
            raise DeliveryDenied("导出已被撤销，未领取分片一律失效")
        if state == EXPIRED:
            raise DeliveryDenied("导出已过期，未领取分片一律失效")
        if state in TERMINAL_STATES:
            raise DeliveryDenied(f"导出处于终态 {state}")
        manifest = self._active_manifest(con, case["tenant_id"], case["case_id"])
        if manifest is None:
            raise DeliveryDenied("不存在生效中的批准清单")
        if manifest["valid_until"] is None or parse_iso(manifest["valid_until"]) <= self._now():
            # 惰性过期：把事实补齐，再拒绝（事实必须随提交保留）。
            self._set_state(con, case["tenant_id"], case["case_id"], EXPIRED)
            self._append_event(con, EXPORT_EXPIRED, case["tenant_id"], case["case_id"],
                               actor_id, {"manifest_version": manifest["manifest_version"],
                                          "valid_until": manifest["valid_until"]})
            self._audit(con, case["tenant_id"], case["case_id"], actor_id,
                        "export.expired", {"valid_until": manifest["valid_until"]})
            raise _GateFailure(DeliveryDenied("批准有效期已过，未领取分片一律失效"))
        drift = self._detect_drift(con, case["tenant_id"], case["case_id"],
                                   int(manifest["manifest_version"]))
        if drift:
            self._invalidate(con, case, manifest, actor_id,
                             reason="delivery_time_drift", changed=drift)
            raise _GateFailure(ManifestStale(
                f"文件已变化：{', '.join(drift)}，批准版本落后，需重新评估"))

    def _invalidate(self, con, case, manifest, actor_id: str, *,
                    reason: str, changed: list[str]) -> None:
        version = int(manifest["manifest_version"])
        con.execute(
            "update manifest_version set status='superseded', superseded_at=? "
            "where tenant_id=? and case_id=? and manifest_version=?",
            (self._now_iso(), case["tenant_id"], case["case_id"], version),
        )
        self._set_state(con, case["tenant_id"], case["case_id"], CLASSIFIED)
        self._append_event(con, MANIFEST_INVALIDATED, case["tenant_id"], case["case_id"],
                           actor_id, {"manifest_version": version,
                                      "manifest_hash": manifest["manifest_hash"],
                                      "reason": reason, "changed_files": changed})
        self._audit(con, case["tenant_id"], case["case_id"], actor_id,
                    "manifest.invalidated",
                    {"manifest_version": version, "reason": reason,
                     "changed_files": changed})

    def _detect_drift(self, con, tenant_id: str, case_id: str,
                      manifest_version: int) -> list[str]:
        entries = self._entries(con, tenant_id, case_id, manifest_version)
        changed: list[str] = []
        for entry in entries:
            row = con.execute(
                "select file_version, content_hash from file_catalog "
                "where tenant_id=? and file_id=?",
                (tenant_id, entry["file_id"]),
            ).fetchone()
            if row is None:
                changed.append(f"{entry['file_id']}(已移除)")
            elif row["content_hash"] != entry["content_hash"] or row["file_version"] != entry["file_version"]:
                changed.append(entry["file_id"])
        return changed

    def _receipt(self, con, tenant_id, case_id, claim_row, *, replayed: bool) -> dict[str, Any]:
        chunk = con.execute(
            "select * from delivery_chunk where tenant_id=? and case_id=? and chunk_id=?",
            (tenant_id, case_id, claim_row["chunk_id"]),
        ).fetchone()
        bill = con.execute(
            "select bytes, charged_at from billing_record where tenant_id=? and case_id=? and claim_key=?",
            (tenant_id, case_id, claim_row["claim_key"]),
        ).fetchone()
        return {
            "claim_key": claim_row["claim_key"],
            "chunk_id": claim_row["chunk_id"],
            "recipient_id": claim_row["recipient_id"],
            "manifest_version": claim_row["manifest_version"],
            "manifest_hash": claim_row["manifest_hash_at_claim"],
            "state": claim_row["state"],
            "claimed_at": claim_row["claimed_at"],
            "content_token": chunk["content_token"] if chunk else None,
            "size_bytes": chunk["size_bytes"] if chunk else None,
            "billed_bytes": bill["bytes"] if bill else None,
            "charged_at": bill["charged_at"] if bill else None,
            "replayed": replayed,
        }

    def _all_claimed(self, con, tenant_id: str, case_id: str, version: int) -> bool:
        total = con.execute(
            "select count(*) from delivery_chunk where tenant_id=? and case_id=? "
            "and manifest_version=?",
            (tenant_id, case_id, version),
        ).fetchone()[0]
        if total == 0:
            return False
        claimed = con.execute(
            "select count(*) from chunk_claim where tenant_id=? and case_id=? "
            "and manifest_version=?",
            (tenant_id, case_id, version),
        ).fetchone()[0]
        return total == claimed

    def _entries(self, con, tenant_id: str, case_id: str,
                 manifest_version: int) -> list[sqlite3_row]:
        return con.execute(
            "select * from manifest_entry where tenant_id=? and case_id=? and manifest_version=? "
            "order by entry_index",
            (tenant_id, case_id, manifest_version),
        ).fetchall()

    def _next_manifest_version(self, con, tenant_id: str, case_id: str) -> int:
        row = con.execute(
            "select coalesce(max(manifest_version), 0) + 1 as v from manifest_version "
            "where tenant_id=? and case_id=?",
            (tenant_id, case_id),
        ).fetchone()
        return int(row["v"])

    def _current_manifest(self, con, tenant_id: str, case_id: str):
        return con.execute(
            "select * from manifest_version where tenant_id=? and case_id=? "
            "order by manifest_version desc limit 1",
            (tenant_id, case_id),
        ).fetchone()

    def _active_manifest(self, con, tenant_id: str, case_id: str):
        return con.execute(
            "select * from manifest_version where tenant_id=? and case_id=? and status='active' "
            "order by manifest_version desc limit 1",
            (tenant_id, case_id),
        ).fetchone()

    def _require_case(self, con, tenant_id: str, case_id: str):
        row = con.execute(
            "select * from export_request where tenant_id=? and case_id=?",
            (tenant_id, case_id),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"租户 {tenant_id} 内找不到导出单 {case_id}")
        return row

    def _set_state(self, con, tenant_id: str, case_id: str, state: str) -> None:
        con.execute(
            "update export_request set state=?, updated_at=? where tenant_id=? and case_id=?",
            (state, self._now_iso(), tenant_id, case_id),
        )

    def _compute_manifest_hash(self, tenant_id, case_id, version, recipient, entries) -> str:
        body = {
            "tenant_id": tenant_id,
            "case_id": case_id,
            "manifest_version": version,
            "recipient_id": recipient,
            "entries": [{
                "entry_index": e["entry_index"],
                "file_id": e["file_id"],
                "file_version": e["file_version"],
                "content_hash": e["content_hash"],
                "size_bytes": e["size_bytes"],
                "sensitivity": e["sensitivity"],
                "source_location": e["source_location"],
                "inclusion_reason": e["inclusion_reason"],
            } for e in entries],
        }
        return digest(canonical_json(body))

    def _append_event(self, con, event_type, tenant_id, case_id, actor_id,
                      payload: dict[str, Any]) -> Event:
        row = con.execute(
            "select coalesce(max(aggregate_version), 0) as v, "
            "coalesce((select event_id from event_log where tenant_id=? and aggregate_id=? "
            "order by aggregate_version desc limit 1), NULL) as tail_id "
            "from event_log where tenant_id=? and aggregate_id=?",
            (tenant_id, case_id, tenant_id, case_id),
        ).fetchone()
        next_version = int(row["v"]) + 1
        prev = "GENESIS" if next_version == 1 else self._event_hash_by_id(con, row["tail_id"])
        event = Event(
            event_id=Event.new_event_id(),
            event_type=event_type,
            tenant_id=tenant_id,
            aggregate_id=case_id,
            occurred_at=self._now(),
            actor_id=actor_id,
            aggregate_version=next_version,
            payload=payload,
        )
        con.execute(
            """
            insert into event_log(event_id, event_type, tenant_id, aggregate_id, occurred_at,
                                  actor_id, aggregate_version, prev_hash, payload_json)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event.event_id, event.event_type, event.tenant_id, event.aggregate_id,
             normalize(event.occurred_at).isoformat(), event.actor_id,
             event.aggregate_version, prev,
             json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        con.execute(
            "update export_request set aggregate_version=?, updated_at=? "
            "where tenant_id=? and case_id=?",
            (next_version, self._now_iso(), tenant_id, case_id),
        )
        return event

    @staticmethod
    def _event_hash(row, prev_hash: str) -> str:
        body = {
            "event_id": row["event_id"],
            "event_type": row["event_type"],
            "tenant_id": row["tenant_id"],
            "aggregate_id": row["aggregate_id"],
            "occurred_at": row["occurred_at"],
            "actor_id": row["actor_id"],
            "aggregate_version": row["aggregate_version"],
            "payload": json.loads(row["payload_json"]),
            "prev_hash": prev_hash,
        }
        return digest(canonical_json(body))

    def _event_hash_by_id(self, con, event_id: str) -> str:
        row = con.execute(
            "select * from event_log where event_id=?", (event_id,)
        ).fetchone()
        return self._event_hash(row, row["prev_hash"])

    def _audit(self, con, tenant_id: str, case_id: str | None, actor_id: str,
               record_type: str, detail: dict[str, Any]) -> None:
        con.execute(
            "insert into audit_record(tenant_id, record_id, case_id, at, actor_id, "
            "record_type, detail_json) values (?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, f"aud-{uuid.uuid4().hex}", case_id, self._now_iso(),
             actor_id, record_type, json.dumps(detail, ensure_ascii=False, sort_keys=True)),
        )

    def _now(self) -> datetime:
        value = self.clock.now()
        return normalize(value)

    def _now_iso(self) -> str:
        return self._iso(self._now())

    @staticmethod
    def _iso(value: datetime) -> str:
        return normalize(value).isoformat()


# 类型别名：sqlite3.Row 的轻量提示，避免在模块顶部额外导入而干扰阅读。
sqlite3_row = Any
