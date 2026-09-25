# 受控导出授权中枢

面向托管智能体平台的受控文件导出服务：申请人先声明业务目的与范围，系统冻结
**不可变清单**并按敏感等级决定是否需要数据所有者与安全值班员共同批准；批准只对
**清单哈希、接收方和有效期**生效，等待期间文件变化即作废旧批准；大批量导出支持
分片续传，但撤销、过期或审批版本落后后未领取分片一律失效；同一领取请求重试不重复
计费、不产生第二份交付记录；管理员可查询每个文件为何纳入、被谁批准、哪些分片已
领取，并对最终清单与审计摘要做一致性对账。服务重启后未完成导出仍停留在正确阶段。

## 目录

- `domain/contract.json`：实体、状态、事件类型与关键业务规则（领域合同）。
- `domain/policies.json`：可被程序读取的策略样例。
- `examples/events.json`：按业务发生时间排列的事件样例。
- `export_guard/`：受控导出服务实现（仅依赖 Python 标准库与 SQLite）。
  - `policy.py`：敏感等级与会签策略（public/internal 免签，confidential 需数据
    所有者，restricted/secret 需数据所有者 + 安全值班员）。
  - `store.py`：SQLite 表结构与事务；事件表带哈希链，只追加。
  - `events.py`：与领域合同对齐的事件类型。
  - `service.py`：领域服务与全部业务不变量。
  - `api.py`：HTTP 接口（`python3 -m export_guard.api`）。
  - `time.py`、`errors.py`：时间归一化（带时区 ISO 8601，UTC 存储）与异常。
- `tools/validate_contract.py`：领域资料离线校验。
- `tests/`：领域规则（29 项）与 HTTP 端到端（2 项）测试。

## 关键不变量与落点

| 要求 | 实现方式 |
| --- | --- |
| 提前知道带走哪些内容、不可变清单 | `freeze_manifest` 对文件版本/哈希/大小/等级/来源/纳入理由做快照，计算 `manifest_hash`；历史版本只追加，永不覆盖。 |
| 按敏感等级会签 | `ApprovalPolicy` 决定必需角色；角色集齐（quorum）清单才置 `active`。 |
| 批准绑定哈希/接收方/有效期 | `approval` 行记录 `bound_manifest_hash`、`bound_recipient_id`、`valid_until`；领取时强校验接收方与版本。 |
| 等待期间文件变化必须重新评估 | 批准与领取前做漂移检测（版本或内容哈希变化、文件移除）；漂移即发布 `manifest.invalidated`、旧版本置 `superseded`、状态回 `classified`，旧批准不携带到新版本。 |
| 分片续传 + 撤销/过期/版本落后失效 | `claim_chunk` 前过交付闸门：`revoked/expired` 拒绝；越过有效期惰性发布 `export.expired`；落后版本分片拒绝。已领取的同键重试仍可回放。 |
| 重试不重复计费、不产生第二份交付 | `chunk_claim` 以 `(case, claim_key)` 为主键、`(case, chunk_id)` 唯一索引；`billing_record` 以 `claim_key` 为主键。同键重试直接回放首张回执。 |
| 管理员可解释与对账 | `list_entries`（为何纳入/是否已漂移）、`list_approvals`、`list_claims`/`list_chunks`、`event_history`、`audit_trail`、`verify_consistency`。 |
| 最终清单与审计摘要一致 | `verify_consistency` 重算清单哈希、校验事件 `prev_hash` 哈希链与版本连续性、核对领取绑定哈希、计费一一对应、完成态与领取进度一致，并给出 `audit_summary_hash`。 |
| 重启后保持正确阶段 | 状态、版本、领取、计费全部在 SQLite 提交；进程无易变状态。启动调用 `recover()`/`sweep_expired()` 把越过有效期的导出补齐为 `expired`。 |

## 快速开始（领域服务）

```python
from datetime import datetime, timedelta, timezone
from export_guard import ControlledExportService

svc = ControlledExportService("guard.db")
svc.upsert_file("tenant-1", "f-a", "v1", "h-a", 100, "restricted", "s3://f-a", actor_id="cat")
svc.create_request("tenant-1", "case-1", "op", "应急取证", "rx", actor_id="op")
svc.freeze_manifest("tenant-1", "case-1",
                    [{"file_id": "f-a", "inclusion_reason": "命中告警"}], actor_id="rev")
deadline = datetime.now(timezone.utc) + timedelta(hours=12)
svc.record_approval("tenant-1", "case-1", "data_owner", "owner", deadline, actor_id="owner")
svc.record_approval("tenant-1", "case-1", "security_officer", "soc", deadline, actor_id="soc")
svc.prepare_chunks("tenant-1", "case-1", [[0]], actor_id="op")
receipt = svc.claim_chunk("tenant-1", "case-1", "chunk-1-0", "rx", "claim-key-1", actor_id="op")
print(svc.verify_consistency("tenant-1", "case-1"))
```

## HTTP 服务

```bash
python3 -m export_guard.api --db ./guard.db --host 127.0.0.1 --port 8080
```

- `POST /tenants/:t/files`：登记/更新文件台账
- `POST /tenants/:t/cases`：创建导出申请
- `POST /tenants/:t/cases/:c/manifest`：冻结并分级清单
- `POST /tenants/:t/cases/:c/approvals`：会签批准（携带 `valid_until` 带时区时间戳，可选 `expected_manifest_version`）
- `POST /tenants/:t/cases/:c/chunks`：规划/重复下发分片计划
- `POST /tenants/:t/cases/:c/claims`：幂等领取（`claim_key` 为重试键）
- `POST /tenants/:t/cases/:c/revoke`：撤销
- `POST /admin/sweep-expired`：过期扫描
- `GET  /tenants/:t/cases/:c`：阶段与当前清单
- `GET  /tenants/:t/cases/:c/entries`：每个文件为何纳入、冻结后是否漂移
- `GET  /tenants/:t/cases/:c/approvals`：批准人与绑定要素
- `GET  /tenants/:t/cases/:c/chunks` / `claims`：分片与领取/计费
- `GET  /tenants/:t/cases/:c/events` / `audit` / `verify`：事件流、审计轨迹、对账

错误状态：404 不存在，400 范围/参数错误，409 状态冲突或版本落后/重复领取，
403 撤销/过期等交付拒绝。

## 构建与测试

所有命令在项目根目录执行，无需启动外部数据库或缓存（SQLite 内置）。

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
```
