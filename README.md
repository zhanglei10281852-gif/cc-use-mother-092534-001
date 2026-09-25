# 受控导出授权中枢

托管智能体平台的受控文件导出服务：申请人声明业务目的与范围，系统冻结
不可变清单并按敏感等级决定审批人组合；批准只对清单哈希、接收方和有效期
生效；等待期间文件变化必须重新评估；大批量导出支持分片续传，撤销、过期
或审批版本落后后未领取分片立即失效；同一领取重试不重复计费、不产生第二
份交付记录；管理员可查询每个文件的纳入原因、批准人、分片领取情况，并获
得独立重算的审计一致性结论。服务重启后从未完成导出继续，阶段保持正确。

## 架构

仅依赖 Python 3.11 标准库，持久化使用 SQLite。

- **事件溯源**：领域状态全部由 `domain/contract.json` 定义的 8 类事件重建，
  事实只追加、不覆盖（`exportguard/events.py`、`aggregate.py`）。
- **不可变清单**：条目按规范 JSON（键排序、无空白、UTF-8）计算 SHA-256；
  路径、版本、内容哈希、大小、敏感等级、纳入原因全部参与摘要
  （`events.manifest_hash`）。
- **分级审批**（`policy.py`）：
  - `normal`：系统生成与人工批准同构的自动批准；
  - `confidential` / `restricted`：数据所有者 + 安全值班员共同批准；
  - 批准有效期按等级封顶（72h / 24h / 8h）。
- **原子领取**：幂等记录、计费记录、`chunk.claimed` 事件、可能的
  `export.completed` 事件在同一个数据库事务写入
  （`storage.py` 唯一约束 + `service.claim_chunk`）。
- **审计**：`audit_summary` 不信任内存态，独立重放事件、重算清单哈希、
  核对批准绑定、交付/计费一一对应、分片计划覆盖性。

## 目录

- `domain/contract.json`：实体、状态、事件类型与关键业务规则。
- `domain/policies.json`：机器可读策略（角色、有效期、实施位置）。
- `examples/events.json`：完整生命周期事件样例。
- `exportguard/`：服务实现。
  - `events.py` 事件与规范哈希；`aggregate.py` 状态机与规则；
  - `policy.py` 分级策略；`storage.py` SQLite 事件库/幂等/计费；
  - `service.py` 应用服务（用例事务边界）；`api.py` HTTP 接口；
  - `clock.py` 可注入时钟；`errors.py` 错误码；`models.py` 查询视图。
- `tools/validate_contract.py`：领域资料离线校验。
- `tests/`：36 个测试，覆盖生命周期、版本作废、幂等并发、撤销过期、
  查询审计、重启恢复、HTTP 接口、合同一致性与篡改检测。

## 构建与测试

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
```

## 启动 HTTP 服务

```bash
python3 -m exportguard.api --db data/exportguard.db --host 127.0.0.1 --port 8080
```

## 接口

租户经 `X-Tenant-Id` 头传递，命令可带 `Idempotency-Key` 头。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/exports` | 提交业务目的、接收方，创建申请 |
| GET | `/exports` | 列出本租户申请 |
| GET | `/exports/{case}` | 全貌：状态、清单、批准、领取、事件流 |
| POST | `/exports/{case}/manifest` | 冻结并分级清单（含分片计划） |
| POST | `/exports/{case}/approvals` | 数据所有者/安全值班员批准 |
| POST | `/exports/{case}/invalidate` | 文件变化，作废清单并强制重新评估 |
| POST | `/exports/{case}/chunks/{i}/claims` | 分片领取（同 `claim_key` 重试幂等） |
| POST | `/exports/{case}/revoke` | 撤销，未领取分片立即失效 |
| GET | `/exports/{case}/chunks` | 各分片领取与计费情况 |
| GET | `/exports/{case}/inclusions` | 每个文件为何纳入、谁批准、归属分片 |
| GET | `/exports/{case}/audit` | 审计摘要与一致性结论 |
| POST | `/maintenance/expire` | 扫描并置过期（命令路径也会惰性过期） |

### 典型流程（confidential）

```bash
T="-H X-Tenant-Id:tenant-a -H Content-Type:application/json"
curl -s $T -X POST localhost:8080/exports -d '{
  "applicant_id":"operator-1",
  "business_purpose":"客户空间合规复盘",
  "recipient":"sftp://partner-bucket"}'

curl -s $T -X POST localhost:8080/exports/case-xxx/manifest -d '{
  "actor_id":"reviewer-2","chunk_size_bytes":104857600,
  "entries":[{"file_id":"f1","path":"/data/f1.dat","file_version":"v1",
    "content_hash":"sha256-...","sensitivity":"confidential",
    "size_bytes":1234,"owner_id":"owner-9",
    "included_reason":"命中本次申请范围：客户空间 /data 下文件"}]}'

curl -s $T -X POST localhost:8080/exports/case-xxx/approvals \
  -d '{"role":"data_owner","approver_id":"owner-9"}'
curl -s $T -X POST localhost:8080/exports/case-xxx/approvals \
  -d '{"role":"security_officer","approver_id":"soc-7"}'

curl -s $T -X POST localhost:8080/exports/case-xxx/chunks/0/claims \
  -d '{"claim_key":"claim-20260925-0","claimed_by":"operator-1"}'
# 网络重试时重发完全相同的请求：返回同一 delivery_id 与 billing_record_id
```

### 关键拒绝码

- `revoked` / `expired`：撤销或过期后领取未领取分片；
- `approval_stale`：清单哈希已变（文件更新后未重新共同批准）或批准缺失；
- `manifest_stale`：对已作废清单操作；
- `chunk_already_claimed`：换领取键重复领取同一分片；
- `idempotency_fingerprint_mismatch`：同一幂等键携带了不同参数。

## 设计约束

- 所有时间为带时区 ISO 8601；分片计划对同一份清单确定性生成。
- 重新分级后历史交付与计费不删除，按 `(清单版本, 分片序号)` 保留审计。
- 过期事件在独立事务提交，避免"拒绝的命令"回滚过期事实。
- 生产部署需在 API 前补齐真实身份认证、审批人鉴权与传输加密。
