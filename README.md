# 数字取证移动介质交接核对 API

供数字取证人员核对移动介质（U 盘、移动硬盘、手机镜像等）交接材料的**本地** REST API。
Python 3.11+ / FastAPI / SQLite / Pydantic，**不依赖任何外部服务**。

## 能力一览

| 需求 | 实现 |
|---|---|
| 客户端提交案件编号、证物标识、采集时间、操作者、时区、路径/字节数/SHA-256/分块哈希 | `POST /api/v1/manifests`（Pydantic 强校验：哈希格式、时区 IANA、时间必须带偏移） |
| 规范化、可复现的清单版本 | 封存时固定规范化 JSON（键排序、无空白、UTF-8/LF），计算 `manifest_hash` 与 **Merkle 根**；规范号 `forensic-manifest-v1` |
| 路径大小写 / Unicode 归一化识别重复与歧义 | 统一分隔符 + **NFKC** + `casefold` 折叠键；同折叠键同内容=硬重复拒收；同折叠键不同内容=歧义告警，封存须显式确认 |
| 追加封存 | open 清单可 `POST .../entries` 追加；`POST .../seal` 后只读 |
| 封存后不可改，更正产生关联新版本 | 封存版本任何写操作返回 409；`POST .../correct` 在同一 `lineage_id` 下生成新版本，`supersedes_id` 回指旧版，验证时检查版本链 |
| 交接 / 签收 | `POST .../handoffs` 与 `POST /handoffs/{id}/signoff`；校验交接顺序、签收时间倒置、交出方连续性、身份缺失 |
| 验证（重采元数据或哈希列表） | `.../verify/metadata`、`.../verify/hash-list`，逐项返回**新增、缺失、改名候选、内容变化、时间异常、分块损坏字节范围、元数据异常、交接问题、Merkle/版本链问题** |
| Merkle 根断链检查 | 用库内条目重算根，与封存值比对；同时复验规范化字节哈希 |
| 仅追加审计链 | 每次状态变化写入事件，响应含 `prev_hash` 与 `event_hash`；SQLite 触发器在**数据库层**禁止 `audit_event` 的 UPDATE/DELETE；`GET /audit/verify` 重算全链 |
| 导出 | JSON 证据包 `GET .../export`；人类可读 Markdown 报告 `GET .../report` 或按验证 ID 取 |
| 样例数据 / OpenAPI | `scripts/seed_demo.py`；`samples/`；交互式文档 `/docs`、`/redoc`，规范 `/openapi.json` |

## Merkle 与审计哈希约定

* 叶子：`SHA256(0x00LEAF: + canonical({path,size,sha256,chunk_size,chunk_hashes,mtime}))`
* 内部：`SHA256(0x01INNER: + left_hash + right_hash)`，域分隔前缀防止叶子/内部节点伪造
* 奇数节点复制最后一个节点参与配对（duplicate-last-node）
* 审计事件：`event_hash = SHA256(prev_hash + canonical(event_body))`，首事件前驱为 64 个 `0`

## 快速开始

```bash
# 1) 安装依赖（二选一）
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
#   或本仓库已在 ./.pylibs 内置依赖时直接用 run.sh

# 2) 启动（默认 http://127.0.0.1:8080，数据在 ./data/forensic.db）
./run.sh
#   自定义：FORENSIC_DB=/data/case.db HOST=0.0.0.0 PORT=9000 ./run.sh
```

打开 <http://127.0.0.1:8080/docs> 即为 OpenAPI 交互文档。

## 典型流程

```bash
BASE=http://127.0.0.1:8080/api/v1

# 1. 创建清单
curl -s $BASE/manifests -H 'Content-Type: application/json' \
  -d @samples/request.create_manifest.json

# 2. 追加条目（open 状态）
curl -s $BASE/manifests/$MID/entries -H 'Content-Type: application/json' \
  -d '{"operator":"王探员","entries":[{"path":"LOGS/a.zip","size":90112,"sha256":"<64hex>"}]}'

# 3. 封存（有路径歧义时须 acknowledge_issues=true）
curl -s $BASE/manifests/$MID/seal -H 'Content-Type: application/json' \
  -d '{"operator":"李探员","occurred_at":"2026-09-01T09:45:00+08:00","acknowledge_issues":true}'

# 4. 交接 + 签收（actor 可留空 => 记录身份缺失）
curl -s $BASE/manifests/$MID/handoffs -H 'Content-Type: application/json' \
  -d '{"from_party":"李探员","to_party":"赵工","occurred_at":"2026-09-01T10:00:00+08:00","timezone":"Asia/Shanghai"}'
curl -s $BASE/handoffs/$HID/signoff -H 'Content-Type: application/json' \
  -d '{"actor":"赵工","actor_id_no":"GZ-088","occurred_at":"2026-09-01T11:20:00+08:00","timezone":"Asia/Shanghai"}'

# 5. 更正已封存清单 => 同 lineage 新版本
curl -s $BASE/manifests/$MID/correct -H 'Content-Type: application/json' \
  -d '{"operator":"赵工","reason":"补录遗漏视频","entries":[ ...完整新版本条目... ]}'

# 6. 重新采集后核验（metadata 完整模式 / hash-list 轻量模式）
curl -s $BASE/manifests/$MID/verify/hash-list -H 'Content-Type: application/json' \
  -d '{"mode":"hash_list","collected_at":"2026-09-05T15:00:00+08:00","timezone":"Asia/Shanghai","entries":[{"path":"DCIM/IMG_0001.jpg","sha256":"..."}]}'

# 7. 导出证据包 / 报告 / 校验审计链
curl -s $BASE/manifests/$MID/export -o evidence_package.json
curl -s $BASE/manifests/$MID/report                 # 最近一次验证的 Markdown
curl -s $BASE/verifications/$VID/report             # 指定验证的 Markdown
curl -s $BASE/audit/verify
```

## 验证结论（verdict）与发现代码

* `PASS` / `PASS_WITH_WARNINGS`（仅有 warning/info）/ `FAIL`（存在 high/critical）
* 发现分组：`added` / `missing` / `rename_candidates`（哈希一致=high 强候选，
  否则按路径相似度给 medium/low）/ `changed` / `time_anomalies` /
  `chunk_corruptions`（含 `start_chunk`-`end_chunk` 与字节范围提示）/
  `metadata_anomalies` / `custody_findings` / `lineage_findings` / `merkle_findings`
* 强改名候选（同 SHA-256）只计入改名，不再计为无法解释的新增/缺失

主要发现代码：`UNEXPLAINED_ADD/MISSING`、`MTIME_IN_FUTURE`、`MTIME_AFTER_COLLECT`、
`RECOLLECT_BEFORE_COLLECT`、`SIZE_MISMATCH`、`MTIME_MISMATCH`、
`CUSTODY_UNSIGNED_HANDOFF`、`CUSTODY_PARTY_DISCONTINUITY`、
`SIGNOFF_IDENTITY_MISSING`、`SIGNOFF_TIME_INVERSION`、`CHAIN_TIME_INVERSION`、
`LINEAGE_LINK_BROKEN`、`LINEAGE_UNSEALED_PARENT`、`MERKLE_ROOT_MISMATCH`、
`MANIFEST_HASH_MISMATCH`、`AUDIT_CHAIN_BROKEN`。

## 样例数据

```bash
PYTHONPATH=. python3 scripts/seed_demo.py     # 生成 data/demo.db 与 samples/ 下的证据包、报告
```

样例剧本覆盖：追加、封存、封存后拒改、交接签收、更正生成 v2、一致验证与
异常验证（改名/新增/缺失/内容变化/块 10-11 与 64 损坏/未来时间戳）。

* `samples/openapi.sample.json` — OpenAPI 规范快照
* `samples/evidence_package.sample.json` — v2 证据包样例（含版本链、验证记录）
* `samples/evidence_package_v1.sample.json` — v1 证据包样例（含交接/签收审计事件）
* `samples/verification_report.sample.md` — 人类可读核验报告
* `samples/request.create_manifest.json` — 创建请求样例

## 测试

```bash
PYTHONPATH=.pylibs:. python3 -m pytest tests/ -q        # 21 个单元/接口测试
PYTHONPATH=.pylibs:. python3 scripts/http_smoke_test.py # 真实 HTTP 端到端冒烟（20 项断言）
```

## 数据与安全说明

* 所有时间内部统一存储 UTC ISO-8601，并保留采集/事件时区；导出报告按记录时区呈现
* `audit_event` 的 UPDATE/DELETE 由 SQLite 触发器拒绝（已在测试中验证）
* 直接篡改 `entry` 表会在验证时触发 `MERKLE_ROOT_MISMATCH`（已验证）
* 服务默认仅监听 `127.0.0.1`；无认证设计，部署到多用户环境请置于本机或受控内网并自行加边界防护

## 目录结构

```
app/
  config.py       路径与规范常量
  crypto.py       规范化 JSON、路径 NFKC/casefold、Merkle、分块区间
  timeutil.py     时区与 ISO-8601 校验
  database.py     SQLite 模式/触发器、连接管理
  audit.py        仅追加哈希链
  models.py       条目规范化与重复/歧义扫描
  schemas.py      Pydantic 请求模型
  ops.py          业务操作（清单生命周期、交接、验证、导出）
  routers/api.py  REST 路由
  main.py         应用入口与异常处理
scripts/          样例数据与 HTTP 冒烟脚本
samples/          样例请求/证据包/报告/OpenAPI
tests/            pytest 测试
```
