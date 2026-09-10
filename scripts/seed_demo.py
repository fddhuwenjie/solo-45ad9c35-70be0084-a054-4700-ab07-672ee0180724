# -*- coding: utf-8 -*-
"""生成本地样例数据（演示库 data/demo.db），完整走一遍：

创建清单 -> 追加 -> 封存 -> 交接 -> 签收 -> 更正新版本 v2 封存 -> 验证（正常/异常）。

运行：
    PYTHONPATH=. python3 scripts/seed_demo.py
可选环境：DEMO_DB=/tmp/x.db
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config, database, ops  # noqa: E402

# 在导入任何持有 DB_PATH 的模块前指定演示库
DEMO_DB = os.environ.get("DEMO_DB", str(config.BASE_DIR / "data" / "demo.db"))
config.DB_PATH = Path(DEMO_DB)
if Path(DEMO_DB).exists():
    Path(DEMO_DB).unlink()
for suffix in ("-wal", "-shm"):
    p = Path(DEMO_DB + suffix)
    if p.exists():
        p.unlink()
database.init_db()

TZ = "Asia/Shanghai"


def h(tag: str) -> str:
    """生成可复现的演示用 SHA-256（仅样例，真实环境由采集工具计算）。"""
    return hashlib.sha256(("forensic-demo:" + tag).encode()).hexdigest()


def chunks(tag: str, n: int):
    return 4096, [h(f"{tag}:chunk:{i}") for i in range(n)]


# ---------------------------------------------------------------------------
# 初始采集清单（v1）
# ---------------------------------------------------------------------------
create = types.SimpleNamespace(
    case_no="A-2026-0917",
    evidence_id="USB-KINGSTON-64G-03",
    collected_at="2026-09-01T09:30:00+08:00",
    timezone=TZ,
    operator="李探员(11023)",
    note="嫌疑人移动U盘初次采集，写保护接入",
    entries=[
        types.SimpleNamespace(path="DCIM/IMG_0001.jpg", size=2485760,
                              sha256=h("IMG_0001"), chunk_size=None,
                              chunk_hashes=None,
                              mtime="2026-08-20T22:14:03+08:00"),
        types.SimpleNamespace(path="DCIM/IMG_0002.jpg", size=2512992,
                              sha256=h("IMG_0002"), chunk_size=None,
                              chunk_hashes=None,
                              mtime="2026-08-20T22:14:09+08:00"),
        types.SimpleNamespace(path="Documents/案件笔记.txt", size=8421,
                              sha256=h("notes"), chunk_size=None,
                              chunk_hashes=None,
                              mtime="2026-08-21T07:55:41+08:00"),
        types.SimpleNamespace(path="Images/banner.png", size=128 * 4096,
                              sha256=h("banner"),
                              chunk_size=4096, chunk_hashes=chunks("banner", 128)[1],
                              mtime="2026-08-18T12:00:00+08:00"),
    ],
)
created = ops.create_manifest(create)
m1_id = created["manifest"]["id"]
print("[1] 创建清单 v1:", m1_id)
print("    歧义提示数:",
      sum(len(e.get("issues") or []) for e in created["manifest"]["entries"]))

# 追加：一个带大小写变体提示的不同文件（NFKC+casefold 命中，但内容不同 => 歧义告警）
append = types.SimpleNamespace(
    operator="王探员(11045)",
    note="补充采集隐藏目录",
    entries=[
        types.SimpleNamespace(path="LOGS/syslog_2026-08.zip", size=90112,
                              sha256=h("syslog"), chunk_size=None,
                              chunk_hashes=None,
                              mtime="2026-08-21T08:02:00+08:00"),
    ],
)
appended = ops.append_entries(m1_id, append)
print("[2] 追加条目，现共", appended["manifest"]["entry_count"], "条")

# 封存（有歧义需显式确认 —— 本样例路径无冲突，直接封存）
seal = types.SimpleNamespace(operator="李探员(11023)",
                             acknowledge_issues=True, note="采集完成，封存",
                             occurred_at="2026-09-01T09:45:00+08:00",
                             timezone=TZ)
sealed = ops.seal_manifest(m1_id, seal)
print("[3] 封存 v1  merkle_root =", sealed["manifest"]["merkle_root"][:24], "...")
print("    manifest_hash =", sealed["manifest"]["manifest_hash"][:24], "...")

# 尝试篡改已封存清单（应被 409 拒绝）
try:
    ops.append_entries(m1_id, append)
except ops.models.Conflict as e:
    print("[4] 封存后追加被拒绝：", str(e)[:48], "...")

# ---------------------------------------------------------------------------
# 交接与签收
# ---------------------------------------------------------------------------
h1 = ops.create_handoff(m1_id, types.SimpleNamespace(
    from_party="李探员(11023)", to_party="鉴定中心-赵工(GZ-088)",
    occurred_at="2026-09-01T10:00:00+08:00", timezone=TZ, note="送鉴定"))
hid1 = h1["handoff"]["id"]
print("[5] 交接 #1:", hid1[:8])

s1 = ops.signoff(hid1, types.SimpleNamespace(
    actor="赵工", actor_id_no="GZ-088",
    occurred_at="2026-09-01T11:20:00+08:00", timezone=TZ, note="签收完好"))
print("[6] 签收 #1，身份缺失=", s1["missing_identity"])

# ---------------------------------------------------------------------------
# 更正：鉴定中发现一个文件记录有误，生成关联新版本 v2（open 后再封存）
# ---------------------------------------------------------------------------
v2_entries = [
    types.SimpleNamespace(path="DCIM/IMG_0001.jpg", size=2485760,
                          sha256=h("IMG_0001"), chunk_size=None,
                          chunk_hashes=None, mtime="2026-08-20T22:14:03+08:00"),
    types.SimpleNamespace(path="DCIM/IMG_0002.jpg", size=2512992,
                          sha256=h("IMG_0002"), chunk_size=None,
                          chunk_hashes=None, mtime="2026-08-20T22:14:09+08:00"),
    types.SimpleNamespace(path="Documents/案件笔记.txt", size=8421,
                          sha256=h("notes"), chunk_size=None,
                          chunk_hashes=None, mtime="2026-08-21T07:55:41+08:00"),
    types.SimpleNamespace(path="Images/banner.png", size=128 * 4096,
                          sha256=h("banner"), chunk_size=4096,
                          chunk_hashes=chunks("banner", 128)[1],
                          mtime="2026-08-18T12:00:00+08:00"),
    types.SimpleNamespace(path="LOGS/syslog_2026-08.zip", size=90112,
                          sha256=h("syslog"), chunk_size=None,
                          chunk_hashes=None, mtime="2026-08-21T08:02:00+08:00"),
    # 更正：补充初采遗漏的视频
    types.SimpleNamespace(path="VIDEO/REC_0001.mp4", size=58 * 1024 * 1024,
                          sha256=h("rec1"), chunk_size=1024 * 1024,
                          chunk_hashes=chunks("rec1", 58)[1],
                          mtime="2026-08-20T22:20:11+08:00"),
]
corrected = ops.correct_manifest(m1_id, types.SimpleNamespace(
    case_no=None, evidence_id=None, collected_at=None, timezone=None,
    operator="赵工(GZ-088)", reason="初采遗漏 VIDEO/REC_0001.mp4，依鉴定申请补充并生成v2",
    entries=v2_entries, note="v2 更正版"))
m2_id = corrected["manifest"]["id"]
print("[7] 更正生成 v2:", m2_id, "supersedes =", m1_id[:8])
ops.seal_manifest(m2_id, types.SimpleNamespace(
    operator="赵工(GZ-088)", acknowledge_issues=True, note="v2封存",
    occurred_at="2026-09-02T16:30:00+08:00", timezone=TZ))
print("    v2 已封存")

# ---------------------------------------------------------------------------
# 验证 1：完全一致（hash_list 模式）
# ---------------------------------------------------------------------------
ok_payload = types.SimpleNamespace(
    mode="hash_list", collected_at="2026-09-05T14:00:00+08:00",
    timezone=TZ, operator="赵工(GZ-088)",
    entries=[types.SimpleNamespace(path=e.path, sha256=e.sha256, size=e.size,
                                   chunk_size=e.chunk_size,
                                   chunk_hashes=e.chunk_hashes)
             for e in v2_entries],
)
r_ok = ops.verify_manifest(m2_id, ok_payload)
print("[8] 验证（一致）verdict =", r_ok["verdict"])

# ---------------------------------------------------------------------------
# 验证 2：异常场景 —— 改名、新增、缺失、内容变化、分块损坏、时间异常
# ---------------------------------------------------------------------------
bad_banner_chunks = list(chunks("banner", 128)[1])
bad_banner_chunks[10] = h("TAMPERED-CHUNK-10")
bad_banner_chunks[11] = h("TAMPERED-CHUNK-11")
bad_banner_chunks[64] = h("TAMPERED-CHUNK-64")

bad_entries = [
    # 内容变化 + 分块损坏（banner 第 10-11、64 块）
    types.SimpleNamespace(path="Images/banner.png", size=128 * 4096,
                          sha256=h("banner-TAMPERED"), chunk_size=4096,
                          chunk_hashes=bad_banner_chunks,
                          mtime="2026-09-03T03:03:03+08:00"),  # 时间戳也被改
    # 改名候选：文件被重命名，哈希不变（路径大小写也被改）
    types.SimpleNamespace(path="DCIM/IMG_0002_备份.jpg", size=2512992,
                          sha256=h("IMG_0002"), chunk_size=None,
                          chunk_hashes=None,
                          mtime="2026-08-20T22:14:09+08:00"),
    types.SimpleNamespace(path="Documents/案件笔记.txt", size=8421,
                          sha256=h("notes"), chunk_size=None,
                          chunk_hashes=None, mtime="2026-08-21T07:55:41+08:00"),
    types.SimpleNamespace(path="LOGS/syslog_2026-08.zip", size=90112,
                          sha256=h("syslog"), chunk_size=None,
                          chunk_hashes=None, mtime="2026-08-21T08:02:00+08:00"),
    # 新增未知文件（修改时间晚于重采时间/落在未来，制造时间异常）
    types.SimpleNamespace(path="RECYCLER/stealer.exe", size=45056,
                          sha256=h("stealer"), chunk_size=None,
                          chunk_hashes=None,
                          mtime="2026-09-12T01:30:00+08:00"),
    # IMG_0001 缺失；REC_0001.mp4 缺失
]
bad_payload = types.SimpleNamespace(
    mode="metadata", collected_at="2026-09-05T15:00:00+08:00",
    timezone=TZ, operator="赵工(GZ-088)", entries=bad_entries,
)
r_bad = ops.verify_manifest(m2_id, bad_payload)
print("[9] 验证（异常）verdict =", r_bad["verdict"])
print("    新增:", [e["path"] for e in r_bad["added"]])
print("    缺失:", [e["path"] for e in r_bad["missing"]])
print("    改名候选:",
      [(c["old_path"], c["new_path"], c["confidence"]) for c in r_bad["rename_candidates"]])
print("    分块损坏:",
      [(c["path"], c["corrupt_ranges"]) for c in r_bad["chunk_corruptions"]])
print("    时间异常:", [f["code"] for f in r_bad["time_anomalies"]])

# ---------------------------------------------------------------------------
# 导出证据包 + 报告
# ---------------------------------------------------------------------------
pkg = ops.build_evidence_package(m2_id)
out_dir = config.BASE_DIR / "samples"
out_dir.mkdir(exist_ok=True)
with open(out_dir / "evidence_package.sample.json", "w", encoding="utf-8") as f:
    json.dump(pkg, f, ensure_ascii=False, indent=2)

# v1 的证据包：包含交接/签收审计事件（交接发生在更正之前）
pkg_v1 = ops.build_evidence_package(m1_id)
with open(out_dir / "evidence_package_v1.sample.json", "w", encoding="utf-8") as f:
    json.dump(pkg_v1, f, ensure_ascii=False, indent=2)

text, _, _ = ops.render_report_by_verification(r_bad["verification_id"])
with open(out_dir / "verification_report.sample.md", "w", encoding="utf-8") as f:
    f.write(text)

print("[10] 审计链:", ops.audit.verify_chain())
print("[11] 证据包与报告已写入 samples/")
print("     清单ID: v1 =", m1_id, " v2 =", m2_id)
print("     演示库:", DEMO_DB)
