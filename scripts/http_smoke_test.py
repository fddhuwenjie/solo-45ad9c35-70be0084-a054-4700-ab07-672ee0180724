# -*- coding: utf-8 -*-
"""HTTP 端到端冒烟测试（仅用标准库）。

在临时数据库上启动应用并直接用 FastAPI TestClient 需要 httpx；
为避免额外依赖，这里用 uvicorn + urllib 走真实 HTTP。

运行：
    PYTHONPATH=. python3 scripts/http_smoke_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("SMOKE_PORT", "8099"))
BASE = f"http://127.0.0.1:{PORT}/api/v1"
DB = ROOT / "data" / "smoke.db"

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def req(method: str, path: str, body=None, expect: int = 200):
    url = BASE + path
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            code = resp.status
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        code = e.code
        raw = e.read().decode()
    payload = None
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw
    assert code == expect, f"{method} {path} -> {code}（期望 {expect}）: {raw[:400]}"
    return payload


def h(tag: str) -> str:
    return hashlib.sha256(("smoke:" + tag).encode()).hexdigest()


def main() -> int:
    for p in (DB, Path(str(DB) + "-wal"), Path(str(DB) + "-shm")):
        if p.exists():
            p.unlink()

    env = dict(os.environ, PYTHONPATH=f"{ROOT}/.pylibs:{ROOT}",
               FORENSIC_DB=str(DB))
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        # 等待启动
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=2)
                break
            except Exception:
                time.sleep(0.5)
        else:
            out = server.stdout.read().decode() if server.stdout else ""
            raise RuntimeError("服务启动失败:\n" + out)

        print("[系统]")
        health = urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health").read()
        check("health 200", b"ok" in health)

        print("[创建/重复识别]")
        body = {
            "case_no": "C-1", "evidence_id": "E-1",
            "collected_at": "2026-09-01T09:00:00+08:00", "timezone": "Asia/Shanghai",
            "operator": "alice", "entries": [
                {"path": "a/File.dat", "size": 10, "sha256": h("f1"),
                 "mtime": "2026-08-30T10:00:00+08:00"},
                # NFKC+casefold 与上一条折叠相同但哈希不同 => 歧义
                {"path": "a/ＦＩＬＥ.dat", "size": 20, "sha256": h("f2")},
            ],
        }
        r = req("POST", "/manifests", body)
        mid = r["manifest"]["id"]
        issues = [i for e in r["manifest"]["entries"] for i in (e.get("issues") or [])]
        check("创建成功并返回审计 prev/event hash",
              r["audit"]["prev_hash"] == "0" * 64 and len(r["audit"]["event_hash"]) == 64)
        check("NFKC+大小写歧义被标记",
              any(i["code"] == "AMBIGUOUS_PATH_CONTENT" for i in issues),
              json.dumps(issues, ensure_ascii=False))

        # 硬重复（折叠同路径 + 同内容）应 400
        dup = {"entries": [{"path": "A/file.dat", "size": 10, "sha256": h("f1")}]}
        req("POST", f"/manifests/{mid}/entries", dup, expect=400)

        # 坏哈希格式应 422
        bad = {"entries": [{"path": "x", "size": 1, "sha256": "abc"}]}
        req("POST", f"/manifests/{mid}/entries", bad, expect=422)
        # 无时区偏移时间应 422
        badtz = {"entries": [{"path": "y", "size": 1, "sha256": h("y")}]}
        req("POST", f"/manifests/{mid}/entries", badtz)  # 合法追加
        bad_collect = {"case_no": "C", "evidence_id": "E",
                       "collected_at": "2026-09-01T09:00:00", "timezone": "Asia/Shanghai",
                       "operator": "a", "entries": []}
        req("POST", "/manifests", bad_collect, expect=400)

        print("[封存/不可变]")
        # 有歧义未确认 -> 400
        req("POST", f"/manifests/{mid}/seal",
            {"operator": "alice", "acknowledge_issues": False,
             "occurred_at": "2026-09-01T09:30:00+08:00"}, expect=400)
        sealed = req("POST", f"/manifests/{mid}/seal",
                     {"operator": "alice", "acknowledge_issues": True,
                      "occurred_at": "2026-09-01T09:30:00+08:00"})
        check("封存产生 manifest_hash 与 merkle_root",
              bool(sealed["manifest"]["manifest_hash"])
              and bool(sealed["manifest"]["merkle_root"]))
        root1 = sealed["manifest"]["merkle_root"]
        # 重复封存 409，追加 409
        req("POST", f"/manifests/{mid}/seal",
            {"operator": "alice", "acknowledge_issues": True}, expect=409)
        req("POST", f"/manifests/{mid}/entries",
            {"entries": [{"path": "z", "size": 1, "sha256": h("z")}]}, expect=409)

        print("[交接/签收/倒置/身份缺失]")
        h1 = req("POST", f"/manifests/{mid}/handoffs",
                 {"from_party": "alice", "to_party": "bob",
                  "occurred_at": "2026-09-01T10:00:00+08:00", "timezone": "Asia/Shanghai"})
        hid = h1["handoff"]["id"]
        # 交接早于封存 -> 400
        req("POST", f"/manifests/{mid}/handoffs",
            {"from_party": "a", "to_party": "b",
             "occurred_at": "2026-09-01T08:00:00+08:00", "timezone": "Asia/Shanghai"},
            expect=400)
        # 签收早于交接 -> 400
        req("POST", f"/handoffs/{hid}/signoff",
            {"actor": "bob", "occurred_at": "2026-09-01T09:59:00+08:00",
             "timezone": "Asia/Shanghai"}, expect=400)
        # 身份缺失签收（允许，记录缺失）
        s = req("POST", f"/handoffs/{hid}/signoff",
                {"occurred_at": "2026-09-01T10:30:00+08:00",
                 "timezone": "Asia/Shanghai"})
        check("无 actor 签收记录 missing_identity=true", s["missing_identity"] is True)
        # 重复签收 409
        req("POST", f"/handoffs/{hid}/signoff",
            {"actor": "bob", "occurred_at": "2026-09-01T10:31:00+08:00",
             "timezone": "Asia/Shanghai"}, expect=409)

        print("[更正版本链]")
        entries_v2 = [
            {"path": "a/File.dat", "size": 10, "sha256": h("f1")},
            {"path": "y", "size": 1, "sha256": h("y")},
            {"path": "new/corrected.log", "size": 100, "sha256": h("c1")},
        ]
        corr = req("POST", f"/manifests/{mid}/correct",
                   {"operator": "bob", "reason": "补录遗漏文件", "entries": entries_v2})
        v2 = corr["manifest"]["id"]
        check("更正生成 v2 且 supersedes 指向 v1",
              corr["supersedes_id"] == mid
              and any(x["version"] == 2 and x["supersedes_id"] == mid
                      for x in corr["manifest"]["lineage"]))
        req("POST", f"/manifests/{v2}/seal",
            {"operator": "bob", "acknowledge_issues": True,
             "occurred_at": "2026-09-02T09:00:00+08:00"})

        print("[验证：hash_list]")
        vr = req("POST", f"/manifests/{v2}/verify/hash-list",
                 {"mode": "hash_list",
                  "collected_at": "2026-09-03T09:00:00+08:00",
                  "timezone": "Asia/Shanghai",
                  "entries": [{"path": p["path"], "sha256": p["sha256"]}
                              for p in entries_v2]})
        check("完全一致 -> PASS，Merkle 重算根匹配封存根",
              vr["verdict"] == "PASS"
              and vr["merkle"]["baseline_root_sealed"]
              == vr["merkle"]["baseline_root_recomputed"],
              json.dumps(vr.get("merkle_findings"), ensure_ascii=False))
        vid = vr["verification_id"]

        # 异常：改名（哈希一致）、新增、缺失、内容变化、分块损坏
        bin_chunks = [h(f"bin:chunk:{i}") for i in range(4)]
        bad_chunks = list(bin_chunks)
        bad_chunks[2] = h("TAMPER")
        entries_v2_with_chunks = [
            {"path": "a/File.dat", "size": 10, "sha256": h("f1")},
            {"path": "renamed/corrected_rename.log", "size": 100,
             "sha256": h("c1")},
            {"path": "new/tampered.bin", "size": 16384, "sha256": h("tampered"),
             "chunk_size": 4096, "chunk_hashes": bad_chunks},
        ]
        # 先给 v2 的一个文件加 chunk 基线：构造第三版
        v3_entries = entries_v2 + [
            {"path": "new/tampered.bin", "size": 16384, "sha256": h("orig-bin"),
             "chunk_size": 4096, "chunk_hashes": bin_chunks},
        ]
        corr3 = req("POST", f"/manifests/{v2}/correct",
                    {"operator": "bob", "reason": "加入分块文件", "entries": v3_entries})
        v3 = corr3["manifest"]["id"]
        req("POST", f"/manifests/{v3}/seal",
            {"operator": "bob", "acknowledge_issues": True,
             "occurred_at": "2026-09-02T10:00:00+08:00"})

        bad_verify = [
            {"path": "a/File.dat", "size": 10, "sha256": h("f1")},
            {"path": "y", "size": 1, "sha256": h("y")},
            # corrected.log 被改名（同哈希）
            {"path": "renamed/corrected_rename.log", "size": 100, "sha256": h("c1")},
            # tampered.bin 内容变化 + 第 2 块损坏
            {"path": "new/tampered.bin", "size": 16384, "sha256": h("tampered"),
             "chunk_size": 4096, "chunk_hashes": bad_chunks,
             "mtime": "2027-01-01T00:00:00+08:00"},
        ]
        vb = req("POST", f"/manifests/{v3}/verify/metadata",
                 {"mode": "metadata",
                  "collected_at": "2026-09-03T10:00:00+08:00",
                  "timezone": "Asia/Shanghai", "entries": bad_verify})
        check("改名高置信候选（哈希一致）",
              any(c["same_sha256"] and c["confidence"] == "high"
                  and c["old_path"] == "new/corrected.log"
                  for c in vb["rename_candidates"]))
        check("改名不计入无法解释的缺失/新增",
              all(a["path"] != "new/corrected.log" for a in vb["added_unexplained"])
              and "new/corrected.log" not in
              [m["path"] for m in vb["missing_unexplained"]])
        check("检测到内容变化", any(c["path"] == "new/tampered.bin" for c in vb["changed"]))
        cc = [c for c in vb["chunk_corruptions"] if c["path"] == "new/tampered.bin"][0]
        check("分块损坏范围 = 块2（字节 8192-12287）",
              cc["corrupt_ranges"] == [
                  {"start_chunk": 2, "end_chunk": 2,
                   "byte_range_hint": [8192, 12287]}],
              json.dumps(cc, ensure_ascii=False))
        check("时间异常（未来 mtime）",
              any(f["code"] == "MTIME_IN_FUTURE" for f in vb["time_anomalies"]))
        check("综合结论 FAIL", vb["verdict"] == "FAIL")
        check("审计链完好", vb["audit_chain"]["intact"] is True)

        # 交接/身份缺失检查针对 v1（交接记录挂在原始清单版本上）
        vc = req("POST", f"/manifests/{mid}/verify/hash-list",
                 {"mode": "hash_list",
                  "collected_at": "2026-09-03T11:00:00+08:00",
                  "timezone": "Asia/Shanghai",
                  "entries": [{"path": "a/File.dat", "sha256": h("f1")},
                              {"path": "a/ＦＩＬＥ.dat", "sha256": h("f2")},
                              {"path": "y", "sha256": h("y")}]})
        check("交接身份缺失被验证发现",
              any(f["code"] == "SIGNOFF_IDENTITY_MISSING"
                  for f in vc["custody_findings"]),
              json.dumps(vc["custody_findings"], ensure_ascii=False))

        print("[报告与导出]")
        rep = urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/api/v1/verifications/{vid}/report").read().decode()
        check("Markdown 报告可下载且含结论", "核验结论" in rep and "通过" in rep)
        pkg = req("GET", f"/manifests/{mid}/export")
        check("证据包含审计事件与链校验",
              pkg["audit_chain"]["intact"]
              and len(pkg["audit_events"]["custody"]) >= 2
              and pkg["canonical_manifest"] is not None
              and pkg["manifest_hash"],
              f"custody={len(pkg['audit_events']['custody'])}")

        print("[审计链]")
        chain = req("GET", "/audit/verify")
        check("全链重算完好", chain["intact"] and chain["event_count"] >= 8)
        evs = req("GET", "/audit/events?limit=1000")["events"]
        linked = all(
            evs[i]["event_hash"] == evs[i + 1]["prev_hash"]
            for i in range(len(evs) - 1))
        check("返回事件前后哈希依次相接", linked)

        print("[OpenAPI]")
        spec = json.loads(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/openapi.json").read())
        check("OpenAPI 文档存在且列出接口",
              "/api/v1/manifests" in spec["paths"]
              and any("verify" in p for p in spec["paths"]))

        print(f"\n结果：{PASS} 通过，{FAIL} 失败")
        return 1 if FAIL else 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
