# -*- coding: utf-8 -*-
"""接口级测试：pytest + FastAPI TestClient，每个测试独立临时数据库。"""
import hashlib

import pytest


def H(tag: str) -> str:
    return hashlib.sha256(("test:" + tag).encode()).hexdigest()


def make_manifest(client, entries=None, **over):
    body = {
        "case_no": "CASE-1", "evidence_id": "EV-1",
        "collected_at": "2026-09-01T09:00:00+08:00",
        "timezone": "Asia/Shanghai", "operator": "alice",
        "entries": entries if entries is not None else [
            {"path": "a.txt", "size": 10, "sha256": H("a")}],
    }
    body.update(over)
    r = client.post("/api/v1/manifests", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def seal(client, mid, **over):
    body = {"operator": "alice", "acknowledge_issues": True,
            "occurred_at": "2026-09-01T09:30:00+08:00"}
    body.update(over)
    r = client.post(f"/api/v1/manifests/{mid}/seal", json=body)
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------

def test_health_and_openapi(client):
    assert client.get("/health").json()["status"] == "ok"
    spec = client.get("/openapi.json").json()
    assert "/api/v1/manifests" in spec["paths"]


def test_bad_hash_rejected(client):
    r = client.post("/api/v1/manifests", json={
        "case_no": "C", "evidence_id": "E",
        "collected_at": "2026-09-01T09:00:00+08:00", "timezone": "Asia/Shanghai",
        "operator": "a",
        "entries": [{"path": "x", "size": 1, "sha256": "deadbeef"}]})
    assert r.status_code == 422


def test_naive_datetime_rejected(client):
    r = client.post("/api/v1/manifests", json={
        "case_no": "C", "evidence_id": "E", "collected_at": "2026-09-01T09:00:00",
        "timezone": "Asia/Shanghai", "operator": "a", "entries": []})
    assert r.status_code == 400


def test_unicode_casefold_ambiguity(client):
    created = make_manifest(client, entries=[
        {"path": "Docs/File.dat", "size": 10, "sha256": H("f1")},
        # 全角 + 大写：NFKC/casefold 后同路径，哈希不同 -> 歧义
        {"path": "Docs/ＦＩＬＥ.DAT", "size": 20, "sha256": H("f2")},
    ])
    issues = [i for e in created["manifest"]["entries"] for i in (e.get("issues") or [])]
    assert any(i["code"] == "AMBIGUOUS_PATH_CONTENT" for i in issues)


def test_hard_duplicate_rejected(client):
    created = make_manifest(client)
    mid = created["manifest"]["id"]
    r = client.post(f"/api/v1/manifests/{mid}/entries", json={
        "entries": [{"path": "A.TXT", "size": 10, "sha256": H("a")}]})
    assert r.status_code == 400  # 折叠路径相同且内容一致


def test_seal_immutable_and_correct_version(client):
    created = make_manifest(client)
    mid = created["manifest"]["id"]
    sealed = seal(client, mid)
    assert sealed["manifest"]["merkle_root"] and sealed["manifest"]["manifest_hash"]

    # 封存后追加/重复封存冲突
    assert client.post(f"/api/v1/manifests/{mid}/entries", json={
        "entries": [{"path": "b", "size": 1, "sha256": H("b")}]}).status_code == 409
    assert client.post(f"/api/v1/manifests/{mid}/seal", json={
        "operator": "a", "acknowledge_issues": True}).status_code == 409

    # 更正生成 v2，supersedes 回指 v1
    r = client.post(f"/api/v1/manifests/{mid}/correct", json={
        "operator": "bob", "reason": "补录",
        "entries": [{"path": "a.txt", "size": 10, "sha256": H("a")},
                    {"path": "b.txt", "size": 20, "sha256": H("b")}]})
    assert r.status_code == 200
    v2 = r.json()["manifest"]
    assert v2["lineage"][1]["version"] == 2
    assert v2["lineage"][1]["supersedes_id"] == mid


def test_seal_requires_ack_for_ambiguous(client):
    created = make_manifest(client, entries=[
        {"path": "a/x.dat", "size": 1, "sha256": H("1")},
        {"path": "a/X.DAT", "size": 2, "sha256": H("2")}])
    mid = created["manifest"]["id"]
    r = client.post(f"/api/v1/manifests/{mid}/seal", json={
        "operator": "a", "acknowledge_issues": False})
    assert r.status_code == 400


def test_custody_flow_and_identity_missing(client):
    mid = make_manifest(client)["manifest"]["id"]
    seal(client, mid)
    r = client.post(f"/api/v1/manifests/{mid}/handoffs", json={
        "from_party": "alice", "to_party": "bob",
        "occurred_at": "2026-09-01T10:00:00+08:00", "timezone": "Asia/Shanghai"})
    hid = r.json()["handoff"]["id"]

    # 时间倒置
    bad = client.post(f"/api/v1/handoffs/{hid}/signoff", json={
        "actor": "bob", "occurred_at": "2026-09-01T09:00:00+08:00",
        "timezone": "Asia/Shanghai"})
    assert bad.status_code == 400

    ok = client.post(f"/api/v1/handoffs/{hid}/signoff", json={
        "occurred_at": "2026-09-01T10:30:00+08:00",
        "timezone": "Asia/Shanghai"})
    assert ok.status_code == 200 and ok.json()["missing_identity"] is True
    # 重复签收
    again = client.post(f"/api/v1/handoffs/{hid}/signoff", json={
        "actor": "bob", "occurred_at": "2026-09-01T10:31:00+08:00",
        "timezone": "Asia/Shanghai"})
    assert again.status_code == 409


def test_verify_pass_and_full_diff(client):
    entries = [
        {"path": "a.txt", "size": 10, "sha256": H("a")},
        {"path": "big.bin", "size": 4 * 4096, "sha256": H("big"),
         "chunk_size": 4096, "chunk_hashes": [H(f"big{i}") for i in range(4)]},
    ]
    mid = make_manifest(client, entries=entries)["manifest"]["id"]
    seal(client, mid)

    # 一致验证
    ok = client.post(f"/api/v1/manifests/{mid}/verify/hash-list", json={
        "mode": "hash_list", "collected_at": "2026-09-02T09:00:00+08:00",
        "timezone": "Asia/Shanghai",
        "entries": [{"path": "a.txt", "sha256": H("a")},
                    {"path": "big.bin", "sha256": H("big")}]}).json()
    assert ok["verdict"] == "PASS"
    assert ok["merkle"]["baseline_root_sealed"] == ok["merkle"]["baseline_root_recomputed"]

    # 差异验证：a.txt 改名（同哈希）；big.bin 第 2 块损坏；新增恶意文件
    bad_chunks = [H(f"big{i}") for i in range(4)]
    bad_chunks[2] = H("evil")
    diff = client.post(f"/api/v1/manifests/{mid}/verify/metadata", json={
        "mode": "metadata", "collected_at": "2026-09-02T10:00:00+08:00",
        "timezone": "Asia/Shanghai",
        "entries": [
            {"path": "renamed/a.txt", "size": 10, "sha256": H("a")},
            {"path": "big.bin", "size": 4 * 4096, "sha256": H("big-evil"),
             "chunk_size": 4096, "chunk_hashes": bad_chunks},
            {"path": "evil.exe", "size": 999, "sha256": H("evil-file"),
             "mtime": "2030-01-01T00:00:00+08:00"},
        ]}).json()
    assert diff["verdict"] == "FAIL"
    assert any(c["same_sha256"] for c in diff["rename_candidates"])
    cc = diff["chunk_corruptions"][0]
    assert cc["corrupt_ranges"] == [
        {"start_chunk": 2, "end_chunk": 2, "byte_range_hint": [8192, 12287]}]
    assert any(f["code"] == "MTIME_IN_FUTURE" for f in diff["time_anomalies"])
    assert any(x["path"] == "evil.exe" for x in diff["added_unexplained"])


def test_merkle_tamper_detected(client):
    mid = make_manifest(client)["manifest"]["id"]
    seal(client, mid)
    # 绕过应用直接改库
    import sqlite3
    from app import database
    conn = database.get_conn()
    conn.execute("UPDATE entry SET sha256=? WHERE manifest_id=?",
                 (H("hacked"), mid))
    conn.commit()
    r = client.post(f"/api/v1/manifests/{mid}/verify/hash-list", json={
        "mode": "hash_list", "timezone": "Asia/Shanghai",
        "entries": [{"path": "a.txt", "sha256": H("a")}]}).json()
    assert any(f["code"] == "MERKLE_ROOT_MISMATCH" for f in r["merkle_findings"])
    assert r["verdict"] == "FAIL"


def test_audit_chain_links_and_immutable(client):
    mid = make_manifest(client)["manifest"]["id"]
    seal(client, mid)
    chain = client.get("/api/v1/audit/verify").json()
    assert chain["intact"]
    events = client.get("/api/v1/audit/events").json()["events"]
    assert events[0]["prev_hash"] == "0" * 64
    for a, b in zip(events, events[1:]):
        assert a["event_hash"] == b["prev_hash"]

    import sqlite3
    from app import database
    conn = database.get_conn()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE audit_event SET actor='x' WHERE seq=1")
    conn.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM audit_event WHERE seq=1")
    conn.rollback()


def test_export_and_report(client):
    mid = make_manifest(client)["manifest"]["id"]
    seal(client, mid)
    vr = client.post(f"/api/v1/manifests/{mid}/verify/hash-list", json={
        "mode": "hash_list", "timezone": "Asia/Shanghai",
        "entries": [{"path": "a.txt", "sha256": H("a")}]}).json()
    pkg = client.get(f"/api/v1/manifests/{mid}/export").json()
    assert pkg["manifest_hash"] and pkg["audit_chain"]["intact"]
    rep = client.get(f"/api/v1/verifications/{vr['verification_id']}/report")
    assert rep.status_code == 200 and "核验结论" in rep.text
