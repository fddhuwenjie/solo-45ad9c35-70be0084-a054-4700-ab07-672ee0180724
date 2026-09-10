# -*- coding: utf-8 -*-
"""业务操作层：清单生命周期、交接签收、验证比对、导出。"""
from __future__ import annotations

import difflib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import audit, models
from .crypto import (
    canonical_dumps,
    corrupt_chunk_ranges,
    fold_key,
    leaf_hash,
    merkle_root,
    sha256_hex,
)
from .database import get_conn, row_to_dict
from .timeutil import local_iso, parse_dt, to_utc_iso, utc_now_iso, validate_timezone


# ---------------------------------------------------------------------------
# 读取辅助
# ---------------------------------------------------------------------------

def _get_manifest_row(manifest_id: str):
    row = get_conn().execute(
        "SELECT * FROM manifest WHERE id = ?", (manifest_id,)
    ).fetchone()
    if not row:
        raise models.NotFound(f"清单 {manifest_id} 不存在")
    return row


def get_manifest(manifest_id: str) -> Dict[str, Any]:
    row = _get_manifest_row(manifest_id)
    m = row_to_dict(row)
    m["entries"] = list_entries(manifest_id)
    m["handoffs"] = list_handoffs(manifest_id)
    m["lineage"] = get_lineage(m["lineage_id"])
    return m


def list_entries(manifest_id: str) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT seq, path, size, sha256, chunk_size, chunk_hashes, mtime, issues "
        "FROM entry WHERE manifest_id = ? ORDER BY seq ASC", (manifest_id,)
    ).fetchall()
    out = []
    for r in rows:
        e = row_to_dict(r)
        e["leaf_hash"] = leaf_hash({
            "path": e["path"], "size": e["size"], "sha256": e["sha256"],
            "chunk_size": e.get("chunk_size"),
            "chunk_hashes": e.get("chunk_hashes") or [],
            "mtime": e.get("mtime"),
        })
        out.append(e)
    return out


def list_handoffs(manifest_id: str) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT * FROM handoff WHERE manifest_id = ? ORDER BY seq ASC", (manifest_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_lineage(lineage_id: str) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT id, version, supersedes_id, status, case_no, evidence_id, "
        "merkle_root, entry_count, created_at, sealed_at, manifest_hash "
        "FROM manifest WHERE lineage_id = ? ORDER BY version ASC",
        (lineage_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def list_manifests(case_no: Optional[str] = None, evidence_id: Optional[str] = None,
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
    sql = ("SELECT id, lineage_id, version, supersedes_id, case_no, evidence_id, "
           "status, merkle_root, entry_count, created_at, sealed_at FROM manifest WHERE 1=1")
    params: List[Any] = []
    if case_no:
        sql += " AND case_no = ?"; params.append(case_no)
    if evidence_id:
        sql += " AND evidence_id = ?"; params.append(evidence_id)
    if status:
        sql += " AND status = ?"; params.append(status)
    sql += " ORDER BY created_at DESC, version DESC"
    return [dict(r) for r in get_conn().execute(sql, params).fetchall()]


# ---------------------------------------------------------------------------
# 条目写入
# ---------------------------------------------------------------------------

def _normalize_inputs(entries: List[Any]) -> List[Dict[str, Any]]:
    return [models.normalize_entry(models.entry_payload(e)) for e in entries]


def _insert_entries(manifest_id: str, tagged: List[Dict[str, Any]], start_seq: int) -> None:
    conn = get_conn()
    for offset, e in enumerate(tagged):
        conn.execute(
            """INSERT INTO entry
               (manifest_id, seq, path, path_fold, size, sha256,
                chunk_size, chunk_hashes, mtime, issues)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (manifest_id, start_seq + offset, e["path"], e["path_fold"],
             e["size"], e["sha256"], e.get("chunk_size"),
             json.dumps(e.get("chunk_hashes") or [], ensure_ascii=False),
             e.get("mtime"),
             json.dumps(e.get("issues") or [], ensure_ascii=False)),
        )


def _recompute_live(manifest_id: str) -> Tuple[Optional[str], int]:
    entries = list_entries(manifest_id)
    leaves = [e["leaf_hash"] for e in entries]
    return merkle_root(leaves), len(entries)


# ---------------------------------------------------------------------------
# 创建清单
# ---------------------------------------------------------------------------

def create_manifest(data: Any) -> Dict[str, Any]:
    validate_timezone(data.timezone)
    collected_dt = parse_dt(data.collected_at, "采集时间")

    norm = _normalize_inputs(data.entries)
    # 仅在本批提交内识别硬重复/歧义；跨版本核对交由 verify 接口
    tagged, rejected = models.scan_entries(norm, [])
    if rejected:
        raise models.DomainError(
            "存在硬重复条目，已拒绝：" + json.dumps(rejected, ensure_ascii=False)
        )

    conn = get_conn()
    manifest_id = uuid.uuid4().hex
    now = utc_now_iso()
    meta = {
        "case_no": data.case_no.strip(),
        "evidence_id": data.evidence_id.strip(),
        "collected_at": to_utc_iso(collected_dt),
        "timezone": data.timezone,
        "operator": data.operator.strip(),
        "note": data.note,
    }
    conn.execute(
        """INSERT INTO manifest
           (id, lineage_id, version, supersedes_id, case_no, evidence_id,
            collected_at, timezone, operator, note, status, entry_count, created_at)
           VALUES (?,?,?,NULL,?,?,?,?,?,?,'open',0,?)""",
        (manifest_id, manifest_id, 1, meta["case_no"], meta["evidence_id"],
         meta["collected_at"], meta["timezone"], meta["operator"], meta["note"], now),
    )
    _insert_entries(manifest_id, tagged, 1)
    root, count = _recompute_live(manifest_id)
    conn.execute("UPDATE manifest SET entry_count = ? WHERE id = ?", (count, manifest_id))

    ev = audit.append_event(
        "manifest.create", "manifest", manifest_id,
        {"meta": meta, "entry_count": count, "merkle_root_unsealed": root,
         "ambiguous_entries": [e for e in tagged if e.get("issues")]},
        actor=meta["operator"], commit=False,
    )
    conn.commit()
    return {"manifest": get_manifest(manifest_id), "audit": ev,
            "rejected_duplicates": rejected}


# ---------------------------------------------------------------------------
# 追加条目
# ---------------------------------------------------------------------------

def append_entries(manifest_id: str, data: Any) -> Dict[str, Any]:
    m = row_to_dict(_get_manifest_row(manifest_id))
    if m["status"] != "open":
        raise models.Conflict(
            f"清单 {manifest_id} 已封存，不可追加；如需更正请调用 /correct 生成新版本"
        )

    norm = _normalize_inputs(data.entries)
    existing = [
        {"path": e["path"], "path_fold": fold_key(e["path"]),
         "size": e["size"], "sha256": e["sha256"]}
        for e in list_entries(manifest_id)
    ]
    tagged, rejected = models.scan_entries(norm, existing)
    if rejected:
        raise models.DomainError(
            "存在硬重复条目，已拒绝：" + json.dumps(rejected, ensure_ascii=False)
        )

    conn = get_conn()
    next_seq = m["entry_count"] + 1
    _insert_entries(manifest_id, tagged, next_seq)
    root, count = _recompute_live(manifest_id)
    conn.execute("UPDATE manifest SET entry_count = ? WHERE id = ?", (count, manifest_id))
    ev = audit.append_event(
        "manifest.append", "manifest", manifest_id,
        {"added": [{"path": e["path"], "sha256": e["sha256"]} for e in tagged],
         "entry_count": count, "merkle_root_unsealed": root},
        actor=data.operator or m["operator"], commit=False,
    )
    conn.commit()
    return {"manifest": get_manifest(manifest_id), "audit": ev,
            "rejected_duplicates": rejected}


# ---------------------------------------------------------------------------
# 封存
# ---------------------------------------------------------------------------

def _collect_entries_for_seal(manifest_id: str) -> List[Dict[str, Any]]:
    return list_entries(manifest_id)


def seal_manifest(manifest_id: str, data: Any) -> Dict[str, Any]:
    m = row_to_dict(_get_manifest_row(manifest_id))
    if m["status"] == "sealed":
        raise models.Conflict("清单已封存，不可重复封存")

    entries = list_entries(manifest_id)
    if not entries:
        raise models.Conflict("空清单不可封存")

    ambiguous = [
        {"seq": e["seq"], "path": e["path"], "issues": e["issues"]}
        for e in entries
        if any(i.get("severity") == "warning" for i in (e.get("issues") or []))
    ]
    if ambiguous and not data.acknowledge_issues:
        raise models.DomainError(
            "存在路径歧义（大小写/Unicode 归一化冲突）条目，"
            "须由操作者确认后在请求中置 acknowledge_issues=true："
            + json.dumps(ambiguous, ensure_ascii=False)
        )

    meta = {
        "case_no": m["case_no"], "evidence_id": m["evidence_id"],
        "collected_at": m["collected_at"], "timezone": m["timezone"],
        "operator": m["operator"], "note": m["note"],
    }
    canonical = models.build_canonical_manifest(meta, entries)
    canonical_text = canonical_dumps(canonical)
    manifest_hash = sha256_hex(canonical_text.encode("utf-8"))
    root = canonical["merkle_tree"]["root"]

    conn = get_conn()
    now = to_utc_iso(parse_dt(data.occurred_at, "封存时间")) if getattr(
        data, "occurred_at", None) else utc_now_iso()
    if getattr(data, "occurred_at", None):
        validate_timezone(getattr(data, "timezone", "Asia/Shanghai"))
    if now < m["collected_at"]:
        raise models.DomainError("封存时间早于采集时间，时间倒置")
    conn.execute(
        """UPDATE manifest SET status='sealed', merkle_root=?, canonical_json=?,
               manifest_hash=?, sealed_at=?, acknowledged_issues=?
           WHERE id=?""",
        (root, canonical_text, manifest_hash, now,
         json.dumps(ambiguous, ensure_ascii=False), manifest_id),
    )
    ev = audit.append_event(
        "manifest.seal", "manifest", manifest_id,
        {"manifest_hash": manifest_hash, "merkle_root": root,
         "entry_count": len(entries), "acknowledged_issues": ambiguous,
         "seal_operator": data.operator, "note": data.note},
        actor=data.operator, commit=False,
    )
    conn.commit()
    result = get_manifest(manifest_id)
    result["manifest_hash"] = manifest_hash
    result["canonical"] = canonical
    return {"manifest": result, "audit": ev}


# ---------------------------------------------------------------------------
# 更正 -> 新版本
# ---------------------------------------------------------------------------

def correct_manifest(manifest_id: str, data: Any) -> Dict[str, Any]:
    old = row_to_dict(_get_manifest_row(manifest_id))
    if old["status"] != "sealed":
        raise models.Conflict("仅已封存清单可发起更正（开放清单可直接追加/修改条目）")

    tz = data.timezone or old["timezone"]
    validate_timezone(tz)
    collected_iso = old["collected_at"]
    if data.collected_at:
        collected_iso = to_utc_iso(parse_dt(data.collected_at, "采集时间"))

    norm = _normalize_inputs(data.entries)
    tagged, rejected = models.scan_entries(norm, [])
    if rejected:
        raise models.DomainError(
            "更正条目中存在硬重复：" + json.dumps(rejected, ensure_ascii=False)
        )

    conn = get_conn()
    new_id = uuid.uuid4().hex
    new_version = int(
        conn.execute("SELECT COALESCE(MAX(version),0)+1 AS v FROM manifest WHERE lineage_id=?",
                     (old["lineage_id"],)).fetchone()["v"]
    )
    now = utc_now_iso()
    meta = {
        "case_no": (data.case_no or old["case_no"]).strip(),
        "evidence_id": (data.evidence_id or old["evidence_id"]).strip(),
        "collected_at": collected_iso,
        "timezone": tz,
        "operator": data.operator.strip(),
        "note": data.note,
    }
    conn.execute(
        """INSERT INTO manifest
           (id, lineage_id, version, supersedes_id, case_no, evidence_id,
            collected_at, timezone, operator, note, status, entry_count, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?)""",
        (new_id, old["lineage_id"], new_version, manifest_id,
         meta["case_no"], meta["evidence_id"], meta["collected_at"],
         meta["timezone"], meta["operator"], meta["note"], len(tagged), now),
    )
    _insert_entries(new_id, tagged, 1)
    root, count = _recompute_live(new_id)
    conn.execute("UPDATE manifest SET entry_count=? WHERE id=?", (count, new_id))
    ev = audit.append_event(
        "manifest.correct", "manifest", new_id,
        {"supersedes_id": manifest_id, "lineage_id": old["lineage_id"],
         "new_version": new_version, "reason": data.reason,
         "entry_count": count, "merkle_root_unsealed": root,
         "operator": data.operator},
        actor=data.operator, commit=False,
    )
    conn.commit()
    return {"manifest": get_manifest(new_id), "audit": ev,
            "supersedes_id": manifest_id, "reason": data.reason,
            "rejected_duplicates": rejected}


# ---------------------------------------------------------------------------
# 交接 / 签收
# ---------------------------------------------------------------------------

def _next_handoff_seq(conn, manifest_id: str) -> int:
    r = conn.execute(
        "SELECT COALESCE(MAX(seq),0)+1 AS s FROM handoff WHERE manifest_id=?",
        (manifest_id,),
    ).fetchone()
    return int(r["s"])


def create_handoff(manifest_id: str, data: Any) -> Dict[str, Any]:
    m = row_to_dict(_get_manifest_row(manifest_id))
    if m["status"] != "sealed":
        raise models.Conflict("仅已封存清单可以发起交接")
    validate_timezone(data.timezone)
    occurred = to_utc_iso(parse_dt(data.occurred_at, "交接时间"))

    conn = get_conn()
    # 交接时间不得早于封存时间
    if occurred < m["sealed_at"]:
        raise models.DomainError("交接时间早于封存时间，时间倒置")
    # 与上一交接/签收事件比较
    last = conn.execute(
        "SELECT occurred_at, event_type, seq FROM handoff WHERE manifest_id=? "
        "ORDER BY seq DESC LIMIT 1", (manifest_id,)).fetchone()
    if last and occurred < last["occurred_at"]:
        raise models.DomainError(
            f"交接时间早于上一事件（seq={last['seq']} {last['event_type']}），时间倒置")

    hid = uuid.uuid4().hex
    seq = _next_handoff_seq(conn, manifest_id)
    conn.execute(
        """INSERT INTO handoff
           (id, manifest_id, seq, event_type, from_party, to_party, actor,
            actor_id_no, occurred_at, timezone, note, created_at)
           VALUES (?,?,?, 'handoff', ?,?,?, NULL,?,?,?,?)""",
        (hid, manifest_id, seq, data.from_party.strip(), data.to_party.strip(),
         None, occurred, data.timezone, data.note, utc_now_iso()),
    )
    ev = audit.append_event(
        "custody.handoff", "handoff", hid,
        {"manifest_id": manifest_id, "seq": seq,
         "from_party": data.from_party, "to_party": data.to_party,
         "occurred_at": occurred},
        actor=data.from_party, commit=False,
    )
    conn.commit()
    return {"handoff": dict(conn.execute(
        "SELECT * FROM handoff WHERE id=?", (hid,)).fetchone()),
        "audit": ev}


def signoff(handoff_id: str, data: Any) -> Dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM handoff WHERE id=?", (handoff_id,)).fetchone()
    if not row:
        raise models.NotFound(f"交接记录 {handoff_id} 不存在")
    h = dict(row)
    if h["event_type"] != "handoff":
        raise models.Conflict("仅 handoff 记录可执行签收")
    existing = conn.execute(
        "SELECT id FROM handoff WHERE manifest_id=? AND event_type='signoff' AND seq=?",
        (h["manifest_id"], h["seq"] + 1)).fetchone()
    if existing:
        raise models.Conflict("该交接已存在签收记录，不能重复签收")
    validate_timezone(data.timezone)
    occurred = to_utc_iso(parse_dt(data.occurred_at, "签收时间"))

    if occurred < h["occurred_at"]:
        raise models.DomainError("签收时间早于对应交接时间，时间倒置")
    later = conn.execute(
        "SELECT MIN(occurred_at) AS t FROM handoff WHERE manifest_id=? AND seq > ?",
        (h["manifest_id"], h["seq"])).fetchone()
    if later["t"] and occurred > later["t"]:
        raise models.DomainError("签收时间晚于其后的交接事件，签收时间倒置")

    actor = (data.actor or "").strip() or None
    signoff_id = uuid.uuid4().hex
    conn.execute(
        """INSERT INTO handoff
           (id, manifest_id, seq, event_type, from_party, to_party, actor,
            actor_id_no, occurred_at, timezone, note, created_at)
           VALUES (?,?,?, 'signoff', ?,?,?, ?,?,?,?,?)""",
        (signoff_id, h["manifest_id"], h["seq"] + 1,
         h["from_party"], h["to_party"], actor,
         (data.actor_id_no or None), occurred, data.timezone,
         data.note, utc_now_iso()),
    )
    missing_identity = actor is None
    ev = audit.append_event(
        "custody.signoff", "handoff", handoff_id,
        {"manifest_id": h["manifest_id"], "handoff_seq": h["seq"],
         "signoff_seq": h["seq"] + 1, "signoff_id": signoff_id,
         "actor": actor, "actor_id_no": data.actor_id_no,
         "occurred_at": occurred, "missing_identity": missing_identity},
        actor=actor, commit=False,
    )
    conn.commit()
    return {
        "handoff_id": handoff_id,
        "signoff": dict(conn.execute(
            "SELECT * FROM handoff WHERE id=?", (signoff_id,)).fetchone()),
        "missing_identity": missing_identity,
        "audit": ev,
    }


# ---------------------------------------------------------------------------
# 验证
# ---------------------------------------------------------------------------

def _norm_verify_entries(entries: List[Any]) -> List[Dict[str, Any]]:
    out = []
    for e in entries:
        d = e.model_dump(exclude_none=True) if hasattr(e, "model_dump") else (
            e if isinstance(e, dict) else vars(e))
        ne = models.normalize_entry({
            "path": d["path"],
            "size": d.get("size", 0),
            "sha256": d["sha256"],
            "chunk_size": d.get("chunk_size"),
            "chunk_hashes": d.get("chunk_hashes"),
            "mtime": d.get("mtime"),
        })
        if d.get("size") is None:
            ne["size"] = None  # hash_list 模式可能无字节数
        out.append(ne)
    return out


def _verify_custody(manifest_id: str) -> List[Dict[str, Any]]:
    """交接顺序 / 签收倒置 / 身份缺失检查。"""
    findings: List[Dict[str, Any]] = []
    hs = list_handoffs(manifest_id)
    prev_time: Optional[str] = None
    handoff_pending: Optional[Dict[str, Any]] = None
    last_to: Optional[str] = None
    for h in hs:
        if prev_time and h["occurred_at"] < prev_time:
            findings.append({
                "code": "CHAIN_TIME_INVERSION", "severity": "critical",
                "message": f"交接事件 seq={h['seq']} 时间早于前一事件",
                "seq": h["seq"],
            })
        prev_time = h["occurred_at"]

        if h["event_type"] == "handoff":
            if not h["from_party"] or not h["to_party"]:
                findings.append({
                    "code": "CUSTODY_PARTY_MISSING", "severity": "high",
                    "message": f"seq={h['seq']} 交接方信息不完整", "seq": h["seq"]})
            if handoff_pending is not None:
                findings.append({
                    "code": "CUSTODY_UNSIGNED_HANDOFF", "severity": "high",
                    "message": f"seq={handoff_pending['seq']} 的交接在未签收前发生了下一次交接",
                    "seq": handoff_pending["seq"]})
            if last_to is not None and h["from_party"] != last_to:
                findings.append({
                    "code": "CUSTODY_PARTY_DISCONTINUITY", "severity": "warning",
                    "message": f"seq={h['seq']} 交出方 {h['from_party']!r} 与上次接收方 "
                               f"{last_to!r} 不一致", "seq": h["seq"]})
            handoff_pending = h
        elif h["event_type"] == "signoff":
            if not h["actor"]:
                findings.append({
                    "code": "SIGNOFF_IDENTITY_MISSING", "severity": "high",
                    "message": f"seq={h['seq']} 签收缺少实际签收人身份", "seq": h["seq"]})
            if h["occurred_at"] < _find_handoff_time(hs, h["seq"]):
                findings.append({
                    "code": "SIGNOFF_TIME_INVERSION", "severity": "critical",
                    "message": f"seq={h['seq']} 签收时间早于交接时间", "seq": h["seq"]})
            last_to = h["to_party"]
            handoff_pending = None
    if handoff_pending is not None:
        findings.append({
            "code": "CUSTODY_AWAITING_SIGNOFF", "severity": "info",
            "message": f"seq={handoff_pending['seq']} 已交接但尚未签收",
            "seq": handoff_pending["seq"]})
    return findings


def _find_handoff_time(hs: List[Dict[str, Any]], signoff_seq: int) -> str:
    for h in hs:
        if h["event_type"] == "handoff" and h["seq"] == signoff_seq - 1:
            return h["occurred_at"]
    return "9999"


def verify_manifest(manifest_id: str, data: Any) -> Dict[str, Any]:
    m = row_to_dict(_get_manifest_row(manifest_id))
    tz = data.timezone or m["timezone"]
    validate_timezone(tz)
    recollected_utc = None
    if data.collected_at:
        recollected_utc = to_utc_iso(parse_dt(data.collected_at, "重新采集时间"))

    baseline = list_entries(manifest_id)
    observed = _norm_verify_entries(data.entries)
    mode = getattr(data, "mode", "metadata")

    base_by_fold = {fold_key(e["path"]): e for e in baseline}
    obs_by_fold = {fold_key(e["path"]): e for e in observed}

    added: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []
    unchanged: List[str] = []
    rename_candidates: List[Dict[str, Any]] = []
    time_anomalies: List[Dict[str, Any]] = []
    chunk_corruptions: List[Dict[str, Any]] = []
    metadata_anomalies: List[Dict[str, Any]] = []

    # 1) 内容变化 / 元数据变化（折叠键匹配）
    for key, oe in obs_by_fold.items():
        be = base_by_fold.get(key)
        if not be:
            continue
        if be["sha256"] != oe["sha256"]:
            changed.append({
                "path": oe["path"], "baseline_path": be["path"],
                "baseline_sha256": be["sha256"], "observed_sha256": oe["sha256"],
            })
        else:
            unchanged.append(oe["path"])
            if mode == "metadata":
                if oe["size"] is not None and be["size"] != oe["size"]:
                    metadata_anomalies.append({
                        "code": "SIZE_MISMATCH", "severity": "high",
                        "path": oe["path"], "baseline_size": be["size"],
                        "observed_size": oe["size"],
                        "message": "SHA-256 相同但字节数不一致，元数据异常"})
                if oe.get("mtime") and be.get("mtime") and oe["mtime"] != be["mtime"]:
                    metadata_anomalies.append({
                        "code": "MTIME_MISMATCH", "severity": "warning",
                        "path": oe["path"], "baseline_mtime": be["mtime"],
                        "observed_mtime": oe["mtime"],
                        "message": "内容哈希一致但修改时间变化（可能为时间戳被篡改或复制时重写）"})
        # 分块损坏范围（哈希相同或不同都要报具体块）
        if be.get("chunk_hashes") and oe.get("chunk_hashes"):
            ranges = corrupt_chunk_ranges(be["chunk_hashes"], oe["chunk_hashes"])
            if ranges:
                chunk_corruptions.append({
                    "path": oe["path"],
                    "chunk_size": oe.get("chunk_size") or be.get("chunk_size"),
                    "corrupt_ranges": [
                        {"start_chunk": a, "end_chunk": b,
                         "byte_range_hint": [
                             a * (oe.get("chunk_size") or be.get("chunk_size") or 0),
                             (b + 1) * (oe.get("chunk_size") or be.get("chunk_size") or 0) - 1]}
                        for a, b in ranges],
                    "baseline_chunk_count": len(be["chunk_hashes"]),
                    "observed_chunk_count": len(oe["chunk_hashes"]),
                })

    # 2) 新增 / 缺失（按折叠键）
    added_keys = set()
    for oe in observed:
        if fold_key(oe["path"]) not in base_by_fold:
            added.append({"path": oe["path"], "sha256": oe["sha256"],
                          "size": oe["size"]})
            added_keys.add(oe["path"])
    for be in baseline:
        if fold_key(be["path"]) not in obs_by_fold:
            missing.append({"path": be["path"], "sha256": be["sha256"],
                            "size": be["size"]})

    # 3) 改名候选：缺失条目 × 新增条目，哈希相同直接强候选；否则路径相似度
    strong_pairs: List[Tuple[str, str]] = []
    for miss in missing:
        for add in added:
            score = difflib.SequenceMatcher(
                None, miss["path"].lower(), add["path"].lower()).ratio()
            strong = miss["sha256"] == add["sha256"]
            if strong or score >= 0.6:
                rename_candidates.append({
                    "old_path": miss["path"], "new_path": add["path"],
                    "confidence": "high" if strong else ("medium" if score >= 0.75 else "low"),
                    "similarity": round(score, 3),
                    "same_sha256": strong,
                })
            if strong:
                strong_pairs.append((miss["path"], add["path"]))

    # 强改名候选（哈希一致）只算“改名”，不再计入无法解释的新增/缺失
    renamed_paths = {p for pair in strong_pairs for p in pair}
    added_unexplained = [a for a in added if a["path"] not in renamed_paths]
    missing_unexplained = [mi for mi in missing if mi["path"] not in renamed_paths]
    unexplained_anomalies: List[Dict[str, Any]] = [
        {"code": "UNEXPLAINED_ADD", "severity": "high",
         "path": a["path"], "message": "重采数据出现基线中不存在的文件（且无哈希一致的改名候选）"}
        for a in added_unexplained] + [
        {"code": "UNEXPLAINED_MISSING", "severity": "high",
         "path": mi["path"], "message": "基线文件在重采数据中缺失（且无哈希一致的改名候选）"}
        for mi in missing_unexplained]

    # 4) 时间异常
    now_iso = utc_now_iso()
    if recollected_utc:
        if recollected_utc < m["collected_at"]:
            time_anomalies.append({
                "code": "RECOLLECT_BEFORE_COLLECT", "severity": "critical",
                "message": "重新采集时间早于证物原始采集时间"})
        if recollected_utc > now_iso:
            time_anomalies.append({
                "code": "COLLECT_TIME_IN_FUTURE", "severity": "high",
                "message": "重新采集时间晚于当前时间"})
    for oe in observed:
        mt = oe.get("mtime")
        if not mt:
            continue
        if mt > now_iso:
            time_anomalies.append({
                "code": "MTIME_IN_FUTURE", "severity": "warning", "path": oe["path"],
                "mtime": mt, "message": "文件修改时间晚于当前时间"})
        if recollected_utc and mt > recollected_utc:
            time_anomalies.append({
                "code": "MTIME_AFTER_COLLECT", "severity": "warning", "path": oe["path"],
                "mtime": mt, "message": "文件修改时间晚于重新采集时间"})

    # 5) 重算 Merkle 根 + lineage 链 + 审计链 + 交接
    recomputed_leaves = [leaf_hash({
        "path": e["path"], "size": e["size"], "sha256": e["sha256"],
        "chunk_size": e.get("chunk_size"),
        "chunk_hashes": e.get("chunk_hashes") or [],
        "mtime": e.get("mtime")}) for e in baseline]
    recomputed_root = merkle_root(recomputed_leaves)
    merkle_findings: List[Dict[str, Any]] = []
    if m["status"] == "sealed":
        if recomputed_root != m["merkle_root"]:
            merkle_findings.append({
                "code": "MERKLE_ROOT_MISMATCH", "severity": "critical",
                "expected": m["merkle_root"], "recomputed": recomputed_root,
                "message": "清单条目重算 Merkle 根与封存值不一致，清单可能被篡改"})
        # 规范化字节与 manifest_hash 复验
        if m.get("canonical_json"):
            ok_hash = sha256_hex(m["canonical_json"].encode("utf-8")) == m["manifest_hash"]
            if not ok_hash:
                merkle_findings.append({
                    "code": "MANIFEST_HASH_MISMATCH", "severity": "critical",
                    "message": "规范化清单字节哈希与封存 manifest_hash 不一致"})
    else:
        merkle_findings.append({
            "code": "MANIFEST_UNSEALED", "severity": "info",
            "merkle_root_live": recomputed_root,
            "message": "清单尚未封存，Merkle 根为活值，不构成封存证据"})

    lineage_findings = _verify_lineage_links(m)
    chain = audit.verify_chain()
    if not chain["intact"]:
        merkle_findings.append({
            "code": "AUDIT_CHAIN_BROKEN", "severity": "critical",
            "breaks": chain["breaks"],
            "message": "审计哈希链断裂"})
    custody_findings = _verify_custody(manifest_id)

    # 观测侧自身的 Merkle 根（便于比对采集工具输出）
    observed_leaves = [leaf_hash({
        "path": e["path"], "size": e.get("size") or 0, "sha256": e["sha256"],
        "chunk_size": e.get("chunk_size"),
        "chunk_hashes": e.get("chunk_hashes") or [],
        "mtime": e.get("mtime")}) for e in observed]
    observed_root = merkle_root(observed_leaves)

    result = {
        "manifest_id": manifest_id,
        "lineage_id": m["lineage_id"],
        "version": _manifest_version(m),
        "status": m["status"],
        "mode": mode,
        "timezone": tz,
        "recollected_at": recollected_utc,
        "counts": {
            "baseline_entries": len(baseline),
            "observed_entries": len(observed),
            "added": len(added),
            "missing": len(missing),
            "unexplained_added": len(added_unexplained),
            "unexplained_missing": len(missing_unexplained),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "rename_candidates": len(rename_candidates),
            "time_anomalies": len(time_anomalies),
            "chunk_corruptions": len(chunk_corruptions),
            "metadata_anomalies": len(metadata_anomalies),
            "unexplained_anomalies": len(unexplained_anomalies),
            "custody_findings": len(custody_findings),
            "merkle_findings": len(merkle_findings),
            "lineage_findings": len(lineage_findings),
        },
        "added": added,
        "missing": missing,
        "added_unexplained": added_unexplained,
        "missing_unexplained": missing_unexplained,
        "rename_candidates": rename_candidates,
        "changed": changed,
        "unchanged": unchanged,
        "time_anomalies": time_anomalies,
        "chunk_corruptions": chunk_corruptions,
        "metadata_anomalies": metadata_anomalies,
        "unexplained_anomalies": unexplained_anomalies,
        "custody_findings": custody_findings,
        "lineage_findings": lineage_findings,
        "merkle_findings": merkle_findings,
        "merkle": {
            "baseline_root_sealed": m["merkle_root"],
            "baseline_root_recomputed": recomputed_root,
            "observed_root": observed_root,
            "baseline_leaves": recomputed_leaves,
        },
        "audit_chain": {"intact": chain["intact"], "event_count": chain["event_count"],
                        "last_event_hash": chain["last_event_hash"],
                        "breaks": chain["breaks"]},
        "verdict": _verdict(
            [{"severity": "critical"} for _ in changed],
            unexplained_anomalies, time_anomalies, chunk_corruptions,
            metadata_anomalies, custody_findings, merkle_findings,
            lineage_findings),
    }

    conn = get_conn()
    vid = uuid.uuid4().hex
    ev = audit.append_event(
        "verification.run", "verification", vid,
        {"manifest_id": manifest_id, "mode": mode,
         "counts": result["counts"], "verdict": result["verdict"],
         "observed_root": observed_root},
        actor=getattr(data, "operator", None), commit=False,
    )
    conn.execute(
        "INSERT INTO verification (id, manifest_id, mode, created_at, collected_at, "
        "summary, result, audit_event_id) VALUES (?,?,?,?,?,?,?,?)",
        (vid, manifest_id, mode, utc_now_iso(), recollected_utc,
         json.dumps({"counts": result["counts"], "verdict": result["verdict"]},
                    ensure_ascii=False),
         json.dumps(result, ensure_ascii=False), ev["event_id"]),
    )
    conn.commit()
    result["verification_id"] = vid
    result["audit"] = ev
    return result


def _manifest_version(m: Dict[str, Any]) -> int:
    r = get_conn().execute(
        "SELECT version FROM manifest WHERE id=?", (m["id"],)).fetchone()
    return r["version"]


def _verify_lineage_links(m: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    rows = get_conn().execute(
        "SELECT * FROM manifest WHERE lineage_id=? ORDER BY version ASC",
        (m["lineage_id"],)).fetchall()
    prev: Optional[Any] = None
    for r in rows:
        d = row_to_dict(r)
        if d["version"] == 1:
            if d["supersedes_id"] is not None:
                findings.append({"code": "LINEAGE_BAD_ROOT", "severity": "high",
                                 "id": d["id"], "message": "v1 不应有前驱版本"})
        else:
            if not d["supersedes_id"] or (prev and d["supersedes_id"] != prev["id"]):
                findings.append({"code": "LINEAGE_LINK_BROKEN", "severity": "critical",
                                 "id": d["id"], "message": "版本 supersede 链接断裂"})
            if prev and prev["status"] != "sealed":
                findings.append({"code": "LINEAGE_UNSEALED_PARENT", "severity": "high",
                                 "id": d["id"], "message": "更正链中前驱版本未封存"})
        prev = d
    return findings


def _verdict(*finding_groups) -> str:
    critical = 0
    warnings = 0
    for group in finding_groups:
        for f in group:
            sev = f.get("severity") if isinstance(f, dict) else None
            if sev in ("critical", "high"):
                critical += 1
            elif sev == "warning":
                warnings += 1
    if critical:
        return "FAIL"
    if warnings:
        return "PASS_WITH_WARNINGS"
    return "PASS"


# ---------------------------------------------------------------------------
# 导出证据包 / 报告
# ---------------------------------------------------------------------------

def build_evidence_package(manifest_id: str) -> Dict[str, Any]:
    m = get_manifest(manifest_id)
    row = row_to_dict(_get_manifest_row(manifest_id))
    canonical = None
    if row.get("canonical_json"):
        canonical = json.loads(row["canonical_json"])

    conn = get_conn()
    lineage_ids = [v["id"] for v in get_lineage(m["lineage_id"])]
    # handoff 事件 object_id = handoff 行 id；signoff 事件 object_id 同样回指其 handoff id
    handoff_ids = [h["id"] for h in m["handoffs"] if h["event_type"] == "handoff"]
    verifications = [dict(r) for r in conn.execute(
        "SELECT id, mode, created_at, collected_at, summary, audit_event_id "
        "FROM verification WHERE manifest_id=? ORDER BY created_at ASC",
        (manifest_id,)).fetchall()]
    for v in verifications:
        v["summary"] = json.loads(v["summary"])
    verification_ids = [v["id"] for v in verifications]

    def _fetch(object_type: str, ids: List[str]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM audit_event WHERE object_type=? AND object_id IN ({marks}) "
            "ORDER BY seq ASC", [object_type, *ids]).fetchall()]

    manifest_events = _fetch("manifest", lineage_ids)
    custody_events = _fetch("handoff", handoff_ids)
    verification_events = _fetch("verification", verification_ids)

    chain = audit.verify_chain()
    return {
        "package_format": "forensic-evidence-package-v1",
        "exported_at": utc_now_iso(),
        "manifest": m,
        "canonical_manifest": canonical,
        "manifest_hash": row.get("manifest_hash"),
        "lineage": get_lineage(m["lineage_id"]),
        "handoffs": m["handoffs"],
        "verifications": verifications,
        "audit_events": {
            "manifest": manifest_events,
            "custody": custody_events,
            "verification": verification_events,
        },
        "audit_chain": chain,
    }


def render_report(result: Dict[str, Any], manifest: Dict[str, Any]) -> str:
    """生成人类可读（Markdown）核验报告。"""
    tz = result.get("timezone", "UTC")
    lines: List[str] = []
    lines.append("# 移动介质证物核验报告")
    lines.append("")
    lines.append(f"- 案件编号：{manifest['case_no']}")
    lines.append(f"- 证物标识：{manifest['evidence_id']}")
    lines.append(f"- 清单 ID：`{manifest['id']}`")
    lines.append(f"- lineage：`{manifest['lineage_id']}`")
    lines.append(f"- 采集时间（本地 {tz}）："
                 f"{local_iso(parse_dt(manifest['collected_at']), tz)}")
    lines.append(f"- 操作者：{manifest['operator']}")
    lines.append(f"- 清单状态：{manifest['status']}"
                 + (f"，封存时间：{manifest['sealed_at']}" if manifest.get("sealed_at") else ""))
    lines.append(f"- 验证编号：`{result['verification_id']}`")
    lines.append(f"- 重新采集时间：{result.get('recollected_at') or '未提供'}")
    lines.append("")
    verdict = result["verdict"]
    badge = {"PASS": "✅ 通过", "PASS_WITH_WARNINGS": "⚠️ 通过（有警告）",
             "FAIL": "❌ 不通过"}.get(verdict, verdict)
    lines.append(f"## 核验结论：{badge}")
    lines.append("")
    c = result["counts"]
    lines.append("| 项目 | 数量 |")
    lines.append("|---|---:|")
    for key, label in [
        ("baseline_entries", "基线条目"), ("observed_entries", "重采条目"),
        ("added", "新增"), ("missing", "缺失"), ("changed", "内容变化"),
        ("rename_candidates", "改名候选"), ("time_anomalies", "时间异常"),
        ("chunk_corruptions", "分块损坏文件"), ("metadata_anomalies", "元数据异常"),
        ("custody_findings", "交接问题"), ("merkle_findings", "Merkle/链问题"),
        ("lineage_findings", "版本链问题")]:
        lines.append(f"| {label} | {c[key]} |")
    lines.append("")

    def section(title, items, fmt):
        if not items:
            return
        lines.append(f"## {title}")
        for it in items:
            lines.append("- " + fmt(it))
        lines.append("")

    section("新增文件", result["added"],
            lambda i: f"`{i['path']}`  sha256=`{i['sha256'][:16]}…`  {i.get('size','?')} 字节")
    section("缺失文件", result["missing"],
            lambda i: f"`{i['path']}`  sha256=`{i['sha256'][:16]}…`")
    section("无法解释的新增/缺失", result.get("unexplained_anomalies", []),
            lambda i: f"[{i['severity']}] {i['code']} `{i.get('path','')}`：{i['message']}")
    section("改名候选", result["rename_candidates"],
            lambda i: f"`{i['old_path']}` → `{i['new_path']}`（{i['confidence']}，"
                      f"相似度 {i['similarity']}，哈希一致：{i['same_sha256']}）")
    section("内容变化", result["changed"],
            lambda i: f"`{i['path']}`：`{i['baseline_sha256'][:16]}…` → "
                      f"`{i['observed_sha256'][:16]}…`")
    section("时间异常", result["time_anomalies"],
            lambda i: f"[{i['severity']}] {i.get('code')} "
                      f"{i.get('path','')}：{i['message']}")

    def fmt_chunk(i):
        rs = ", ".join(f"块 {r['start_chunk']}-{r['end_chunk']}（字节约 "
                       f"{r['byte_range_hint'][0]}-{r['byte_range_hint'][1]}）"
                       for r in i["corrupt_ranges"])
        return f"`{i['path']}` 分块大小 {i.get('chunk_size')}：{rs}"
    section("分块损坏范围", result["chunk_corruptions"], fmt_chunk)
    section("元数据异常", result["metadata_anomalies"],
            lambda i: f"[{i['severity']}] {i['code']} `{i.get('path','')}`：{i['message']}")
    section("交接与签收问题", result["custody_findings"],
            lambda i: f"[{i['severity']}] {i['code']}：{i['message']}")
    section("版本谱系问题", result["lineage_findings"],
            lambda i: f"[{i['severity']}] {i['code']}：{i['message']}")
    section("Merkle / 哈希链问题", result["merkle_findings"],
            lambda i: f"[{i['severity']}] {i['code']}：{i['message']}")

    mk = result["merkle"]
    lines.append("## Merkle 根")
    lines.append("")
    lines.append(f"- 封存根：`{mk['baseline_root_sealed']}`")
    lines.append(f"- 基线重算根：`{mk['baseline_root_recomputed']}`")
    lines.append(f"- 重采数据根：`{mk['observed_root']}`")
    lines.append("")
    ac = result["audit_chain"]
    lines.append("## 审计哈希链")
    lines.append("")
    lines.append(f"- 完整性：{'完好' if ac['intact'] else '断裂'}")
    lines.append(f"- 事件数：{ac['event_count']}")
    lines.append(f"- 末事件哈希：`{ac['last_event_hash']}`")
    lines.append("")
    return "\n".join(lines)


def render_report_by_verification(verification_id: str) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    row = get_conn().execute(
        "SELECT * FROM verification WHERE id=?", (verification_id,)).fetchone()
    if not row:
        raise models.NotFound(f"验证记录 {verification_id} 不存在")
    result = json.loads(row["result"])
    result.setdefault("verification_id", verification_id)
    manifest = get_manifest(row["manifest_id"])
    return render_report(result, manifest), result, manifest
