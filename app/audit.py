# -*- coding: utf-8 -*-
"""仅追加审计链。

每个业务状态变化写入一条事件：event_hash = SHA256(prev_hash | 规范化事件主体)，
形成按 seq 线性连接的哈希链；数据库触发器禁止 UPDATE/DELETE。
"""
from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, List, Optional

from .crypto import canonical_bytes, sha256_hex
from .database import GENESIS_PREV, get_conn
from .timeutil import utc_now_iso

_chain_lock = threading.RLock()


def _compute_event_hash(
    event_type: str,
    object_type: str,
    object_id: str,
    timestamp: str,
    actor: Optional[str],
    payload_hash: str,
    prev_hash: str,
) -> str:
    body = {
        "event_type": event_type,
        "object_type": object_type,
        "object_id": object_id,
        "timestamp": timestamp,
        "actor": actor,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
    }
    return sha256_hex(prev_hash.encode("ascii") + canonical_bytes(body))


def append_event(
    event_type: str,
    object_type: str,
    object_id: str,
    payload: Any,
    actor: Optional[str] = None,
    timestamp: Optional[str] = None,
    commit: bool = True,
) -> Dict[str, Any]:
    """追加一条审计事件（调用方需在同一事务中完成业务写入后再 commit）。

    返回事件记录，其中含 prev_hash 与 event_hash。
    """
    conn = get_conn()
    ts = timestamp or utc_now_iso()
    payload_hash = sha256_hex(canonical_bytes(payload))

    # 串行化“读末事件哈希 -> 计算 -> 插入”，保证本进程内链头不竞争
    with _chain_lock:
        row = conn.execute(
            "SELECT event_hash FROM audit_event ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["event_hash"] if row else GENESIS_PREV

        event_id = uuid.uuid4().hex
        event_hash = _compute_event_hash(
            event_type, object_type, object_id, ts, actor, payload_hash, prev_hash
        )

        conn.execute(
            """INSERT INTO audit_event
               (event_id, event_type, object_type, object_id, timestamp, actor,
                payload_hash, prev_hash, event_hash)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (event_id, event_type, object_type, object_id, ts, actor,
             payload_hash, prev_hash, event_hash),
        )
        if commit:
            conn.commit()
    return {
        "event_id": event_id,
        "event_type": event_type,
        "object_type": object_type,
        "object_id": object_id,
        "timestamp": ts,
        "actor": actor,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
    }


def list_events(object_type: Optional[str] = None, object_id: Optional[str] = None,
                limit: int = 200) -> List[Dict[str, Any]]:
    conn = get_conn()
    sql = "SELECT * FROM audit_event"
    cond, params = [], []
    if object_type:
        cond.append("object_type = ?")
        params.append(object_type)
    if object_id:
        cond.append("object_id = ?")
        params.append(object_id)
    if cond:
        sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY seq ASC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def verify_chain() -> Dict[str, Any]:
    """重算整条审计链，检查前向哈希链接与序号连续性。"""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM audit_event ORDER BY seq ASC").fetchall()
    prev = GENESIS_PREV
    expected_seq = 1
    broken: List[Dict[str, Any]] = []
    for r in rows:
        recomputed = _compute_event_hash(
            r["event_type"], r["object_type"], r["object_id"], r["timestamp"],
            r["actor"], r["payload_hash"], r["prev_hash"],
        )
        problems = []
        if r["seq"] != expected_seq:
            problems.append("seq 不连续")
        if r["prev_hash"] != prev:
            problems.append("prev_hash 断链")
        if recomputed != r["event_hash"]:
            problems.append("event_hash 重算不一致")
        if problems:
            broken.append({"seq": r["seq"], "event_id": r["event_id"],
                           "problems": problems})
        prev = r["event_hash"]
        expected_seq += 1
    return {
        "algorithm": "sha256(prev_hash + canonical(event_body))",
        "event_count": len(rows),
        "intact": not broken,
        "breaks": broken,
        "last_event_hash": prev if rows else GENESIS_PREV,
    }
