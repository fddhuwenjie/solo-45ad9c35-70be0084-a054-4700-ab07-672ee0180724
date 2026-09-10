# -*- coding: utf-8 -*-
"""SQLite 连接、模式初始化与仅追加审计链的数据库层强制。"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict

from . import config

_lock = threading.RLock()
_local = threading.local()
_all_conns: "list[sqlite3.Connection]" = []  # 跨线程连接注册表（便于切换库时全部关闭）

SCHEMA = """
CREATE TABLE IF NOT EXISTS manifest (
    id              TEXT PRIMARY KEY,
    lineage_id      TEXT NOT NULL,
    version         INTEGER NOT NULL,
    supersedes_id   TEXT,
    case_no         TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,
    collected_at    TEXT NOT NULL,      -- UTC ISO
    timezone        TEXT NOT NULL,      -- 采集时区 IANA
    operator        TEXT NOT NULL,
    note            TEXT,
    status          TEXT NOT NULL CHECK (status IN ('open','sealed')),
    merkle_root     TEXT,
    entry_count     INTEGER NOT NULL DEFAULT 0,
    canonical_json  TEXT,
    manifest_hash   TEXT,
    sealed_at       TEXT,
    acknowledged_issues TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    UNIQUE (lineage_id, version)
);
CREATE INDEX IF NOT EXISTS idx_manifest_case ON manifest(case_no, evidence_id);
CREATE INDEX IF NOT EXISTS idx_manifest_lineage ON manifest(lineage_id, version);

CREATE TABLE IF NOT EXISTS entry (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_id   TEXT NOT NULL REFERENCES manifest(id),
    seq           INTEGER NOT NULL,
    path          TEXT NOT NULL,
    path_fold     TEXT NOT NULL,
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    chunk_size    INTEGER,
    chunk_hashes  TEXT,                -- JSON array
    mtime         TEXT,                -- UTC ISO, 可空
    issues        TEXT NOT NULL DEFAULT '[]',
    UNIQUE (manifest_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_entry_manifest ON entry(manifest_id, seq);
CREATE INDEX IF NOT EXISTS idx_entry_fold ON entry(manifest_id, path_fold);

CREATE TABLE IF NOT EXISTS handoff (
    id            TEXT PRIMARY KEY,
    manifest_id   TEXT NOT NULL REFERENCES manifest(id),
    seq           INTEGER NOT NULL,     -- 同一清单内交接序号
    event_type    TEXT NOT NULL CHECK (event_type IN ('handoff','signoff')),
    from_party    TEXT,
    to_party      TEXT,
    actor         TEXT,                 -- 实际签收人（signoff 时可空=身份缺失）
    actor_id_no   TEXT,                 -- 证件/编号（可空）
    occurred_at   TEXT NOT NULL,        -- UTC ISO
    timezone      TEXT NOT NULL,
    note          TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (manifest_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_handoff_manifest ON handoff(manifest_id, seq);

CREATE TABLE IF NOT EXISTS verification (
    id            TEXT PRIMARY KEY,
    manifest_id   TEXT NOT NULL REFERENCES manifest(id),
    mode          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    collected_at  TEXT,                -- 重新采集时间（UTC）
    summary       TEXT NOT NULL,       -- JSON
    result        TEXT NOT NULL,       -- 完整结果 JSON
    audit_event_id TEXT
);

CREATE TABLE IF NOT EXISTS audit_event (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    event_type   TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    actor        TEXT,
    payload_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,        -- 首事件为固定 GENESIS 前值
    event_hash   TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_object ON audit_event(object_type, object_id);

-- 仅追加审计链：数据库层拒绝 UPDATE/DELETE。
CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event 为仅追加表，禁止更新');
END;
CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event 为仅追加表，禁止删除');
END;
"""

GENESIS_PREV = "0" * 64


def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    db_path = str(config.DB_PATH)
    # 若当前线程连接指向的库路径已变化（测试中切换 FORENSIC_DB 时会发生），重连
    if conn is not None and getattr(_local, "db_path", None) != db_path:
        reset_connection()
        conn = None
    if conn is None:
        config.ensure_dirs()
        # check_same_thread=False 以便测试切换库时可从主控线程关闭工作线程连接；
        # 连接仍通过 threading.local 保证单线程独占使用。
        conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        _local.conn = conn
        _local.db_path = db_path
        with _lock:
            _all_conns.append(conn)
    return conn


def reset_connection() -> None:
    """关闭当前线程缓存连接并清除路径记忆（主要供测试切换数据库）。"""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        with _lock:
            if conn in _all_conns:
                _all_conns.remove(conn)
    _local.__dict__.pop("conn", None)
    _local.__dict__.pop("db_path", None)


def reset_all_connections() -> None:
    """关闭所有线程缓存的连接（切换底层数据库路径时使用）。"""
    with _lock:
        for conn in list(_all_conns):
            try:
                conn.close()
            except Exception:
                pass
        _all_conns.clear()
    _local.__dict__.pop("conn", None)
    _local.__dict__.pop("db_path", None)


def init_db() -> None:
    with _lock:
        conn = get_conn()
        conn.executescript(SCHEMA)
        conn.commit()


def row_to_dict(row: sqlite3.Row | None) -> Dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for key in ("chunk_hashes", "issues", "acknowledged_issues", "summary"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (ValueError, TypeError):
                pass
    return d
