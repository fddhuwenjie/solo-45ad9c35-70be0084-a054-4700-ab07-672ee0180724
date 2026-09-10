# -*- coding: utf-8 -*-
"""领域逻辑：条目规范化、重复/歧义识别、规范化清单、Merkle 计算。"""
from __future__ import annotations

import unicodedata
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from . import config
from .crypto import (
    fold_key,
    leaf_hash,
    merkle_root,
    normalize_path,
    unicode_variants,
)
from .timeutil import parse_dt, to_utc_iso


class DomainError(Exception):
    """400 级业务错误（重复、状态非法等）。"""


class NotFound(Exception):
    """404。"""


class Conflict(Exception):
    """409：封存后不可改等。"""


def entry_payload(e: Any) -> Dict[str, Any]:
    """把 Pydantic 条目模型（或 SimpleNamespace/dict）转成纯 dict 载荷。"""
    if hasattr(e, "model_dump"):
        return e.model_dump(exclude_none=True)
    if isinstance(e, dict):
        return e
    return vars(e)


def normalize_entry(raw: Dict[str, Any]) -> Dict[str, Any]:
    """规范化单条输入：路径 NFKC、哈希小写、mtime 转 UTC ISO。"""
    path = normalize_path(str(raw["path"]))
    mtime = raw.get("mtime")
    if mtime:
        mtime = to_utc_iso(parse_dt(mtime, f"{path} 的 mtime"))
    return {
        "path": path,
        "path_fold": fold_key(path),
        "size": int(raw["size"]) if raw.get("size") is not None else None,
        "sha256": str(raw["sha256"]).strip().lower(),
        "chunk_size": raw.get("chunk_size"),
        "chunk_hashes": (
            [h.strip().lower() for h in raw["chunk_hashes"]]
            if raw.get("chunk_hashes") else None
        ),
        "mtime": mtime,
    }


def scan_entries(
    new_norm: List[Dict[str, Any]],
    existing_norm: List[Dict[str, Any]] | None = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """对“已有条目 + 新条目”整体扫描。

    返回 (带 issues 标注的新条目, 被拒绝的硬重复列表)。
    硬重复：折叠键相同且 (size, sha256) 相同 —— 同一文件重复登记，拒绝接收。
    歧义：折叠键相同但内容哈希不同，或显示形态不同（大小写/Unicode）—— 允许登记但标注。
    """
    existing_norm = existing_norm or []
    # fold -> 已见 (显示路径, size, sha256, 来源)
    seen: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ex in existing_norm:
        seen[ex["path_fold"]].append(ex)

    # 本批内每个折叠键对应的显示形态集合（识别大小写 / Unicode 同形异码）
    batch_forms: Dict[str, set] = defaultdict(set)
    for ne in new_norm:
        batch_forms[ne["path_fold"]].add(ne["path"])

    rejected: List[Dict[str, Any]] = []
    out: List[Dict[str, Any]] = []

    for ne in new_norm:
        issues: List[Dict[str, str]] = []
        key = ne["path_fold"]
        hard_dup = False
        for prior in seen[key]:
            same_content = (
                prior.get("size") == ne["size"]
                and prior.get("sha256") == ne["sha256"]
            )
            if same_content:
                # 完全同内容：无论显示是否相同，都视为重复登记
                hard_dup = True
                rejected.append({
                    "path": ne["path"],
                    "sha256": ne["sha256"],
                    "conflicts_with": prior["path"],
                    "reason": "归一化路径相同且内容一致：重复条目",
                })
                break
            # 同折叠键、不同内容
            issues.append({
                "code": "AMBIGUOUS_PATH_CONTENT",
                "severity": "warning",
                "message": f"路径与 {prior['path']!r} 归一化后相同，但 SHA-256 不同",
                "conflicts_with": prior["path"],
            })
        if hard_dup:
            continue

        forms = batch_forms[key]
        if len(forms) > 1:
            issues.append({
                "code": "UNICODE_OR_CASE_VARIANT",
                "severity": "warning",
                "message": "同批中存在仅大小写/Unicode 形态不同的路径："
                           + ", ".join(sorted(forms)),
            })
        nfc = unicodedata.normalize("NFC", ne["path"])
        nfd = unicodedata.normalize("NFD", ne["path"])
        if nfc != ne["path"] or nfd != ne["path"]:
            issues.append({
                "code": "UNICODE_NOT_NFC",
                "severity": "info",
                "message": "路径非 NFC 标准形态，已按 NFKC 规范化存储与比对",
            })

        tagged = dict(ne)
        tagged["issues"] = issues
        seen[key].append(ne)
        out.append(tagged)
    return out, rejected


def build_canonical_manifest(meta: Dict[str, Any], entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """构造规范化清单对象（字段固定、键排序、条目按登记顺序并含 seq）。"""
    norm_entries = []
    for i, e in enumerate(entries, start=1):
        norm_entries.append({
            "seq": i,
            "path": e["path"],
            "size": e["size"],
            "sha256": e["sha256"],
            "chunk_size": e.get("chunk_size"),
            "chunk_hashes": e.get("chunk_hashes") or [],
            "mtime": e.get("mtime"),
        })
    leaves = [leaf_hash(e) for e in norm_entries]
    return {
        "spec": config.MANIFEST_SPEC,
        "case_no": meta["case_no"],
        "evidence_id": meta["evidence_id"],
        "collected_at": meta["collected_at"],
        "timezone": meta["timezone"],
        "operator": meta["operator"],
        "note": meta.get("note"),
        "entries": norm_entries,
        "merkle_tree": {
            "algorithm": "sha256",
            "leaf_prefix": "0x00LEAF:",
            "inner_prefix": "0x01INNER:",
            "odd_node_strategy": "duplicate-last-node",
            "leaves": leaves,
            "root": merkle_root(leaves),
        },
    }
