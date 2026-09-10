# -*- coding: utf-8 -*-
"""规范化、哈希、Merkle 根与路径归一化工具。

设计要点：
* 所有规范化序列化使用 sort_keys + UTF-8 + LF + 无多余空白，保证字节级可复现；
* 路径比对同时做大小写折叠与 Unicode NFKC 归一化，以识别大小写 / 全半角 / 兼容字符歧义；
* Merkle 树采用叶节点直接为叶子哈希、奇数节点复制上提（duplicate-last-node）策略。
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any, Dict, Iterable, List, Tuple

SHA256_RE_LEN = 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_dumps(obj: Any) -> str:
    """规范化 JSON：键排序、无空白、ensure_ascii=False、LF 换行。"""
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_dumps(obj).encode("utf-8")


def hash_object(obj: Any) -> str:
    """对任意可 JSON 化对象求规范化 SHA-256。"""
    return sha256_hex(canonical_bytes(obj))


# ---------------------------------------------------------------------------
# 路径归一化
# ---------------------------------------------------------------------------

def normalize_path(path: str) -> str:
    """NFKC 归一化并统一路径分隔符、压缩重复分隔符、去尾部分隔符。

    注意：不做大小写折叠 —— 规范化保留真实显示形态，折叠仅用于比对键。
    """
    if path is None:
        raise ValueError("路径不能为空")
    p = unicodedata.normalize("NFKC", str(path))
    # 统一反斜杠（Windows 采集）为正斜杠
    p = p.replace("\\", "/")
    # 压缩重复斜杠（保留可选的 UNC //server 前缀，介质取证多为相对/挂载路径，统一压缩）
    while "//" in p:
        p = p.replace("//", "/")
    # 去掉结尾斜杠（根 "/" 例外）
    if len(p) > 1:
        p = p.rstrip("/")
    # 统一点号开头的相对路径
    if p.startswith("./"):
        p = p[2:]
    return p


def fold_key(normalized_path: str) -> str:
    """用于重复识别的折叠键：NFKC + casefold。

    casefold 覆盖大小写、希腊终西格玛、德语 ß->ss 等；NFKC 覆盖全角字母、
    兼容字符（如 ｆｉ 连字、上标数字、罗马数字）。
    """
    return unicodedata.normalize("NFKC", normalized_path).casefold()


def unicode_variants(path: str) -> List[str]:
    """返回同一字符串的其他归一化形态，用于标记“看起来不同但 NFKC 后相同”的歧义。"""
    variants = set()
    for form in ("NFC", "NFD", "NFKC", "NFKD"):
        variants.add(unicodedata.normalize(form, str(path)))
    variants.discard(str(path))
    return sorted(variants)


# ---------------------------------------------------------------------------
# Merkle 树
# ---------------------------------------------------------------------------
# 域分隔前缀，防止“内部节点哈希”与“叶子哈希”相互伪造。
LEAF_PREFIX = b"\x00LEAF:"
INNER_PREFIX = b"\x01INNER:"


def leaf_hash(entry: Dict[str, Any]) -> str:
    """单条目叶子哈希，输入为规范化后的条目字段（不含运行时 id）。"""
    material = {
        "path": entry["path"],
        "size": entry["size"],
        "sha256": entry["sha256"],
        "chunk_size": entry.get("chunk_size"),
        "chunk_hashes": entry.get("chunk_hashes") or [],
        "mtime": entry.get("mtime"),
    }
    return sha256_hex(LEAF_PREFIX + canonical_bytes(material))


def _parent(a: str, b: str) -> str:
    return sha256_hex(INNER_PREFIX + a.encode("ascii") + b.encode("ascii"))


def merkle_root(leaves: Iterable[str]) -> str | None:
    """从叶子哈希列表计算 Merkle 根；空列表返回 None。

    奇数节点：最后一个节点复制后参与配对（duplicate-last-node）。
    """
    level: List[str] = list(leaves)
    if not level:
        return None
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(_parent(left, right))
        level = nxt
    return level[0]


def corrupt_chunk_ranges(
    original: List[str], recollected: List[str]
) -> List[Tuple[int, int]]:
    """对比两组分块哈希，返回 (起始块号, 结束块号) 的损坏/差异区间（块号从 0 起，闭区间）。"""
    ranges: List[Tuple[int, int]] = []
    start: int | None = None
    n = max(len(original), len(recollected))
    for i in range(n):
        a = original[i] if i < len(original) else None
        b = recollected[i] if i < len(recollected) else None
        if a != b:
            if start is None:
                start = i
        else:
            if start is not None:
                ranges.append((start, i - 1))
                start = None
    if start is not None:
        ranges.append((start, n - 1))
    return ranges
