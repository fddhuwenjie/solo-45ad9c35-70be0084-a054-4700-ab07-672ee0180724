# -*- coding: utf-8 -*-
"""纯函数单元测试：路径归一化、Merkle、规范化序列化、分块区间。"""
from app.crypto import (
    canonical_dumps,
    corrupt_chunk_ranges,
    fold_key,
    hash_object,
    leaf_hash,
    merkle_root,
    normalize_path,
)
from app.models import build_canonical_manifest, normalize_entry, scan_entries


def test_path_normalization_matrix():
    assert fold_key(normalize_path("DCIM\\IMG_0001.jpg")) == "dcim/img_0001.jpg"
    assert fold_key(normalize_path("./DCIM//IMG_0001.jpg")) == "dcim/img_0001.jpg"
    assert fold_key(normalize_path("ＦＩＬＥ.dat")) == "file.dat"
    assert fold_key(normalize_path("Ⅰ.txt")) == "i.txt"
    assert fold_key(normalize_path("ﬁle.txt")) == "file.txt"
    assert fold_key(normalize_path("Straße.dat")) == fold_key(
        normalize_path("STRASSE.dat"))
    # 显示形态保留（不做大小写折叠存储）
    assert normalize_path("Docs/File.dat") == "Docs/File.dat"


def test_unicode_variants_fold_equal():
    import unicodedata
    nfc = unicodedata.normalize("NFC", "café.pdf")
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd  # 组合 vs 分解形式
    assert fold_key(normalize_path(nfc)) == fold_key(normalize_path(nfd))


def test_scan_entries_duplicate_and_ambiguity():
    e1 = normalize_entry({"path": "a/f.dat", "size": 10,
                          "sha256": "a" * 64})
    e2 = normalize_entry({"path": "A/F.DAT", "size": 10,
                          "sha256": "a" * 64})
    tagged, rejected = scan_entries([e1, e2])
    assert len(tagged) == 1 and len(rejected) == 1

    e3 = normalize_entry({"path": "A/F.DAT", "size": 20,
                          "sha256": "b" * 64})
    tagged, rejected = scan_entries([e1, e3])
    assert len(tagged) == 2 and rejected == []
    assert any(i["code"] == "AMBIGUOUS_PATH_CONTENT"
               for i in tagged[1]["issues"])


def test_scan_batch_case_variants():
    e1 = normalize_entry({"path": "X.dat", "size": 1, "sha256": "a" * 64})
    e2 = normalize_entry({"path": "x.dat", "size": 2, "sha256": "b" * 64})
    tagged, rejected = scan_entries([e1, e2])
    codes = {i["code"] for i in tagged[0]["issues"]}
    assert "UNICODE_OR_CASE_VARIANT" in codes


def test_canonical_json_deterministic():
    obj = {"b": 1, "a": [3, 2, {"x": True, "w": None}]}
    s1 = canonical_dumps(obj)
    s2 = canonical_dumps(obj)
    assert s1 == s2
    # 键排序 + 无多余空白
    assert s1.startswith('{"a"')
    assert ": " not in s1 and ", " not in s1


def test_merkle_properties():
    leaves = [hash_object({"i": i}) for i in range(7)]
    assert merkle_root([]) is None
    assert merkle_root([leaves[0]]) == leaves[0]
    assert merkle_root(leaves) == merkle_root(leaves)  # 确定性
    assert merkle_root(leaves) != merkle_root(list(reversed(leaves)))  # 顺序敏感


def test_leaf_hash_includes_chunks_and_mtime():
    base = {"path": "f", "size": 1, "sha256": "a" * 64,
            "chunk_size": None, "chunk_hashes": [], "mtime": None}
    assert leaf_hash(base) == leaf_hash(dict(base))
    changed = dict(base, mtime="2026-01-01T00:00:00+00:00")
    assert leaf_hash(changed) != leaf_hash(base)


def test_manifest_hash_reproducible():
    meta = {"case_no": "C", "evidence_id": "E", "collected_at": "t",
            "timezone": "UTC", "operator": "o", "note": None}
    entries = [normalize_entry({"path": "a", "size": 1, "sha256": "a" * 64}),
               normalize_entry({"path": "b", "size": 2, "sha256": "b" * 64})]
    m1 = build_canonical_manifest(meta, entries)
    m2 = build_canonical_manifest(meta, entries)
    assert canonical_dumps(m1) == canonical_dumps(m2)
    assert m1["merkle_tree"]["root"]
    # 条目顺序变化 => Merkle 根变化
    m3 = build_canonical_manifest(meta, list(reversed(entries)))
    assert m3["merkle_tree"]["root"] != m1["merkle_tree"]["root"]


def test_corrupt_chunk_ranges():
    a = ["h0", "h1", "h2", "h3", "h4"]
    b = ["h0", "XX", "XX", "h3", "XX"]
    assert corrupt_chunk_ranges(a, b) == [(1, 2), (4, 4)]
    assert corrupt_chunk_ranges(a, a) == []
    # 观测块数变少：尾部块视为损坏
    assert corrupt_chunk_ranges(a, a[:3]) == [(3, 4)]
