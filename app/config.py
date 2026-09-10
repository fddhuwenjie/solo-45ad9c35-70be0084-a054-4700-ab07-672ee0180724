# -*- coding: utf-8 -*-
"""数字取证移动介质交接核对系统 (Forensic Mobile Media Chain-of-Custody API)

本地运行、无外部服务依赖。
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# 数据库文件（SQLite，本地）
DB_PATH = Path(os.environ.get("FORENSIC_DB", BASE_DIR / "data" / "forensic.db"))

# 清单版本的规范化数据格式版本号
MANIFEST_SPEC = "forensic-manifest-v1"

# 审计链使用的哈希算法
HASH_ALG = "sha256"

# 时区校验范围
VALID_TZ_HINT = "IANA 时区名称，例如 Asia/Shanghai、UTC"


def ensure_dirs() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)
