# -*- coding: utf-8 -*-
"""pytest 全局夹具：每个测试使用独立临时数据库。

通过在导入应用前设置 FORENSIC_DB，或在夹具中切换 config.DB_PATH 并重置
线程本地连接来隔离数据库。
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("FORENSIC_DB", str(db_path))

    from app import config, database
    monkeypatch.setattr(config, "DB_PATH", db_path)
    # 关闭所有线程（含 TestClient 工作线程）缓存的旧连接
    database.reset_all_connections()
    database.init_db()

    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c

    database.reset_all_connections()
