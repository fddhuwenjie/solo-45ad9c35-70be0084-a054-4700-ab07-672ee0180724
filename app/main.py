# -*- coding: utf-8 -*-
"""FastAPI 应用入口。本地运行，无外部服务依赖。

启动：
    PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8080
或：
    python -m app.main
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from . import config
from .database import init_db
from .models import Conflict, DomainError, NotFound
from .routers.api import router
from .timeutil import TimeError

DESCRIPTION = """# 移动介质证物交接核对本地 API

供数字取证人员核对移动介质（U盘、移动硬盘、手机镜像等）交接材料的**本地** REST API。

## 核心能力

* **规范化、可复现的清单版本**：固定字段、键排序、UTF-8 无空白 JSON；封存时固化
  `manifest_hash = SHA256(规范化字节)` 与 **Merkle 根**。
* **路径归一化识别重复/歧义**：统一分隔符后做 Unicode **NFKC** 归一化 +
  `casefold` 折叠键，可识别大小写差异（`Report.pdf` / `REPORT.PDF`）、
  全角/半角、兼容字符（如连字、罗马数字）等同形异码路径。
* **封存不可变 + 关联更正版本**：封存后原版本只读；任何更正生成同一 `lineage_id`
  下的新版本（`supersedes_id` 指向前版本），并校验版本链。
* **逐项验证**：上传重新采集的元数据或哈希列表，返回
  新增 / 缺失 / 改名候选 / 内容变化 / 时间异常 / **分块损坏字节范围**，
  并检查交接顺序、签收时间倒置、身份缺失、版本链与 **Merkle 根断链**。
* **仅追加审计哈希链**：每次状态变化写入事件，返回 `prev_hash` 与 `event_hash`；
  SQLite 触发器在数据库层禁止审计表 UPDATE/DELETE。
* **导出**：JSON 证据包与人类可读 Markdown 核验报告。

所有数据保存在本地 SQLite（默认 `./data/forensic.db`，可用环境变量
`FORENSIC_DB` 覆盖），不依赖任何外部服务。
"""

@asynccontextmanager
async def lifespan(app: FastAPI):
    config.ensure_dirs()
    init_db()
    yield


app = FastAPI(
    title="数字取证移动介质交接核对 API",
    description=DESCRIPTION,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


@app.exception_handler(NotFound)
async def _not_found(_: Request, exc: NotFound) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(Conflict)
async def _conflict(_: Request, exc: Conflict) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(DomainError)
async def _domain_error(_: Request, exc: DomainError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(TimeError)
async def _time_error(_: Request, exc: TimeError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(ValueError)
async def _value_error(_: Request, exc: ValueError) -> JSONResponse:
    # 领域层直接抛出的值错误（含时间解析）统一按 400
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["system"], summary="健康检查")
def health():
    return {"status": "ok", "db": str(config.DB_PATH), "spec": config.MANIFEST_SPEC}


app.include_router(router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn

    config.ensure_dirs()
    init_db()
    uvicorn.run(app, host="127.0.0.1", port=8080)
