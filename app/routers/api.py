# -*- coding: utf-8 -*-
"""FastAPI 路由：清单、交接、验证、导出、审计。"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

from .. import audit, ops
from ..models import Conflict, DomainError, NotFound
from ..schemas import (
    AppendEntriesIn,
    CorrectIn,
    HandoffCreateIn,
    ManifestCreateIn,
    SealIn,
    SignoffIn,
    VerifyHashListIn,
    VerifyMetadataIn,
)

router = APIRouter()


def _handle(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except NotFound as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Conflict as e:
        raise HTTPException(status_code=409, detail=str(e))
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# 清单
# ---------------------------------------------------------------------------

@router.post("/manifests", tags=["manifests"], summary="创建清单（v1，open 状态）")
def create_manifest(data: ManifestCreateIn):
    return _handle(ops.create_manifest, data)


@router.get("/manifests", tags=["manifests"], summary="列出/检索清单")
def list_manifests(case_no: Optional[str] = None, evidence_id: Optional[str] = None,
                   status: Optional[str] = Query(None, pattern="^(open|sealed)$")):
    return {"manifests": ops.list_manifests(case_no, evidence_id, status)}


@router.get("/manifests/{manifest_id}", tags=["manifests"], summary="获取清单详情")
def get_manifest(manifest_id: str):
    return _handle(ops.get_manifest, manifest_id)


@router.post("/manifests/{manifest_id}/entries", tags=["manifests"],
             summary="向 open 清单追加条目")
def append_entries(manifest_id: str, data: AppendEntriesIn):
    return _handle(ops.append_entries, manifest_id, data)


@router.post("/manifests/{manifest_id}/seal", tags=["manifests"],
             summary="封存清单：固化规范化字节、manifest_hash 与 Merkle 根")
def seal(manifest_id: str, data: SealIn):
    return _handle(ops.seal_manifest, manifest_id, data)


@router.post("/manifests/{manifest_id}/correct", tags=["manifests"],
             summary="对已封存清单更正，生成同 lineage 的关联新版本")
def correct(manifest_id: str, data: CorrectIn):
    return _handle(ops.correct_manifest, manifest_id, data)


# ---------------------------------------------------------------------------
# 交接 / 签收
# ---------------------------------------------------------------------------

@router.post("/manifests/{manifest_id}/handoffs", tags=["custody"],
             summary="记录一次交接（封存后）")
def create_handoff(manifest_id: str, data: HandoffCreateIn):
    return _handle(ops.create_handoff, manifest_id, data)


@router.get("/manifests/{manifest_id}/handoffs", tags=["custody"], summary="交接记录列表")
def list_handoffs(manifest_id: str):
    return _handle(lambda mid: {"handoffs": ops.list_handoffs(mid)}, manifest_id)


@router.post("/handoffs/{handoff_id}/signoff", tags=["custody"],
             summary="交接签收（actor 留空将记录身份缺失）")
def signoff(handoff_id: str, data: SignoffIn):
    return _handle(ops.signoff, handoff_id, data)


# ---------------------------------------------------------------------------
# 验证
# ---------------------------------------------------------------------------

@router.post("/manifests/{manifest_id}/verify/metadata", tags=["verification"],
             summary="上传重新采集的完整元数据进行逐项核验")
def verify_metadata(manifest_id: str, data: VerifyMetadataIn):
    return _handle(ops.verify_manifest, manifest_id, data)


@router.post("/manifests/{manifest_id}/verify/hash-list", tags=["verification"],
             summary="上传路径+哈希列表进行核验（字节数/时间可缺省）")
def verify_hash_list(manifest_id: str, data: VerifyHashListIn):
    # hash_list 复用同一比对核心：size 缺省置 0，且不参与 mtime/size 检查
    normalized = VerifyMetadataIn(
        mode="hash_list",
        collected_at=data.collected_at,
        timezone=data.timezone,
        operator=data.operator,
        entries=[{
            "path": e.path, "sha256": e.sha256,
            "size": e.size if e.size is not None else 0,
            "chunk_size": e.chunk_size,
            "chunk_hashes": e.chunk_hashes,
        } for e in data.entries],
    )
    return _handle(ops.verify_manifest, manifest_id, normalized)


@router.get("/verifications/{verification_id}/report", tags=["verification"],
            summary="人类可读 Markdown 核验报告", response_class=PlainTextResponse)
def verification_report(verification_id: str):
    try:
        text, _, _ = ops.render_report_by_verification(verification_id)
    except NotFound as e:
        raise HTTPException(status_code=404, detail=str(e))
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------

@router.get("/manifests/{manifest_id}/export", tags=["export"],
            summary="导出 JSON 证据包（清单+版本链+交接+验证+审计事件+链校验）")
def export_package(manifest_id: str):
    return _handle(ops.build_evidence_package, manifest_id)


@router.get("/manifests/{manifest_id}/report", tags=["export"],
            summary="基于最近一次验证生成 Markdown 核验报告",
            response_class=PlainTextResponse)
def latest_report(manifest_id: str):
    from ..database import get_conn
    row = get_conn().execute(
        "SELECT id FROM verification WHERE manifest_id=? ORDER BY created_at DESC LIMIT 1",
        (manifest_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="该清单尚无验证记录，请先调用验证接口")
    try:
        text, _, _ = ops.render_report_by_verification(row["id"])
    except NotFound as e:
        raise HTTPException(status_code=404, detail=str(e))
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


# ---------------------------------------------------------------------------
# 审计链
# ---------------------------------------------------------------------------

@router.get("/audit/events", tags=["audit"], summary="查询审计事件（仅追加哈希链）")
def get_audit_events(object_type: Optional[str] = None, object_id: Optional[str] = None,
                     limit: int = Query(200, ge=1, le=10000)):
    return {"events": audit.list_events(object_type, object_id, limit)}


@router.get("/audit/verify", tags=["audit"], summary="重算全链，校验审计哈希链完整性")
def verify_audit_chain():
    return audit.verify_chain()
