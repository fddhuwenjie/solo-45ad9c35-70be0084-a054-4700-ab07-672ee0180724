# -*- coding: utf-8 -*-
"""Pydantic 请求/响应模型（含取证字段校验）。"""
from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _validate_sha256(v: str, name: str) -> str:
    v = (v or "").strip().lower()
    if not SHA256_RE.match(v):
        raise ValueError(f"{name} 必须为 64 位十六进制 SHA-256")
    return v


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------

class ChunkHashIn(BaseModel):
    index: int = Field(..., ge=0, description="分块序号，从 0 开始")
    sha256: str = Field(..., description="该分块 SHA-256（64 位十六进制）")

    @field_validator("sha256")
    @classmethod
    def _h(cls, v):
        return _validate_sha256(v, "分块 sha256")


class EntryIn(BaseModel):
    path: str = Field(..., min_length=1, description="文件在介质中的路径")
    size: int = Field(..., ge=0, description="字节数")
    sha256: str = Field(..., description="整文件 SHA-256")
    chunk_size: Optional[int] = Field(None, ge=1, description="分块大小（字节）")
    chunk_hashes: Optional[List[str]] = Field(None, description="按序排列的分块 SHA-256")
    mtime: Optional[str] = Field(None, description="文件修改时间，ISO-8601 且带时区偏移")

    @field_validator("sha256")
    @classmethod
    def _file_hash(cls, v):
        return _validate_sha256(v, "sha256")

    @field_validator("chunk_hashes")
    @classmethod
    def _chunk_list(cls, v):
        if v is None:
            return v
        return [_validate_sha256(x, "分块哈希") for x in v]

    @model_validator(mode="after")
    def _cross(self):
        if (self.chunk_size is None) != (not self.chunk_hashes):
            raise ValueError("chunk_size 与 chunk_hashes 必须同时提供或同时省略")
        return self


class ManifestCreateIn(BaseModel):
    case_no: str = Field(..., min_length=1, description="案件编号")
    evidence_id: str = Field(..., min_length=1, description="证物标识")
    collected_at: str = Field(..., description="采集时间，ISO-8601 且带时区偏移")
    timezone: str = Field(..., description="采集操作者所在 IANA 时区，如 Asia/Shanghai")
    operator: str = Field(..., min_length=1, description="操作者")
    note: Optional[str] = None
    entries: List[EntryIn] = Field(default_factory=list, description="初始条目，可为空后追加")


class AppendEntriesIn(BaseModel):
    entries: List[EntryIn] = Field(..., min_length=1)
    operator: Optional[str] = None
    note: Optional[str] = None


class SealIn(BaseModel):
    operator: str = Field(..., min_length=1)
    occurred_at: Optional[str] = Field(None, description="封存发生时间，ISO-8601 带偏移；缺省为服务端当前时间")
    timezone: str = Field("Asia/Shanghai")
    acknowledge_issues: bool = Field(
        False, description="存在路径歧义条目时必须显式置 true 才可封存"
    )
    note: Optional[str] = None


class CorrectIn(BaseModel):
    """对已封存版本发起更正，生成同 lineage 的新版本（新版本初始为 open）。"""
    case_no: Optional[str] = None
    evidence_id: Optional[str] = None
    collected_at: Optional[str] = None
    timezone: Optional[str] = None
    operator: str = Field(..., min_length=1, description="发起更正的操作者")
    reason: str = Field(..., min_length=1, description="更正原因，写入审计")
    entries: List[EntryIn] = Field(..., description="更正后新版本的完整条目集")
    note: Optional[str] = None


class HandoffCreateIn(BaseModel):
    from_party: str = Field(..., min_length=1, description="交出方（姓名/单位/警号）")
    to_party: str = Field(..., min_length=1, description="接收方（姓名/单位/警号）")
    occurred_at: str = Field(..., description="交接发生时间，ISO-8601 带偏移")
    timezone: str = Field("Asia/Shanghai")
    note: Optional[str] = None


class SignoffIn(BaseModel):
    actor: Optional[str] = Field(None, description="实际签收人；为空将记录身份缺失")
    actor_id_no: Optional[str] = Field(None, description="签收人证件/编号")
    occurred_at: str = Field(..., description="签收时间，ISO-8601 带偏移")
    timezone: str = Field("Asia/Shanghai")
    note: Optional[str] = None


class VerifyEntryIn(BaseModel):
    path: str
    size: int = Field(..., ge=0)
    sha256: str
    chunk_size: Optional[int] = Field(None, ge=1)
    chunk_hashes: Optional[List[str]] = None
    mtime: Optional[str] = None

    @field_validator("sha256")
    @classmethod
    def _h(cls, v):
        return _validate_sha256(v, "sha256")

    @field_validator("chunk_hashes")
    @classmethod
    def _chunks(cls, v):
        if v is None:
            return v
        return [_validate_sha256(x, "分块哈希") for x in v]

    @model_validator(mode="after")
    def _cross(self):
        if self.chunk_size is not None and self.chunk_hashes is not None:
            return self
        if self.chunk_size is None and self.chunk_hashes is None:
            return self
        raise ValueError("chunk_size 与 chunk_hashes 必须同时提供或同时省略")


class HashListEntryIn(BaseModel):
    """hash_list 模式条目：path + sha256（可带分块），元数据字段可省略。"""
    path: str
    sha256: str
    size: Optional[int] = Field(None, ge=0)
    chunk_size: Optional[int] = Field(None, ge=1)
    chunk_hashes: Optional[List[str]] = None

    @field_validator("sha256")
    @classmethod
    def _h(cls, v):
        return _validate_sha256(v, "sha256")

    @field_validator("chunk_hashes")
    @classmethod
    def _chunks(cls, v):
        if v is None:
            return v
        return [_validate_sha256(x, "分块哈希") for x in v]


class VerifyMetadataIn(BaseModel):
    mode: str = Field("metadata", pattern="^(metadata|hash_list)$")
    collected_at: Optional[str] = Field(None, description="重新采集时间，ISO-8601 带偏移")
    timezone: str = Field("Asia/Shanghai")
    operator: Optional[str] = None
    entries: List[VerifyEntryIn] = Field(default_factory=list)


class VerifyHashListIn(BaseModel):
    mode: str = Field("hash_list", pattern="^(metadata|hash_list)$")
    collected_at: Optional[str] = None
    timezone: str = Field("Asia/Shanghai")
    operator: Optional[str] = None
    entries: List[HashListEntryIn] = Field(default_factory=list)
