"""受控导出授权中枢。

领域语义以 ``domain/contract.json`` 为准，本包把合同中的实体、状态、事件
落地为可运行的服务：申请、清单冻结与分级、共同批准、分片续传领取、撤销
过期、管理查询与审计摘要，全部状态由事件流重建，重启后阶段保持正确。
"""
from __future__ import annotations

from .errors import (
    ConflictError,
    ExportGuardError,
    NotFoundError,
    ValidationError,
)
from .models import ChunkClaim, EntryInclusion, ExportView, ManifestEntry
from .service import ExportGuardService

__all__ = [
    "ChunkClaim",
    "ConflictError",
    "EntryInclusion",
    "ExportGuardError",
    "ExportGuardService",
    "ExportView",
    "ManifestEntry",
    "NotFoundError",
    "ValidationError",
]

__version__ = "0.1.0"
