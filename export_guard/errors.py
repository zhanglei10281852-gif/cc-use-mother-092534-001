"""受控导出服务的领域异常。"""
from __future__ import annotations


class ExportGuardError(Exception):
    """所有受控导出异常的基类。"""


class NotFoundError(ExportGuardError):
    """租户空间内找不到指定业务对象。"""


class InvalidStateError(ExportGuardError):
    """当前阶段不允许该操作。"""


class ScopeError(ExportGuardError):
    """申请范围或业务目的不合法。"""


class ApprovalError(ExportGuardError):
    """审批本身不合法（未知角色、重复审批、错误的批准版本等）。"""


class ApprovalClosed(ApprovalError):
    """审批绑定的批准版本不是当前待批版本（清单已重新冻结）。"""


class ManifestStale(ExportGuardError):
    """等待期间文件发生变化，批准所绑定的清单哈希已落后。"""


class ClaimKeyConflict(ExportGuardError):
    """同一幂等键被用于不同的领取语义。"""


class ChunkAlreadyClaimed(ExportGuardError):
    """分片已被另一个领取请求先行领取。"""


class DeliveryDenied(ExportGuardError):
    """导出已撤销、过期或批准版本落后，未领取分片必须拒绝。"""
