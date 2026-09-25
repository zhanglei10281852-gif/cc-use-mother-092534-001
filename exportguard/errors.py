"""服务对外抛出的领域错误。

错误码稳定，HTTP 层据此映射状态码，业务代码据此区分冲突与非法请求。
"""
from __future__ import annotations


class ExportGuardError(Exception):
    """所有受控导出服务错误的基类。"""

    code = "export_guard_error"
    http_status = 400

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    def to_dict(self) -> dict:
        return {"error": self.code, "message": str(self)}


class ValidationError(ExportGuardError):
    """请求不满足领域前置条件（字段缺失、状态非法等）。"""

    code = "validation_error"
    http_status = 400


class NotFoundError(ExportGuardError):
    """导出申请或相关对象不存在。"""

    code = "not_found"
    http_status = 404


class ConflictError(ExportGuardError):
    """状态冲突：撤销、过期、审批版本落后、领取键重复等。

    重复领取属于正常的幂等重试还是冲突，由服务层根据是否同请求判定，
    这里的冲突用于"键相同但参数不一致"的异常情况。
    """

    code = "conflict"
    http_status = 409
