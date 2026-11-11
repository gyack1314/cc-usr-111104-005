"""采集器异常类型。

拒收类异常都带稳定的机器可读 code，拒收报告与 CLI 退出码都基于它，
避免用异常字符串做判断。
"""
from __future__ import annotations


class CollectorError(Exception):
    """采集器内所有异常的基类。"""


class RejectionError(CollectorError):
    """包被拒收。code 为稳定错误码，details 保存现场信息。"""

    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "details": self.details}


class ConflictError(CollectorError):
    """相同包ID与修订对应了不同内容（已接收版本不可变）。"""

    def __init__(self, message: str, **details: object) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def as_dict(self) -> dict:
        return {"code": "revision-conflict", "message": self.message, "details": self.details}


class RecoverableStateError(CollectorError):
    """暂存区存在无法自动判定的残留状态，需要人工或 recover 处理。"""
