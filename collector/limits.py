"""流式预算。

所有阈值都以**实际流过的字节**为准，在 verifier 读取/解压的循环里逐块累加，
ZIP 中央目录里的 size/csize 只用于事后对账，不能作为提前放行的依据。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .errors import RejectionError


@dataclass(frozen=True)
class Limits:
    """接收预算。0 表示不限制该项。"""

    package_bytes: int = 10 * 1024 * 1024      # 原始 ZIP 字节上限
    member_count: int = 4096                   # 成员数量上限
    member_bytes: int = 5 * 1024 * 1024        # 单个成员解压字节上限
    total_bytes: int = 50 * 1024 * 1024        # 整包解压字节总和上限
    max_ratio: float = 100.0                   # 单成员 解压字节/实际压缩字节 上限
    manifest_bytes: int = 1 * 1024 * 1024      # 清单文档自身字节上限
    chunk_size: int = 64 * 1024                # 流式读写块大小

    @staticmethod
    def load(path: str | Path | None) -> "Limits":
        if path is None:
            return Limits()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        allowed = Limits().__dict__.keys()
        unknown = set(data) - set(allowed)
        if unknown:
            raise RejectionError("bad-limits-config", "限额配置含未知字段", fields=sorted(unknown))
        return Limits(**data)


class Budget:
    """在流处理过程中记账，超限立即拒收，不等待整包读完。"""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.package_bytes = 0
        self.member_count = 0
        self.total_uncompressed = 0
        self.total_compressed = 0

    def add_package_bytes(self, count: int) -> None:
        self.package_bytes += count
        if self.limits.package_bytes and self.package_bytes > self.limits.package_bytes:
            raise RejectionError(
                "limit-package-bytes",
                "原始包字节超过预算",
                limit=self.limits.package_bytes,
                actual=self.package_bytes,
            )

    def add_uncompressed(self, count: int, member_path: str) -> None:
        self.total_uncompressed += count
        # 单成员上限由 verifier 用成员级计数器在 check_member 中检查。
        if self.limits.total_bytes and self.total_uncompressed > self.limits.total_bytes:
            raise RejectionError(
                "limit-total-bytes",
                "整包解压字节总和超过预算",
                limit=self.limits.total_bytes,
                actual=self.total_uncompressed,
                member=member_path,
            )

    def check_member(self, uncompressed: int, compressed: int, member_path: str) -> None:
        """单个成员读完后的长度与压缩比检查（基于实际计数）。"""
        if self.limits.member_bytes and uncompressed > self.limits.member_bytes:
            raise RejectionError(
                "limit-member-bytes",
                "单个成员解压字节超过预算",
                limit=self.limits.member_bytes,
                actual=uncompressed,
                member=member_path,
            )
        if compressed == 0:
            if uncompressed > 0:
                raise RejectionError(
                    "limit-ratio",
                    "零压缩长度却有非空输出，压缩比视为无限",
                    member=member_path,
                    uncompressed=uncompressed,
                )
            ratio = 1.0
        else:
            ratio = uncompressed / compressed
        self.total_compressed += compressed
        if self.limits.max_ratio and ratio > self.limits.max_ratio:
            raise RejectionError(
                "limit-ratio",
                "成员压缩比超过预算",
                limit=self.limits.max_ratio,
                actual=round(ratio, 3),
                member=member_path,
            )
