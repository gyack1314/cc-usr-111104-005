"""资料包清单结构与严格解析。

清单在一次接收开始时抓取并冻结为 :class:`Manifest`，后续全部校验只使用
冻结对象；即使来源随后更新了清单，本次接收也不会混用新内容（见 fetcher）。
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .errors import RejectionError
from .paths import collision_key, validate_member_path

_HEX64 = set("0123456789abcdef")
_ALLOWED_ROLES = {"resource", "document", "metadata", "readme"}


@dataclass(frozen=True)
class MemberSpec:
    path: str                     # 原始相对路径（保留原名）
    collision_key: str            # NFC + casefold 键
    size: int
    sha256: str
    role: str
    mode: int | None = None


@dataclass(frozen=True)
class Manifest:
    package_id: str
    revision: int
    archive: str                  # 相对来源根的 ZIP 路径，下载时即冻结
    size: int
    sha256: str
    members: tuple[MemberSpec, ...]
    raw: dict = field(repr=False, default_factory=dict)

    def member_by_key(self) -> dict[str, MemberSpec]:
        return {m.collision_key: m for m in self.members}


def _require_str(obj: dict, key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise RejectionError("bad-manifest", f"清单字段 {key} 必须是非空字符串", field=key)
    return value


def _require_int(obj: dict, key: str, *, minimum: int) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RejectionError("bad-manifest", f"清单字段 {key} 必须是 >= {minimum} 的整数", field=key)
    return value


def _require_sha256(obj: dict, key: str) -> str:
    value = _require_str(obj, key)
    if len(value) != 64 or any(c not in _HEX64 for c in value):
        raise RejectionError("bad-manifest", f"清单字段 {key} 不是合法的小写 SHA-256", field=key)
    return value


def parse_manifest(data: bytes | str | dict) -> Manifest:
    """严格解析清单文档。"""
    if isinstance(data, dict):
        doc = data
    else:
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RejectionError("bad-manifest", "清单不是合法 UTF-8") from exc
        else:
            text = data
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RejectionError("bad-manifest", f"清单不是合法 JSON: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise RejectionError("bad-manifest", "清单顶层必须是对象")

    package_id = _require_str(doc, "package_id")
    revision = _require_int(doc, "revision", minimum=0)
    archive = _require_str(doc, "archive")
    if archive.startswith(("http://", "https://", "file://")):
        # 按约定 archive 是相对来源根的路径（允许单个前导斜杠的根相对形式）；
        # 协议绝对地址会让“一次接收固定地址”的边界失效。
        raise RejectionError("bad-manifest", "archive 必须是相对来源根的路径")
    size = _require_int(doc, "size", minimum=0)
    sha256 = _require_sha256(doc, "sha256")

    raw_members = doc.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise RejectionError("bad-manifest", "members 必须是非空数组")

    members: list[MemberSpec] = []
    seen_keys: set[str] = set()
    seen_originals: set[str] = set()
    for index, item in enumerate(raw_members):
        if not isinstance(item, dict):
            raise RejectionError("bad-manifest", f"成员 {index} 必须是对象")
        original = _require_str(item, "path")
        safe = validate_member_path(original)
        if unicodedata.normalize("NFC", original) != original:
            raise RejectionError(
                "manifest-not-nfc",
                "清单成员路径必须使用 Unicode NFC 形式",
                path=original,
            )
        if original in seen_originals:
            raise RejectionError("duplicate-manifest-member", "清单内成员路径重复", path=original)
        seen_originals.add(original)
        if safe.key in seen_keys:
            raise RejectionError(
                "manifest-collision",
                "清单内成员在 NFC+casefold 后碰撞",
                path=original,
                key=safe.key,
            )
        seen_keys.add(safe.key)

        member_size = _require_int(item, "size", minimum=0)
        member_hash = _require_sha256(item, "sha256")
        role = _require_str(item, "role")
        if role not in _ALLOWED_ROLES:
            raise RejectionError("bad-manifest", f"未知成员角色 {role!r}", path=original)
        empty_hash = hashlib.sha256(b"").hexdigest()
        if member_size == 0 and member_hash != empty_hash:
            raise RejectionError(
                "bad-manifest",
                "零字节成员的 SHA-256 必须是空流摘要",
                path=original,
            )
        mode = item.get("mode")
        if mode is not None:
            if isinstance(mode, bool) or not isinstance(mode, int):
                raise RejectionError("bad-manifest", "mode 必须是整数", path=original)
        members.append(
            MemberSpec(
                path=original,
                collision_key=collision_key(original),
                size=member_size,
                sha256=member_hash,
                role=role,
                mode=mode,
            )
        )

    return Manifest(
        package_id=package_id,
        revision=revision,
        archive=archive,
        size=size,
        sha256=sha256,
        members=tuple(members),
        raw=doc,
    )
