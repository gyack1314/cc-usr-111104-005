"""成员相对路径的安全规则。

规则（与 docs/source-format.md 一致并覆盖题目全部要求）：

* 必须是字符串、非空的相对 POSIX 路径，按 ``/`` 分段；
* 拒绝空段（``a//b``、尾随/前导斜杠）、``.``/``..`` 点段；
* 拒绝反斜杠、NUL 及其他 C0 控制字符（Windows 保留盘符与设备名）；
* 拒绝 Windows 盘符（``C:``）与 Windows 保留设备名（``CON``、``NUL`` 等）；
* 保留原始名字（manifest 与 ZIP 中的写法），同时给出
  ``unicodedata.normalize('NFC', ...).casefold()`` 碰撞键用于跨平台比对。

只做字符串判定；落盘时由 verifier 再做一次 ``relative_to``  containment 兜底，
即使判定规则将来出错，路径也无法越出暂存目录。
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .errors import RejectionError

# Windows 保留设备名（不分大小写），出现在任意一段即拒绝。
_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def collision_key(path: str) -> str:
    """跨平台碰撞键：NFC 归一化后 casefold。"""
    return unicodedata.normalize("NFC", path).casefold()


@dataclass(frozen=True)
class SafePath:
    """通过校验的成员路径。original 保留来源原名，key 用于碰撞检查。"""

    original: str
    key: str

    @property
    def parts(self) -> tuple[str, ...]:
        return tuple(self.original.split("/"))


def validate_member_path(path: object) -> SafePath:
    """校验清单或 ZIP 中的成员路径，失败抛出 RejectionError。"""
    if not isinstance(path, str) or not path:
        raise RejectionError("unsafe-path", "成员路径必须是非空字符串", path=repr(path))
    if "\x00" in path:
        raise RejectionError("unsafe-path", "成员路径包含 NUL 字符", path=path)
    if "\\" in path:
        raise RejectionError("unsafe-path", "成员路径不允许反斜杠（仅接受 POSIX 相对路径）", path=path)
    if path.startswith("/"):
        raise RejectionError("unsafe-path", "拒绝绝对路径", path=path)
    # 任何 C0 控制字符（除已单独处理的 NUL 外）都拒绝。
    if any(ord(ch) < 0x20 for ch in path):
        raise RejectionError("unsafe-path", "成员路径包含控制字符", path=path)

    segments = path.split("/")
    if any(seg == "" for seg in segments):
        raise RejectionError("unsafe-path", "路径包含空段（重复/首尾斜杠）", path=path)
    if any(seg in (".", "..") for seg in segments):
        raise RejectionError("unsafe-path", "路径包含 . 或 .. 点段", path=path)

    first = segments[0]
    # Windows 盘符，如 C:、c:（带冒号的首段）。
    if len(first) >= 2 and first[1] == ":" and first[0].isalpha():
        raise RejectionError("unsafe-path", "拒绝 Windows 盘符路径", path=path)
    for seg in segments:
        # Windows 保留设备名对后续扩展名/流名不敏感：nul.txt、CON.log 仍保留。
        device_part = seg.split(".", 1)[0].split(":", 1)[0].rstrip(" ").casefold()
        if device_part in _RESERVED_NAMES:
            raise RejectionError("unsafe-path", "路径包含 Windows 保留设备名", path=path)

    normalized = unicodedata.normalize("NFC", path)
    return SafePath(original=path, key=normalized.casefold())


def ensure_within(root_abs: str, target_abs: str) -> None:
    """落盘兜底：确认 target_abs 位于 root_abs 之内。"""
    import os
    root = os.path.realpath(root_abs)
    target = os.path.realpath(target_abs)
    if target != root and not target.startswith(root + os.sep):
        raise RejectionError(
            "path-escape",
            "解析后的成员路径越出暂存目录",
            root=root,
            target=target,
        )
