"""ZIP 流式校验与安全暂存。

设计要点（对应题目逐条要求）：

* **不使用 extractall / 不覆盖**：每个成员手工流式读取，目标文件以
  ``O_CREAT|O_EXCL|O_NOFOLLOW`` 独占创建，目录也独占创建；
* **只信实际流过的字节**：中央目录仅用于定位与对账；本地文件头由本模块
  手工解析，压缩字节从文件里真实读出并计数，解压由本模块直接驱动 zlib，
  长度、SHA-256、CRC、压缩比全部在流循环中按真实计数计算；
* **内存有界**：每次只持有一个 64KiB 块，不把任何成员整体读入内存；
* **一一对应**：ZIP 成员（忽略目录条目）与清单成员按 NFC+casefold 键做
  双向集合比对，缺项、多项、重复、碰撞全部拒收，零字节成员同样校验；
* **危险条目拒收**：符号链接、特殊文件、加密、非 stored/deflated、
  数据描述符、ZIP64 等在解压前拒收；
* **坏包不留半成品**：任何一步失败都整体删除暂存目录，仅由 quarantine 留报告。
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import RejectionError
from .limits import Budget, Limits
from .manifest import Manifest, MemberSpec
from .paths import ensure_within, validate_member_path

_ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
# 仅允许 bit 11（UTF-8 名称）。数据描述符(bit3)、加密(bit0/6)等一律不接受，
# 这样本地文件头里的长度字段始终可信。
_ALLOWED_FLAG_BITS = 0x0800
_S_IFMT = 0o170000
_S_IFREG = 0o100000
_LOCAL_SIG = b"PK\x03\x04"
_LOCAL_HEADER_FIXED = 30


@dataclass
class MemberResult:
    path: str
    role: str
    size: int
    sha256: str
    compressed_bytes: int
    crc32: int


@dataclass
class VerificationResult:
    package_id: str
    revision: int
    package_size: int
    package_sha256: str
    members: list[MemberResult] = field(default_factory=list)
    total_uncompressed: int = 0
    total_compressed: int = 0

    def to_dict(self) -> dict:
        return {
            "package_id": self.package_id,
            "revision": self.revision,
            "package_size": self.package_size,
            "package_sha256": self.package_sha256,
            "total_uncompressed": self.total_uncompressed,
            "total_compressed": self.total_compressed,
            "members": [
                {
                    "path": m.path,
                    "role": m.role,
                    "size": m.size,
                    "sha256": m.sha256,
                    "compressed_bytes": m.compressed_bytes,
                    "crc32": f"{m.crc32:08x}",
                }
                for m in self.members
            ],
        }


@dataclass
class _LocalHeader:
    """从本地文件头真实解析出的字段（不信任中央目录的长度）。"""

    flags: int
    compress_type: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    data_offset: int


def _check_entry_kind(info: zipfile.ZipInfo) -> None:
    """在解压前拒绝符号链接、特殊文件、加密与不受支持的压缩特性。"""
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    if kind != 0 and kind != _S_IFREG:
        raise RejectionError(
            "special-file",
            "ZIP 成员不是普通文件（符号链接/设备/FIFO 等一律拒收）",
            entry=info.filename,
            mode=f"{mode:04o}",
        )
    if info.flag_bits & 0x1:
        raise RejectionError("encrypted-entry", "加密成员一律拒收", entry=info.filename)
    if info.compress_type not in _ALLOWED_COMPRESSION:
        raise RejectionError(
            "unsupported-compression",
            "仅允许 stored/deflated 压缩",
            entry=info.filename,
            compress_type=info.compress_type,
        )
    if info.flag_bits & ~_ALLOWED_FLAG_BITS:
        raise RejectionError(
            "unsupported-flags",
            "成员使用不受支持的通用位标志（数据描述符/分卷/强加密等）",
            entry=info.filename,
            flags=f"0x{info.flag_bits:04x}",
        )
    # ZIP64 痕迹：extra 中的 0x0001 字段。
    if any(typ == 0x0001 for typ, _data in info.extra):
        raise RejectionError("zip64-entry", "ZIP64 成员不在支持范围内", entry=info.filename)


def _read_local_header(handle, info: zipfile.ZipInfo) -> _LocalHeader:
    try:
        handle.seek(info.header_offset)
        header = handle.read(_LOCAL_HEADER_FIXED)
    except OSError as exc:
        raise RejectionError(
            "bad-zip-structure",
            f"本地文件头无法读取: {exc}",
            entry=info.filename,
        ) from exc
    if len(header) < _LOCAL_HEADER_FIXED or header[:4] != _LOCAL_SIG:
        raise RejectionError(
            "bad-zip-structure",
            "本地文件头签名损坏或被截断",
            entry=info.filename,
        )
    (
        _sig,
        version,
        flags,
        compress_type,
        _mtime,
        _mdate,
        crc32,
        compressed_size,
        uncompressed_size,
        name_len,
        extra_len,
    ) = struct.unpack("<IHHHHHIIIHH", header)
    try:
        # 跳过名称与 extra，定位真实压缩数据起点。
        handle.seek(name_len + extra_len, os.SEEK_CUR)
    except OSError as exc:
        raise RejectionError(
            "bad-zip-structure",
            f"本地文件头 extra 越界: {exc}",
            entry=info.filename,
        ) from exc
    return _LocalHeader(
        flags=flags,
        compress_type=compress_type,
        crc32=crc32,
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        data_offset=handle.tell(),
    )


def _exclusive_mkdir(path: Path) -> None:
    try:
        path.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
        if not path.is_dir() or path.is_symlink():
            raise RejectionError(
                "path-escape",
                "成员目录路径被非目录或符号链接占用",
                path=str(path),
            )


def _open_exclusive(staging_root: Path, rel_posix: str):
    """以 O_EXCL|O_NOFOLLOW 独占打开成员输出文件，绝不覆盖任何已有文件。"""
    target = staging_root.joinpath(*rel_posix.split("/"))
    ensure_within(str(staging_root), str(target))
    parent = target.parent
    ancestor = staging_root
    for part in parent.relative_to(staging_root).parts:
        ancestor = ancestor / part
        if not ancestor.exists():
            _exclusive_mkdir(ancestor)
        elif ancestor.is_symlink() or not ancestor.is_dir():
            raise RejectionError("path-escape", "路径上存在符号链接或非目录", path=str(ancestor))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(target), flags, 0o600)
    return target, fd


def _stream_member(
    handle,
    info: zipfile.ZipInfo,
    local: _LocalHeader,
    out_fd: int,
    spec: MemberSpec,
    budget: Budget,
    limits: Limits,
) -> tuple[int, int, int, "hashlib._Hash"]:
    """流式解压单个成员并落盘。

    返回 (实际压缩字节, 实际解压字节, 实际CRC32, 增量SHA-256)。
    """
    digest = hashlib.sha256()
    crc = 0
    uncompressed = 0
    compressed = 0
    remaining = local.compressed_size
    if local.compress_type == zipfile.ZIP_DEFLATED:
        decompressor = zlib.decompressobj(-15)
    else:
        decompressor = None

    with os.fdopen(out_fd, "wb") as out:
        while remaining > 0:
            try:
                raw = handle.read(min(limits.chunk_size, remaining))
            except OSError as exc:
                raise RejectionError(
                    "bad-compressed-stream",
                    f"压缩数据读取失败: {exc}",
                    member=spec.path,
                ) from exc
            if not raw:
                raise RejectionError(
                    "bad-compressed-stream",
                    "压缩数据在声明长度结束前被截断",
                    member=spec.path,
                    remaining=remaining,
                )
            remaining -= len(raw)
            compressed += len(raw)
            try:
                if decompressor is None:
                    pieces = [raw]
                else:
                    pieces = [decompressor.decompress(raw)]
                    if decompressor.eof and remaining:
                        # deflate 流提前结束但本地头声明还有数据：结构异常。
                        raise RejectionError(
                            "bad-compressed-stream",
                            "deflate 流提前结束，与本地头长度不符",
                            member=spec.path,
                        )
            except zlib.error as exc:
                raise RejectionError(
                    "bad-compressed-stream",
                    f"deflate 流校验失败: {exc}",
                    member=spec.path,
                ) from exc

            for piece in pieces:
                if not piece:
                    continue
                uncompressed += len(piece)
                if limits.member_bytes and uncompressed > limits.member_bytes:
                    raise RejectionError(
                        "limit-member-bytes",
                        "单个成员解压字节超过预算",
                        limit=limits.member_bytes,
                        actual=uncompressed,
                        member=spec.path,
                    )
                budget.add_uncompressed(len(piece), spec.path)
                digest.update(piece)
                crc = zlib.crc32(piece, crc)
                out.write(piece)

        if decompressor is not None:
            try:
                tail = decompressor.flush()
            except zlib.error as exc:
                raise RejectionError(
                    "bad-compressed-stream",
                    f"deflate 收尾失败: {exc}",
                    member=spec.path,
                ) from exc
            if tail:
                uncompressed += len(tail)
                budget.add_uncompressed(len(tail), spec.path)
                digest.update(tail)
                crc = zlib.crc32(tail, crc)
                out.write(tail)
            if not decompressor.eof:
                raise RejectionError(
                    "bad-compressed-stream",
                    "deflate 流不完整（未正常结束）",
                    member=spec.path,
                )
        out.flush()
        os.fsync(out.fileno())

    return compressed, uncompressed, crc, digest


def verify_and_stage(
    archive_path: Path,
    manifest: Manifest,
    staging_dir: Path,
    limits: Limits,
) -> VerificationResult:
    """完整校验一个已下载的 ZIP 并安全解压到全新暂存目录。

    成功返回 :class:`VerificationResult`；失败抛出 RejectionError 并清空暂存目录。
    """
    staging_dir = Path(staging_dir)
    if staging_dir.exists() and any(staging_dir.iterdir()):
        raise RejectionError("staging-not-empty", "暂存目录必须是新建的空目录", path=str(staging_dir))
    staging_dir.mkdir(parents=True, exist_ok=True)
    budget = Budget(limits)

    try:
        # 原始包摘要按真实字节重算（调用方通常已校验，这里做纵深防御）。
        package_digest = hashlib.sha256()
        with open(archive_path, "rb") as raw:
            while True:
                block = raw.read(limits.chunk_size)
                if not block:
                    break
                budget.add_package_bytes(len(block))
                package_digest.update(block)
        package_hash = package_digest.hexdigest()
        if package_hash != manifest.sha256:
            raise RejectionError(
                "archive-digest-mismatch",
                "暂存 ZIP 的 SHA-256 与清单不符",
                expected=manifest.sha256,
                actual=package_hash,
            )

        try:
            zf = zipfile.ZipFile(archive_path)
        except zipfile.BadZipFile as exc:
            raise RejectionError("bad-zip-structure", f"ZIP 结构损坏: {exc}") from exc

        result = VerificationResult(
            package_id=manifest.package_id,
            revision=manifest.revision,
            package_size=budget.package_bytes,
            package_sha256=package_hash,
        )

        with zf:
            # ---- 第一遍：中央目录结构检查与重复/碰撞检测 -----------------
            file_entries: list[zipfile.ZipInfo] = []
            seen_zip_keys: set[str] = set()
            for info in zf.infolist():
                if info.is_dir():
                    # 目录条目不是成员；清单显式列了目录会在后面的对账中报缺项。
                    continue
                safe = validate_member_path(info.filename)
                if safe.key in seen_zip_keys:
                    raise RejectionError(
                        "duplicate-zip-member",
                        "ZIP 内成员路径重复或 NFC+casefold 碰撞",
                        entry=info.filename,
                        key=safe.key,
                    )
                seen_zip_keys.add(safe.key)
                _check_entry_kind(info)
                file_entries.append(info)

            manifest_by_key = manifest.member_by_key()
            zip_keys = seen_zip_keys
            missing = sorted(set(manifest_by_key) - zip_keys)
            extra = sorted(zip_keys - set(manifest_by_key))
            if missing:
                raise RejectionError(
                    "member-missing",
                    "清单中的成员在 ZIP 内缺失",
                    missing=[manifest_by_key[k].path for k in missing],
                )
            if extra:
                extra_set = set(extra)
                raise RejectionError(
                    "member-extra",
                    "ZIP 内存在清单未声明的成员",
                    extra=[
                        i.filename for i in file_entries
                        if validate_member_path(i.filename).key in extra_set
                    ],
                )
            budget.member_count = len(file_entries)
            if limits.member_count and budget.member_count > limits.member_count:
                raise RejectionError(
                    "limit-member-count",
                    "成员数量超过预算",
                    limit=limits.member_count,
                    actual=budget.member_count,
                )

            # ---- 第二遍：逐成员手工流式解压、校验并独占落盘 ---------------
            with open(archive_path, "rb") as handle:
                for info in file_entries:
                    safe = validate_member_path(info.filename)
                    spec: MemberSpec = manifest_by_key[safe.key]
                    # 键相同还要求原始路径逐字一致（防止同键异写被静默改名）。
                    if info.filename != spec.path:
                        raise RejectionError(
                            "member-name-mismatch",
                            "ZIP 与清单的成员原始路径写法不一致",
                            zip_name=info.filename,
                            manifest_name=spec.path,
                        )
                    if spec.mode is not None:
                        zip_mode = (info.external_attr >> 16) & 0xFFFF
                        if stat.S_IFMT(zip_mode) and stat.S_IMODE(zip_mode) != stat.S_IMODE(spec.mode):
                            raise RejectionError(
                                "member-mode-mismatch",
                                "成员权限位与清单声明不一致",
                                entry=spec.path,
                                manifest_mode=oct(spec.mode),
                                zip_mode=oct(zip_mode),
                            )

                    local = _read_local_header(handle, info)
                    if local.flags & ~_ALLOWED_FLAG_BITS:
                        raise RejectionError(
                            "unsupported-flags",
                            "本地文件头使用不受支持的标志位",
                            entry=spec.path,
                            flags=f"0x{local.flags:04x}",
                        )
                    if local.compress_type not in _ALLOWED_COMPRESSION:
                        raise RejectionError(
                            "unsupported-compression",
                            "本地文件头压缩方式不受支持",
                            entry=spec.path,
                            compress_type=local.compress_type,
                        )

                    target, fd = _open_exclusive(staging_dir, spec.path)
                    try:
                        compressed, member_size, crc, member_hash = _stream_member(
                            handle, info, local, fd, spec, budget, limits
                        )
                    except BaseException:
                        if target.exists():
                            target.unlink()
                        raise

                    # 长度三重对账：实际流计数 vs 本地头 vs 中央目录 vs 清单。
                    if member_size != local.uncompressed_size:
                        raise RejectionError(
                            "member-size-mismatch",
                            "实际解压长度与本地文件头不符",
                            member=spec.path,
                            local_header=local.uncompressed_size,
                            actual=member_size,
                        )
                    if member_size != info.file_size:
                        raise RejectionError(
                            "member-size-mismatch",
                            "实际解压长度与中央目录不符",
                            member=spec.path,
                            central=info.file_size,
                            actual=member_size,
                        )
                    if member_size != spec.size:
                        raise RejectionError(
                            "member-size-mismatch",
                            "成员实际解压长度与清单不符",
                            member=spec.path,
                            expected=spec.size,
                            actual=member_size,
                        )
                    if f"{crc:08x}" != f"{local.crc32:08x}":
                        raise RejectionError(
                            "crc-mismatch",
                            "实际 CRC32 与本地文件头声明不符（压缩流可能损坏）",
                            member=spec.path,
                            expected=f"{local.crc32:08x}",
                            actual=f"{crc:08x}",
                        )
                    if f"{crc:08x}" != f"{info.CRC:08x}":
                        raise RejectionError(
                            "crc-mismatch",
                            "实际 CRC32 与中央目录声明不符",
                            member=spec.path,
                            expected=f"{info.CRC:08x}",
                            actual=f"{crc:08x}",
                        )
                    actual_hex = member_hash.hexdigest()
                    if actual_hex != spec.sha256:
                        raise RejectionError(
                            "member-digest-mismatch",
                            "成员 SHA-256 与清单不符",
                            member=spec.path,
                            expected=spec.sha256,
                            actual=actual_hex,
                        )
                    budget.check_member(member_size, compressed, spec.path)
                    result.members.append(
                        MemberResult(
                            path=spec.path,
                            role=spec.role,
                            size=member_size,
                            sha256=actual_hex,
                            compressed_bytes=compressed,
                            crc32=crc,
                        )
                    )

        result.total_uncompressed = budget.total_uncompressed
        result.total_compressed = budget.total_compressed
        return result

    except BaseException:
        # 坏包不留半成品：整个暂存目录清空，拒收证据由 quarantine 另行保存。
        import shutil
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        raise
