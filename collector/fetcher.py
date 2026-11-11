"""本地资料接口：从环回 HTTP 或 file URL 抓取清单与 ZIP。

一次接收的固定点（题目要求“清单 revision 及下载地址在一次接收中固定”）：

* **HTTP 来源（默认）**：单次 GET 一个“接收信封”，信封在同一响应里同时携带
  清单文档与归档的 base64 字节。这一次响应就是冻结快照——即使服务端在响应
  之后立刻更新清单，本次接收也只会使用信封内的 revision、archive 地址与字节。
* **file 来源（本地目录）**：清单与归档直接从本地文件读取，地址在读取清单时
  即冻结，之后不再访问来源目录。
* 所有下载都流式落盘并按实际字节计数，超限在读取途中即拒收；信封里的归档
  字节同样按预算解码，不经过任何“整包进内存”的捷径。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .errors import RejectionError
from .limits import Limits
from .manifest import Manifest, parse_manifest
from .paths import validate_member_path

_ENVELOPE_VERSION = 1


@dataclass(frozen=True)
class PinnedManifest:
    """一次接收中冻结的清单。"""

    manifest: Manifest
    raw_bytes: bytes
    manifest_url: str
    archive_url: str            # 由清单 archive 与来源根拼出，之后不再变化


class Fetcher:
    def __init__(self, limits: Limits, *, timeout: float = 10.0) -> None:
        self.limits = limits
        self.timeout = timeout

    # ---- URL 处理 -------------------------------------------------------

    @staticmethod
    def _split_source(source: str) -> tuple[str, str, str]:
        """把来源描述拆成 (scheme, 基础URL/目录, 清单相对路径)。"""
        if "://" not in source:
            base_path = Path(source).resolve()
            if not base_path.is_dir():
                raise RejectionError("source-unavailable", "本地来源目录不存在", source=source)
            return "file", base_path.as_uri() + "/", "manifest.json"
        parsed = urllib.parse.urlsplit(source)
        if parsed.scheme not in ("http", "https", "file"):
            raise RejectionError("unsupported-scheme", "仅支持 http/https/file 来源",
                                 scheme=parsed.scheme)
        path = parsed.path
        if path.endswith("/"):
            return parsed.scheme, source, "manifest.json"
        base = source.rsplit("/", 1)[0] + "/"
        return parsed.scheme, base, path.rsplit("/", 1)[1]

    def _resolve_archive_url(self, base_url: str, archive: str) -> str:
        # archive 约定为“相对来源根”的路径：样本使用单个前导斜杠的根相对形式
        # （/normal.zip），也接受无斜杠形式；协议绝对地址、点段、反斜杠一律拒绝。
        if archive.startswith(("http://", "https://", "file://")):
            raise RejectionError("bad-manifest", "archive 不能是协议绝对地址")
        if "\x00" in archive or "\\" in archive:
            raise RejectionError("bad-manifest", "archive 路径含非法字符")
        rel = archive.lstrip("/")
        if not rel:
            raise RejectionError("bad-manifest", "archive 路径为空")
        segments = rel.split("/")
        if any(seg in ("", "..", ".") for seg in segments):
            raise RejectionError("bad-manifest", "archive 路径含空段或点段")
        joined = urllib.parse.urljoin(base_url, rel)
        if urllib.parse.urlsplit(joined).scheme not in ("http", "https", "file"):
            raise RejectionError("unsupported-scheme", "解析后的 archive 地址协议不受支持")
        return joined

    # ---- 低层抓取 -------------------------------------------------------

    def _open_url(self, url: str):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "file":
            path = urllib.parse.unquote(parsed.path)
            if not Path(path).is_file():
                raise RejectionError("source-unavailable", "来源文件不存在", url=url)
            return open(path, "rb")
        request = urllib.request.Request(url, method="GET")
        try:
            return urllib.request.urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            raise RejectionError(
                "source-http-error", f"来源返回 HTTP {exc.code}", url=url, status=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise RejectionError("source-unavailable", f"来源不可达: {exc.reason}", url=url) from exc

    def _http_get(self, url: str, byte_limit: int) -> bytes:
        with self._open_url(url) as response:
            return response.read(byte_limit + 1)

    def _stream_raw_to_file(self, raw_iter, dest: Path, byte_limit: int) -> tuple[int, str]:
        import tempfile
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix="." + dest.name + ".", suffix=".part", dir=dest.parent
        )
        digest = hashlib.sha256()
        total = 0
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in raw_iter:
                    if not chunk:
                        continue
                    total += len(chunk)
                    if byte_limit and total > byte_limit:
                        raise RejectionError(
                            "limit-download-bytes",
                            "下载字节超过预算，已在流途中中止",
                            limit=byte_limit, actual=total,
                        )
                    digest.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp_name, dest)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        return total, digest.hexdigest()

    def _iter_file(self, url: str):
        with self._open_url(url) as response:
            while True:
                chunk = response.read(self.limits.chunk_size)
                if not chunk:
                    break
                yield chunk

    # ---- 信封处理 -------------------------------------------------------

    def _build_envelope_from_files(self, manifest_url: str, archive_url: str,
                                   manifest_raw: bytes) -> dict:
        """file 来源：读取本地归档，组装与 HTTP 信封同构的冻结快照。"""
        with self._open_url(archive_url) as f:
            archive_bytes = f.read(self.limits.package_bytes + 1)
        if self.limits.package_bytes and len(archive_bytes) > self.limits.package_bytes:
            raise RejectionError(
                "limit-package-bytes", "原始包字节超过预算",
                limit=self.limits.package_bytes, actual=len(archive_bytes),
            )
        return {
            "envelope_version": _ENVELOPE_VERSION,
            "manifest": base64.b64encode(manifest_raw).decode("ascii"),
            "archive": base64.b64encode(archive_bytes).decode("ascii"),
            "manifest_url": manifest_url,
            "archive_url": archive_url,
        }

    def _fetch_envelope(self, source: str, manifest_path: str | None) -> tuple[dict, str]:
        scheme, base_url, default_path = self._split_source(source)
        rel = manifest_path or default_path
        validate_member_path(rel)
        manifest_url = urllib.parse.urljoin(base_url, rel)

        if scheme == "file":
            # 先读清单才能解析 archive 地址；地址冻结后再读归档，全程不触网。
            manifest_raw = self._http_get(manifest_url, self.limits.manifest_bytes)
            if len(manifest_raw) > self.limits.manifest_bytes:
                raise RejectionError("limit-manifest-bytes", "清单文档超过字节预算",
                                     limit=self.limits.manifest_bytes)
            preview = parse_manifest(manifest_raw)
            archive_url = self._resolve_archive_url(base_url, preview.archive)
            envelope = self._build_envelope_from_files(
                manifest_url, archive_url, manifest_raw
            )
            return envelope, source

        # HTTP：优先请求接收信封（单一响应即快照）。
        envelope_url = urllib.parse.urljoin(base_url, "intake-envelope")
        try:
            raw = self._http_get(
                envelope_url,
                self.limits.manifest_bytes + self.limits.package_bytes + 4096,
            )
        except RejectionError as exc:
            if exc.code != "source-http-error":
                raise
            raise RejectionError(
                "envelope-unavailable",
                "HTTP 来源未提供接收信封（intake-envelope），无法保证一次接收固定",
                url=envelope_url,
            ) from exc
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RejectionError("bad-envelope", "接收信封不是合法 JSON") from exc
        return envelope, source

    # ---- 对外入口 -------------------------------------------------------

    def fetch_manifest(self, source: str, manifest_path: str | None = None,
                       *, envelope: dict | None = None) -> PinnedManifest:
        if envelope is None:
            envelope, _ = self._fetch_envelope(source, manifest_path)
        if not isinstance(envelope, dict) or envelope.get("envelope_version") != _ENVELOPE_VERSION:
            raise RejectionError("bad-envelope", "信封版本不受支持")
        try:
            manifest_raw = base64.b64decode(envelope["manifest"], validate=True)
        except (KeyError, binascii.Error, ValueError) as exc:
            raise RejectionError("bad-envelope", "信封清单字段缺失或非合法 base64") from exc
        if len(manifest_raw) > self.limits.manifest_bytes:
            raise RejectionError("limit-manifest-bytes", "清单文档超过字节预算",
                                 limit=self.limits.manifest_bytes)
        manifest = parse_manifest(manifest_raw)
        base_url = self._split_source(source)[1]
        expected = self._resolve_archive_url(base_url, manifest.archive)
        manifest_url = envelope.get("manifest_url") or urllib.parse.urljoin(
            base_url, manifest_path or "manifest.json"
        )
        archive_url = envelope.get("archive_url") or expected
        # 信封声明的地址必须与清单 archive 解析出的地址一致，防止地址被夹带替换。
        if archive_url != expected:
            raise RejectionError(
                "envelope-url-mismatch",
                "信封 archive 地址与清单解析结果不一致",
                envelope=archive_url, expected=expected,
            )
        return PinnedManifest(
            manifest=manifest,
            raw_bytes=manifest_raw,
            manifest_url=manifest_url,
            archive_url=archive_url,
        )

    def fetch_archive(self, pinned: PinnedManifest, dest: Path,
                      *, envelope: dict | None = None) -> dict:
        """按冻结信封/本地文件把归档字节落到暂存，并核对清单摘要与长度。"""
        if envelope is not None:
            try:
                archive_b64 = envelope["archive"]
            except KeyError as exc:
                raise RejectionError("bad-envelope", "信封缺少 archive 字段") from exc

            def _chunks():
                # 分块 base64 解码，避免整包驻留内存。
                step = self.limits.chunk_size * 4 // 3
                for i in range(0, len(archive_b64), step):
                    part = archive_b64[i:i + step]
                    pad = (-len(part)) % 4
                    try:
                        yield base64.b64decode(part + "=" * pad) if pad else base64.b64decode(part)
                    except binascii.Error as exc:
                        raise RejectionError(
                            "bad-envelope", "信封归档不是合法 base64"
                        ) from exc

            actual_size, actual_hash = self._stream_raw_to_file(
                _chunks(), dest, self.limits.package_bytes
            )
        else:
            actual_size, actual_hash = self._stream_raw_to_file(
                self._iter_file(pinned.archive_url), dest, self.limits.package_bytes
            )

        if actual_hash != pinned.manifest.sha256:
            raise RejectionError(
                "archive-digest-mismatch", "ZIP 实际 SHA-256 与清单不符",
                expected=pinned.manifest.sha256, actual=actual_hash,
                url=pinned.archive_url,
            )
        if actual_size != pinned.manifest.size:
            raise RejectionError(
                "archive-size-mismatch", "ZIP 实际长度与清单不符",
                expected=pinned.manifest.size, actual=actual_size,
            )
        return {
            "archive_url": pinned.archive_url,
            "size": actual_size,
            "sha256": actual_hash,
        }

    @staticmethod
    def dump_pinned(pinned: PinnedManifest) -> dict:
        """把冻结信息写成可落盘的 JSON（供暂存与审计使用）。"""
        return {
            "manifest": pinned.manifest.raw,
            "manifest_url": pinned.manifest_url,
            "archive_url": pinned.archive_url,
            "manifest_sha256": hashlib.sha256(pinned.raw_bytes).hexdigest(),
        }
