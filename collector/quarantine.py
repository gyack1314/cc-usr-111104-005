"""拒收隔离：坏包留下拒收报告与原始包摘要，但不暴露半成品。

* 原始 ZIP（若已下载）按内容摘要存入隔离区 blob，永不覆盖、不被清理流程触碰；
* 每次拒收生成带时间戳与错误码的报告，包含冻结清单、错误现场与原始包摘要；
* 暂存半成品由 verifier 在失败时整体删除，隔离区不保存任何解压内容。
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from .errors import RejectionError


class Quarantine:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.blobs = self.root / "blobs"
        self.reports = self.root / "reports"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.reports.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _atomic_write_json(path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix="." + path.name + ".", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def store_blob(self, archive_path: Path | None) -> dict | None:
        """把被拒收的原始 ZIP 复制进隔离区，按真实 SHA-256 命名。"""
        if archive_path is None or not Path(archive_path).exists():
            return None
        digest = hashlib.sha256()
        with open(archive_path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        key = digest.hexdigest()
        target = self.blobs / key
        if not target.exists():
            fd, name = tempfile.mkstemp(prefix=".part-", dir=self.blobs)
            try:
                with os.fdopen(fd, "wb") as out, open(archive_path, "rb") as src:
                    while True:
                        chunk = src.read(64 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(name, target)
            finally:
                if os.path.exists(name):
                    os.unlink(name)
        return {"sha256": key, "size": target.stat().st_size, "blob": str(target)}

    def record(
        self,
        error: RejectionError,
        *,
        source: str,
        stage: str,
        manifest_doc: dict | None,
        archive_path: Path | None,
    ) -> Path:
        """生成一份拒收报告，返回报告路径。"""
        blob_info = self.store_blob(archive_path)
        timestamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        nonce = os.urandom(4).hex()
        name = f"{timestamp}-{error.code}-{nonce}.json"
        report_path = self.reports / name
        payload = {
            "rejected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stage": stage,
            "source": source,
            "error": error.as_dict(),
            "manifest": manifest_doc,
            "archive": blob_info,
        }
        self._atomic_write_json(report_path, payload)
        return report_path
