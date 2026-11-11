"""采集入口编排：下载、检查、正式接收、离线重验。

四个入口对应题目要求的四类操作：

* ``download`` 只抓取并冻结清单（可选连同 ZIP 落到暂存，不做解压）；
* ``check``    完成下载 + 全量流式校验 + 安全暂存，不改动资料库索引；
* ``accept``   在 check 基础上执行原子发布，坏包与冲突绝不影响已接收版本；
* ``reverify`` 纯离线，对已接收版本重跑完整校验。

所有入口在开始时先执行一次 recover，保证上次崩溃的半成品被判定清理。
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from .errors import ConflictError, RecoverableStateError, RejectionError
from .fetcher import Fetcher, PinnedManifest
from .limits import Limits
from .quarantine import Quarantine
from .repository import Repository, StagedUnit
from .verifier import VerificationResult


@dataclass
class Outcome:
    ok: bool
    action: str
    detail: dict
    report: str | None = None

    def to_dict(self) -> dict:
        data = {"ok": self.ok, "action": self.action, **self.detail}
        if self.report:
            data["rejection_report"] = self.report
        return data


class CollectorService:
    def __init__(self, repo_root: str | Path, limits: Limits | None = None) -> None:
        self.limits = limits or Limits()
        self.repo = Repository(repo_root, self.limits)
        self.quarantine = Quarantine(Path(repo_root) / "quarantine")
        self.fetcher = Fetcher(self.limits)

    # ---- 内部公共流程 ---------------------------------------------------

    @staticmethod
    def _new_token() -> str:
        return time_token() + "-" + secrets.token_hex(4)

    def _reject(
        self,
        error: RejectionError,
        *,
        source: str,
        stage: str,
        unit: StagedUnit | None,
    ) -> Outcome:
        manifest_doc = None
        archive: Path | None = None
        if unit is not None:
            if unit.pin_path.exists():
                try:
                    manifest_doc = json.loads(unit.pin_path.read_text(encoding="utf-8"))["manifest"]
                except (OSError, KeyError, json.JSONDecodeError):
                    manifest_doc = None
            if unit.archive.exists():
                archive = unit.archive
        report = self.quarantine.record(
            error,
            source=source,
            stage=stage,
            manifest_doc=manifest_doc,
            archive_path=archive,
        )
        if unit is not None and unit.dir.exists():
            import shutil
            shutil.rmtree(unit.dir, ignore_errors=True)
        return Outcome(False, stage, {"error": error.as_dict()}, str(report))

    def _prepare(self, source: str, manifest_path: str | None,
                 unit: StagedUnit) -> PinnedManifest:
        """抓取冻结信封（清单+归档快照）并把归档落到暂存单元。"""
        envelope, _ = self.fetcher._fetch_envelope(source, manifest_path)
        pinned = self.fetcher.fetch_manifest(source, manifest_path, envelope=envelope)
        self.repo.write_pin(unit, pinned, source)
        self.fetcher.fetch_archive(pinned, unit.archive, envelope=envelope)
        return pinned

    # ---- 入口 1：下载 ---------------------------------------------------

    def download(self, source: str, manifest_path: str | None = None) -> Outcome:
        with self.repo.locked():
            self.repo.recover()
            unit = self.repo.new_staging(self._new_token())
            try:
                pinned = self._prepare(source, manifest_path, unit)
                return Outcome(True, "download", {
                    "token": unit.token,
                    "staging": str(unit.dir),
                    "package_id": pinned.manifest.package_id,
                    "revision": pinned.manifest.revision,
                    "archive_url": pinned.archive_url,
                    "archive_size": pinned.manifest.size,
                    "archive_sha256": pinned.manifest.sha256,
                    "members": len(pinned.manifest.members),
                })
            except RejectionError as exc:
                return self._reject(exc, source=source, stage="download", unit=unit)

    # ---- 入口 2：检查 ---------------------------------------------------

    def check(self, source: str, manifest_path: str | None = None) -> Outcome:
        with self.repo.locked():
            self.repo.recover()
            unit = self.repo.new_staging(self._new_token())
            try:
                pinned = self._prepare(source, manifest_path, unit)
                result = self.repo.verify_staging(unit, pinned)
                return Outcome(True, "check", {
                    "token": unit.token,
                    "staging": str(unit.dir),
                    "verification": result.to_dict(),
                })
            except RejectionError as exc:
                return self._reject(exc, source=source, stage="check", unit=unit)

    # ---- 入口 3：正式接收 -----------------------------------------------

    def accept(self, source: str, manifest_path: str | None = None,
               *, crash_after_rename: bool = False) -> Outcome:
        with self.repo.locked():
            self.repo.recover()
            unit = self.repo.new_staging(self._new_token())
            try:
                pinned = self._prepare(source, manifest_path, unit)
                result = self.repo.verify_staging(unit, pinned)
                published = self.repo.publish(
                    unit, pinned, result, crash_after_rename=crash_after_rename
                )
                return Outcome(True, "accept", published)
            except RejectionError as exc:
                return self._reject(exc, source=source, stage="accept", unit=unit)
            except ConflictError as exc:
                # 冲突同样落拒收报告，且已接收版本保持原样。
                wrapped = RejectionError("revision-conflict", exc.message, **exc.details)
                return self._reject(wrapped, source=source, stage="accept", unit=unit)
            except RecoverableStateError as exc:
                # 存在改名后未登记的残留：清理本次暂存，提示先 recover，不改动任何已发布版本。
                import shutil
                shutil.rmtree(unit.dir, ignore_errors=True)
                wrapped = RejectionError("recovery-required", str(exc))
                return self._reject(wrapped, source=source, stage="accept", unit=None)

    # ---- 入口 4：离线重验 -----------------------------------------------

    def reverify(self, package_id: str, revision: int) -> Outcome:
        with self.repo.locked():
            try:
                detail = self.repo.offline_reverify(package_id, revision)
                return Outcome(True, "reverify", detail)
            except RejectionError as exc:
                report = self.quarantine.record(
                    exc,
                    source="offline",
                    stage="reverify",
                    manifest_doc=None,
                    archive_path=None,
                )
                return Outcome(False, "reverify", {"error": exc.as_dict()}, str(report))

    def recover(self) -> Outcome:
        with self.repo.locked():
            actions = self.repo.recover()
            return Outcome(True, "recover", {"actions": actions})


def time_token() -> str:
    import time
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime())
