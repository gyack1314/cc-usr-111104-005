"""课程资料库：可恢复的原子发布单元。

目录布局::

    repo/
      index.json                 索引（原子替换；已接收版本不可变）
      .lock                      进程间文件锁（fcntl.flock）
      blobs/<sha256>             原始 ZIP 内容寻址存储
      packages/<pkg>/<rev>/      每个“包ID+修订”一个不可变发布目录
        _meta.json               冻结清单、发布时间、原始包摘要与成员结果
        <成员文件...>
      staging/<token>/           校验通过、等待发布的暂存单元
        PIN.json                 冻结的清单与下载地址
        VERIFIED.json            校验结果（存在即表示整包已完整核验）
        root/                    安全解压出的成员文件
        archive.zip              本次接收下载的原始包

发布是单一可恢复单元，顺序固定为：
1. 校验并写出 VERIFIED.json；2. 重命名 root -> packages/<pkg>/<rev>；
3. 登记 index.json。进程在任意两步之间退出，recover 都能判定：
目标包目录已在索引中 => 发布完成，清理暂存；否则 => 清理暂存与孤立包目录，
已存在的已接收目录始终可读且永不被改写。
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import ConflictError, RecoverableStateError, RejectionError
from .fetcher import Fetcher, PinnedManifest
from .limits import Limits
from .manifest import parse_manifest
from .verifier import VerificationResult, verify_and_stage

_INDEX_NAME = "index.json"
_LOCK_NAME = ".lock"


@dataclass
class StagedUnit:
    token: str
    dir: Path
    root: Path
    archive: Path
    pin_path: Path
    verified_path: Path


def sha256_file(path: Path, chunk_size: int) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class Repository:
    def __init__(self, root: str | Path, limits: Limits) -> None:
        self.root = Path(root)
        self.limits = limits
        self.blobs = self.root / "blobs"
        self.packages = self.root / "packages"
        self.staging = self.root / "staging"
        self.index_path = self.root / _INDEX_NAME
        self.lock_path = self.root / _LOCK_NAME
        self.root.mkdir(parents=True, exist_ok=True)
        self.blobs.mkdir(exist_ok=True)
        self.packages.mkdir(exist_ok=True)
        self.staging.mkdir(exist_ok=True)
        # 即使多进程并发初始化，唯一临时文件名保证两次写入都能原子完成，
        # 且内容相同，最终 index.json 一致。
        if not self.index_path.exists():
            self._write_index({"version": 1, "packages": {}})

    # ---- 基础工具 -------------------------------------------------------

    @contextlib.contextmanager
    def locked(self):
        with open(self.lock_path, "a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def read_index(self) -> dict:
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    @staticmethod
    def _atomic_write_json(path: Path, payload: dict) -> None:
        """同目录唯一临时文件 + fsync + 原子替换，可安全并发调用。"""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix="." + path.name + ".", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise

    def _write_index(self, payload: dict) -> None:
        self._atomic_write_json(self.index_path, payload)

    def package_dir(self, package_id: str, revision: int) -> Path:
        # package_id 只用作目录名，先做严格白名单校验，杜绝路径元素注入。
        if (
            not package_id
            or package_id in (".", "..")
            or any(c in package_id for c in "/\\\x00")
            or package_id != package_id.strip()
        ):
            raise RejectionError("bad-package-id", "包ID 不能作为安全目录名", package_id=package_id)
        return self.packages / package_id / str(revision)

    @staticmethod
    def _write_json_atomic(path: Path, payload: dict) -> None:
        Repository._atomic_write_json(path, payload)

    def _store_blob(self, archive: Path) -> str:
        key = sha256_file(archive, self.limits.chunk_size)
        target = self.blobs / key
        if target.exists():
            return key
        fd, name = tempfile.mkstemp(prefix=".part-", dir=self.blobs)
        try:
            with os.fdopen(fd, "wb") as out, open(archive, "rb") as src:
                shutil.copyfileobj(src, out, self.limits.chunk_size)
                out.flush()
                os.fsync(out.fileno())
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return key

    # ---- 暂存单元 -------------------------------------------------------

    def new_staging(self, token: str) -> StagedUnit:
        unit_dir = self.staging / token
        if unit_dir.exists():
            raise RejectionError("staging-exists", "暂存令牌已存在", token=token)
        root = unit_dir / "root"
        root.mkdir(parents=True)
        return StagedUnit(
            token=token,
            dir=unit_dir,
            root=root,
            archive=unit_dir / "archive.zip",
            pin_path=unit_dir / "PIN.json",
            verified_path=unit_dir / "VERIFIED.json",
        )

    def write_pin(self, unit: StagedUnit, pinned: PinnedManifest, source: str) -> None:
        payload = {
            "source": source,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **Fetcher.dump_pinned(pinned),
        }
        self._write_json_atomic(unit.pin_path, payload)

    def verify_staging(self, unit: StagedUnit, pinned: PinnedManifest) -> VerificationResult:
        result = verify_and_stage(unit.archive, pinned.manifest, unit.root, self.limits)
        # VERIFIED.json 最后写出：它的存在即代表整包核验完整。
        self._write_json_atomic(
            unit.verified_path,
            {
                "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "result": result.to_dict(),
            },
        )
        return result

    # ---- 发布与恢复 -----------------------------------------------------

    def publish(self, unit: StagedUnit, pinned: PinnedManifest, result: VerificationResult,
                *, crash_after_rename: bool = False) -> dict:
        """把已核验暂存单元发布为不可变版本。调用方必须持有锁。"""
        manifest = pinned.manifest
        target = self.package_dir(manifest.package_id, manifest.revision)
        index = self.read_index()
        existing = index.get("packages", {}).get(manifest.package_id, {}).get(str(manifest.revision))
        if existing is not None:
            if existing["sha256"] == manifest.sha256:
                # 同 ID+修订+同摘要：幂等复用，不触碰已发布目录。
                shutil.rmtree(unit.dir, ignore_errors=True)
                return {"action": "reused", **existing}
            raise ConflictError(
                "相同包ID与修订已对应不同内容，拒绝覆盖已接收版本",
                package_id=manifest.package_id,
                revision=manifest.revision,
                existing_sha256=existing["sha256"],
                incoming_sha256=manifest.sha256,
            )

        if target.exists():
            # 目录存在但索引无记录：上次在改名后、登记前崩溃，先交给 recover 判定。
            raise RecoverableStateError(
                "目标发布目录已存在但索引无记录，先运行 recover",
                target=str(target),
            )

        blob_key = self._store_blob(unit.archive)
        target.parent.mkdir(parents=True, exist_ok=True)
        # 关键改名：同文件系统内的原子 rename。
        os.rename(unit.root, target)
        if crash_after_rename:
            # 演示用：模拟进程在改名与登记之间退出（os._exit，不执行任何清理）。
            os._exit(42)
        meta = {
            "package_id": manifest.package_id,
            "revision": manifest.revision,
            "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "archive": {
                "sha256": manifest.sha256,
                "size": manifest.size,
                "blob": blob_key,
                "archive_url": pinned.archive_url,
                "manifest_url": pinned.manifest_url,
            },
            "manifest": manifest.raw,
            "verification": result.to_dict(),
        }
        self._write_json_atomic(target / "_meta.json", meta)

        index.setdefault("packages", {}).setdefault(manifest.package_id, {})[
            str(manifest.revision)
        ] = {
            "revision": manifest.revision,
            "sha256": manifest.sha256,
            "size": manifest.size,
            "path": str(target.relative_to(self.root)),
            "published_at": meta["published_at"],
            "members": len(manifest.members),
        }
        self._write_index(index)
        shutil.rmtree(unit.dir, ignore_errors=True)
        return {
            "action": "published",
            **index["packages"][manifest.package_id][str(manifest.revision)],
        }

    def recover(self) -> list[dict]:
        """扫描暂存区并修复所有半成品；已发布内容保持可读不变。"""
        actions: list[dict] = []
        index = self.read_index()

        def _index_entry(pkg: str, rev: int) -> dict | None:
            return index.get("packages", {}).get(pkg, {}).get(str(rev))

        # 1) 逐个判定暂存单元。
        for unit_dir in sorted(self.staging.iterdir()):
            if not unit_dir.is_dir():
                continue
            pin_file = unit_dir / "PIN.json"
            root = unit_dir / "root"
            if not pin_file.exists():
                shutil.rmtree(unit_dir, ignore_errors=True)
                actions.append({"unit": unit_dir.name, "action": "removed-incomplete-no-pin"})
                continue

            pin = json.loads(pin_file.read_text(encoding="utf-8"))
            manifest = pin["manifest"]
            pkg, rev = manifest["package_id"], manifest["revision"]
            target = self.package_dir(pkg, rev)
            verified = (unit_dir / "VERIFIED.json").exists()
            entry = _index_entry(pkg, rev)

            if entry is not None and entry["sha256"] == manifest["sha256"]:
                # 发布已完成（改名与登记都完成）：只清理暂存，发布目录原样保留。
                shutil.rmtree(unit_dir, ignore_errors=True)
                actions.append({"unit": unit_dir.name, "action": "already-published-cleaned-staging"})
                continue
            if target.exists() and not verified:
                # 改名后、登记前崩溃且无 VERIFIED 佐证：孤立发布目录不可信，连同暂存移除。
                shutil.rmtree(target, ignore_errors=True)
                shutil.rmtree(unit_dir, ignore_errors=True)
                actions.append({"unit": unit_dir.name, "action": "removed-orphan-package-and-staging"})
                continue
            # 未走到改名步骤的半成品（含已核验但未改名）：整体清理，调用方重新接收。
            if root.exists() or unit_dir.exists():
                shutil.rmtree(unit_dir, ignore_errors=True)
                actions.append({"unit": unit_dir.name, "action": "removed-unfinished-staging"})

        # 2) 反向兜底：packages 下存在但索引没有登记的孤立目录
        #    （例如暂存元数据已丢失，只剩改名后的目录）。
        known = {
            (pkg, int(rev))
            for pkg, revs in index.get("packages", {}).items()
            for rev in revs
        }
        if self.packages.exists():
            for pkg_dir in sorted(self.packages.iterdir()):
                if not pkg_dir.is_dir():
                    continue
                for rev_dir in sorted(pkg_dir.iterdir()):
                    if not rev_dir.is_dir():
                        continue
                    try:
                        rev = int(rev_dir.name)
                    except ValueError:
                        continue
                    if (pkg_dir.name, rev) not in known:
                        shutil.rmtree(rev_dir, ignore_errors=True)
                        actions.append({
                            "unit": f"{pkg_dir.name}/{rev_dir.name}",
                            "action": "removed-orphan-package",
                        })
                # 包目录已空则一并移除，保持 packages 树整洁。
                if pkg_dir.exists() and not any(pkg_dir.iterdir()):
                    pkg_dir.rmdir()
        return actions

    # ---- 离线重验 -------------------------------------------------------

    def offline_reverify(self, package_id: str, revision: int) -> dict:
        """不接触网络，对已接收版本重新做完整流式校验。"""
        target = self.package_dir(package_id, revision)
        if not target.is_dir():
            raise RejectionError(
                "unknown-package",
                "指定的已接收版本不存在",
                package_id=package_id,
                revision=revision,
            )
        meta = json.loads((target / "_meta.json").read_text(encoding="utf-8"))
        parsed = parse_manifest(meta["manifest"])
        blob = self.blobs / meta["archive"]["sha256"]
        if not blob.is_file():
            raise RejectionError(
                "blob-missing",
                "原始包 blob 缺失，无法离线重验",
                sha256=meta["archive"]["sha256"],
            )
        if sha256_file(blob, self.limits.chunk_size) != meta["archive"]["sha256"]:
            raise RejectionError("blob-corrupt", "原始包 blob 摘要不符")

        # 在独立临时暂存目录里重新解压校验，绝不触碰已发布目录。
        token = f"reverify-{package_id}-{revision}-{os.urandom(4).hex()}"
        tmp_root = self.staging / token
        tmp_root.mkdir(parents=True)
        try:
            result = verify_and_stage(blob, parsed, tmp_root, self.limits)
            published_files = sorted(
                p.relative_to(target).as_posix()
                for p in target.rglob("*")
                if p.is_file() and p.name != "_meta.json"
            )
            staged_files = sorted(
                p.relative_to(tmp_root).as_posix() for p in tmp_root.rglob("*") if p.is_file()
            )
            if published_files != staged_files:
                raise RejectionError(
                    "reverify-file-list-mismatch",
                    "已发布文件清单与重验结果不一致",
                    published=published_files,
                    restaged=staged_files,
                )
            for rel in published_files:
                old = sha256_file(target / rel, self.limits.chunk_size)
                new = sha256_file(tmp_root / rel, self.limits.chunk_size)
                if old != new:
                    raise RejectionError(
                        "reverify-content-mismatch",
                        "已发布成员与重验内容不一致",
                        member=rel,
                    )
            return {
                "status": "verified",
                "package_id": package_id,
                "revision": revision,
                "result": result.to_dict(),
            }
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
