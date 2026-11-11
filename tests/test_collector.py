"""采集器单元与集成测试（全部使用本地合成样本，无网络依赖）。

HTTP 相关用例通过 source_lab.envelope_server 绑定环回地址进行，
样本由 bin/make_samples.py 在测试 setUp 时生成到临时目录。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.errors import RejectionError  # noqa: E402
from collector.limits import Limits  # noqa: E402
from collector.manifest import parse_manifest  # noqa: E402
from collector.paths import collision_key, validate_member_path  # noqa: E402
from collector.service import CollectorService  # noqa: E402
from source_lab.envelope_server import start as start_envelope  # noqa: E402

SAMPLE_SCENARIOS = [
    "normal", "collision", "traversal", "missing", "extra", "duplicate",
    "bad-stream", "truncated-stream", "crc", "oversized", "bomb",
    "symlink", "unicode", "broken-central", "revision2", "conflict",
]


class SampleTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="collector-samples-"))
        cls.samples = cls.tmp / "data"
        subprocess.run(
            [sys.executable, "-I", str(PROJECT_ROOT / "bin" / "make_samples.py"), str(cls.samples)],
            check=True, capture_output=True,
        )
        cls.repo_root = cls.tmp / "repo"
        cls.service = CollectorService(cls.repo_root, Limits())

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def scenario_source(self, name: str) -> str:
        return str(self.samples)

    def manifest_arg(self, name: str) -> str:
        return f"{name}-manifest.json"


class PathRuleTests(unittest.TestCase):
    def test_allows_plain_relative_and_keeps_original(self) -> None:
        sp = validate_member_path("team-a/readme.txt")
        self.assertEqual(sp.original, "team-a/readme.txt")
        self.assertEqual(sp.key, collision_key("team-a/readme.txt"))

    def test_rejects_absolute_backslash_parent_nul_drive(self) -> None:
        for bad in ["/abs", "a\\b", "../x", "x/../y", "a//b", "x/", "/",
                    "a\x00b", "C:/x", "CON", "team/nul.txt", "a/./b", ""]:
            with self.subTest(bad=bad):
                with self.assertRaises(RejectionError) as ctx:
                    validate_member_path(bad)
                self.assertEqual(ctx.exception.code, "unsafe-path")

    def test_casefold_and_nfc_collision(self) -> None:
        import unicodedata
        self.assertEqual(
            collision_key("A.txt"), collision_key("a.txt")
        )
        nfd = unicodedata.normalize("NFD", "café")
        nfc = unicodedata.normalize("NFC", "café")
        self.assertEqual(collision_key(nfd), collision_key(nfc))


class ManifestTests(SampleTestBase):
    def test_parse_normal_manifest(self) -> None:
        raw = (self.samples / "normal-manifest.json").read_bytes()
        manifest = parse_manifest(raw)
        self.assertEqual(manifest.package_id, "demo-package")
        self.assertEqual(len(manifest.members), 4)
        zero = next(m for m in manifest.members if m.size == 0)
        self.assertEqual(
            zero.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_manifest_collision_rejected(self) -> None:
        raw = (self.samples / "collision-manifest.json").read_bytes()
        with self.assertRaises(RejectionError) as ctx:
            parse_manifest(raw)
        self.assertEqual(ctx.exception.code, "manifest-collision")

    def test_manifest_traversal_rejected(self) -> None:
        raw = (self.samples / "traversal-manifest.json").read_bytes()
        with self.assertRaises(RejectionError) as ctx:
            parse_manifest(raw)
        self.assertEqual(ctx.exception.code, "unsafe-path")


class RejectionMatrixTests(SampleTestBase):
    def _check(self, name: str, limits: Limits | None = None) -> RejectionError:
        service = CollectorService(self.tmp / f"repo-{name}", limits or Limits())
        outcome = service.check(
            self.scenario_source(name), self.manifest_arg(name)
        )
        self.assertFalse(outcome.ok, name)
        return RejectionError(
            outcome.detail["error"]["code"],
            outcome.detail["error"]["message"],
            **outcome.detail["error"].get("details", {}),
        )

    def test_collision(self) -> None:
        self.assertEqual(self._check("collision").code, "manifest-collision")

    def test_traversal(self) -> None:
        self.assertEqual(self._check("traversal").code, "unsafe-path")

    def test_missing_member(self) -> None:
        self.assertEqual(self._check("missing").code, "member-missing")

    def test_extra_member(self) -> None:
        self.assertEqual(self._check("extra").code, "member-extra")

    def test_duplicate_member(self) -> None:
        self.assertEqual(self._check("duplicate").code, "duplicate-zip-member")

    def test_bad_stream_crc(self) -> None:
        self.assertEqual(self._check("bad-stream").code, "crc-mismatch")

    def test_truncated_stream(self) -> None:
        self.assertEqual(self._check("truncated-stream").code, "bad-compressed-stream")

    def test_broken_central_directory(self) -> None:
        self.assertEqual(self._check("broken-central").code, "bad-zip-structure")

    def test_symlink_rejected(self) -> None:
        self.assertEqual(self._check("symlink").code, "special-file")

    def test_unicode_name_mismatch(self) -> None:
        self.assertEqual(self._check("unicode").code, "member-name-mismatch")

    def test_member_size_limit(self) -> None:
        limits = Limits(member_bytes=100_000, max_ratio=10_000)
        self.assertEqual(self._check("oversized", limits).code, "limit-member-bytes")

    def test_ratio_limit(self) -> None:
        limits = Limits(member_bytes=10_000_000, max_ratio=100)
        self.assertEqual(self._check("bomb", limits).code, "limit-ratio")

    def test_rejected_package_leaves_report_and_blob_not_staging(self) -> None:
        repo = self.tmp / "repo-quarantine"
        service = CollectorService(repo, Limits())
        outcome = service.check(self.scenario_source("missing"), self.manifest_arg("missing"))
        self.assertFalse(outcome.ok)
        report = Path(outcome.report)
        self.assertTrue(report.is_file())
        doc = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(doc["error"]["code"], "member-missing")
        self.assertIsNotNone(doc["archive"])
        self.assertTrue((repo / "quarantine" / "blobs").is_dir())
        # 暂存区必须无半成品残留。
        self.assertEqual(list((repo / "staging").iterdir()), [])


class HappyPathAndPublishingTests(SampleTestBase):
    def test_accept_reuse_and_reverify(self) -> None:
        repo = self.tmp / "repo-happy"
        service = CollectorService(repo, Limits())
        first = service.accept(self.scenario_source("normal"), self.manifest_arg("normal"))
        self.assertTrue(first.ok)
        self.assertEqual(first.detail["action"], "published")

        # 再次接收相同 ID+修订+摘要：幂等复用，不产生新版本。
        second = service.accept(self.scenario_source("normal"), self.manifest_arg("normal"))
        self.assertEqual(second.detail["action"], "reused")

        # 已发布文件逐字节与样本一致。
        target = repo / "packages" / "demo-package" / "1"
        with zipfile.ZipFile(self.samples / "normal.zip") as zf:
            for info in zf.infolist():
                self.assertEqual(
                    (target / info.filename).read_bytes(), zf.read(info.filename)
                )

        # 离线重验通过。
        rev = service.reverify("demo-package", 1)
        self.assertTrue(rev.ok)
        self.assertEqual(rev.detail["status"], "verified")

    def test_revision_conflict_does_not_change_accepted(self) -> None:
        repo = self.tmp / "repo-conflict"
        service = CollectorService(repo, Limits())
        service.accept(self.scenario_source("normal"), self.manifest_arg("normal"))
        index_before = (repo / "index.json").read_text(encoding="utf-8")
        conflict = service.accept(
            self.scenario_source("conflict"), self.manifest_arg("conflict")
        )
        self.assertFalse(conflict.ok)
        self.assertEqual(conflict.detail["error"]["code"], "revision-conflict")
        # 索引与已接收目录均未被改变。
        self.assertEqual((repo / "index.json").read_text(encoding="utf-8"), index_before)
        self.assertTrue((repo / "packages" / "demo-package" / "1" / "_meta.json").is_file())

    def test_distinct_revisions_coexist(self) -> None:
        repo = self.tmp / "repo-revs"
        service = CollectorService(repo, Limits())
        service.accept(self.scenario_source("normal"), self.manifest_arg("normal"))
        service.accept(self.scenario_source("revision2"), self.manifest_arg("revision2"))
        index = json.loads((repo / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(index["packages"]["demo-package"], key=int), ["1", "2"]
        )


class RecoveryTests(SampleTestBase):
    def test_recover_crash_after_rename(self) -> None:
        repo = self.tmp / "repo-recover"
        service = CollectorService(repo, Limits())
        service.accept(self.scenario_source("normal"), self.manifest_arg("normal"))

        # 在子进程里触发“改名后、登记前退出”。
        code = """
import sys
sys.path.insert(0, %r)
from collector.limits import Limits
from collector.service import CollectorService
s = CollectorService(%r, Limits())
outcome = s.accept(%r, %r, crash_after_rename=True)
print(outcome.to_dict())
""" % (
            str(PROJECT_ROOT), str(repo),
            self.scenario_source("revision2"), self.manifest_arg("revision2"),
        )
        proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True)
        self.assertEqual(proc.returncode, 42, proc.stderr.decode())

        # 崩溃后：rev1 可读，rev2 目录孤立存在且未登记。
        self.assertTrue((repo / "packages" / "demo-package" / "1").is_dir())
        self.assertTrue((repo / "packages" / "demo-package" / "2").is_dir())
        index = json.loads((repo / "index.json").read_text(encoding="utf-8"))
        self.assertNotIn("2", index["packages"]["demo-package"])

        # recover 判定并清理。
        recovered = service.recover()
        self.assertTrue(recovered.ok)
        actions = {a["action"] for a in recovered.detail["actions"]}
        self.assertTrue(
            {"removed-orphan-package", "removed-unfinished-staging"} & actions
        )
        self.assertFalse((repo / "packages" / "demo-package" / "2").exists())
        self.assertEqual(list((repo / "staging").iterdir()), [])

        # rev1 仍可离线重验；rev2 可干净地重新接收。
        self.assertTrue(service.reverify("demo-package", 1).ok)
        again = service.accept(
            self.scenario_source("revision2"), self.manifest_arg("revision2")
        )
        self.assertTrue(again.ok)
        self.assertEqual(again.detail["revision"], 2)


class HttpEnvelopeTests(SampleTestBase):
    def test_http_envelope_and_pinning(self) -> None:
        server = start_envelope(str(self.samples / "normal-envelope.json"))
        try:
            port = server.server_port
            url = f"http://127.0.0.1:{port}/intake-envelope"
            # 服务可达性确认。
            with urllib.request.urlopen(url, timeout=5) as resp:
                envelope = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(envelope["envelope_version"], 1)

            repo = self.tmp / "repo-http"
            service = CollectorService(repo, Limits())
            outcome = service.accept(url)
            self.assertTrue(outcome.ok, outcome.detail)
            self.assertEqual(outcome.detail["revision"], 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_http_shifting_envelope_pins_snapshot(self) -> None:
        server = start_envelope(str(self.samples / "shifting-envelope.json"))
        try:
            url = f"http://127.0.0.1:{server.server_port}/intake-envelope"
            repo = self.tmp / "repo-shift"
            service = CollectorService(repo, Limits())
            first = service.accept(url)
            second = service.accept(url)
            self.assertEqual(first.detail["revision"], 1)
            self.assertEqual(second.detail["revision"], 2)
            # 每次接收各自冻结，库内两个修订并存。
            index = json.loads((repo / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(
                sorted(index["packages"]["demo-package"], key=int), ["1", "2"]
            )
        finally:
            server.shutdown()
            server.server_close()


class MemoryBoundednessTests(SampleTestBase):
    def test_bomb_uses_streaming_and_does_not_load_all(self) -> None:
        # 极小 member_bytes 也必须在流途中中止，而不是 OOM；
        # 用一个比解压结果小得多的预算，确认抛出的是限额拒收而非内存错误。
        limits = Limits(member_bytes=1024, max_ratio=10_000)
        service = CollectorService(self.tmp / "repo-mem", limits)
        outcome = service.check(self.scenario_source("bomb"), self.manifest_arg("bomb"))
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.detail["error"]["code"], "limit-member-bytes")
        self.assertEqual(list((service.repo.staging).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
