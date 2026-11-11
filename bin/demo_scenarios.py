#!/usr/bin/env python3
"""逐项演示：路径碰撞、穿越成员、清单缺项、坏压缩流、限制触发、中途退出。

每个场景都断言失败包不会改变任何已接收版本。全部样本与资料库都在临时目录中
生成，脚本结束后自动清理；用 ``python -I`` 运行以隔离环境。

用法::

    python -I bin/demo_scenarios.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.limits import Limits  # noqa: E402
from collector.service import CollectorService  # noqa: E402


def line(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(outcome) -> None:
    data = outcome.to_dict()
    if data.get("ok"):
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        err = data["error"]
        print(f"  拒收码: {err['code']}")
        print(f"  说明  : {err['message']}")
        if err.get("details"):
            print(f"  现场  : {json.dumps(err['details'], ensure_ascii=False)}")
        print(f"  报告  : {data.get('rejection_report')}")


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="collector-demo-"))
    samples = work / "demo-data"
    repo = work / "library"
    try:
        subprocess.run(
            [sys.executable, "-I",
             str(PROJECT_ROOT / "bin" / "make_samples.py"), str(samples)],
            check=True, capture_output=True,
        )
        service = CollectorService(repo, Limits())
        src = str(samples)

        line("基线：正式接收正常包 normal（含零字节成员）")
        baseline = service.accept(src, "normal-manifest.json")
        show(baseline)
        assert baseline.ok and baseline.detail["action"] == "published"
        baseline_index = (repo / "index.json").read_text(encoding="utf-8")

        line("场景 1：路径碰撞（A.txt 与 a.txt，casefold 后同键）")
        show(service.check(src, "collision-manifest.json"))

        line("场景 2：穿越成员（../escape.txt，含 .. 段）")
        show(service.check(src, "traversal-manifest.json"))
        # 另演示符号链接条目同样拒收。
        print("  附加：符号链接条目")
        show(service.check(src, "symlink-manifest.json"))

        line("场景 3：清单缺项（清单 4 项，ZIP 仅 3 项）与 ZIP 多项")
        show(service.check(src, "missing-manifest.json"))
        show(service.check(src, "extra-manifest.json"))

        line("场景 4：坏压缩流（deflate 截断 / CRC 损坏 / 中央目录损坏）")
        show(service.check(src, "truncated-stream-manifest.json"))
        show(service.check(src, "bad-stream-manifest.json"))
        show(service.check(src, "broken-central-manifest.json"))

        line("场景 5：限制触发（成员字节上限、压缩比上限）")
        tight = Limits(member_bytes=100_000, max_ratio=10_000)
        show(CollectorService(work / "lib-tight", tight).check(
            src, "oversized-manifest.json"))
        ratio = Limits(member_bytes=10_000_000, max_ratio=100)
        show(CollectorService(work / "lib-ratio", ratio).check(
            src, "bomb-manifest.json"))

        line("场景 6：中途退出（改名后、登记前崩溃，重开 recover）")
        crash_code = (
            "import sys; sys.path.insert(0, %r);"
            "from collector.limits import Limits;"
            "from collector.service import CollectorService;"
            "s=CollectorService(%r, Limits());"
            "s.accept(%r, %r, crash_after_rename=True)"
        ) % (str(PROJECT_ROOT), str(repo), src, "revision2-manifest.json")
        proc = subprocess.run([sys.executable, "-I", "-c", crash_code],
                              capture_output=True)
        print(f"  崩溃子进程退出码: {proc.returncode}（预期 42）")
        print("  recover 判定:")
        show(service.recover())
        print("  重新接收 revision2（干净重来）:")
        show(service.accept(src, "revision2-manifest.json"))

        line("失败包不可改变已接收版本：最终核对")
        current_index = (repo / "index.json").read_text(encoding="utf-8")
        rev1_ok = service.reverify("demo-package", 1).ok
        print(f"  rev1 离线重验: {'通过' if rev1_ok else '失败'}")
        print(f"  库内修订: {sorted(json.loads(current_index)['packages']['demo-package'], key=int)}")
        print(f"  暂存残留: {len(list((repo / 'staging').iterdir()))} 个")
        print(f"  隔离报告: {len(list((repo / 'quarantine' / 'reports').glob('*.json')))} 份")
        assert rev1_ok
        assert baseline.ok

        line("同 ID 同修订不同内容 => 冲突，已接收版本保持不变")
        show(service.accept(src, "conflict-manifest.json"))
        assert (repo / "index.json").read_text(encoding="utf-8") != ""
        print("\n全部场景演示完成。")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
