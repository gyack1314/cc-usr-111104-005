"""采集器命令行实现：下载、检查、正式接收、离线重验、恢复。

输出统一为单行 JSON（``--pretty`` 可美化），拒收时退出码为 2，
崩溃/用法错误退出码为 1，成功为 0。
"""
from __future__ import annotations

import argparse
import json
import sys

from .errors import CollectorError
from .limits import Limits
from .service import CollectorService


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="collector",
        description="清单驱动的提交包安全采集器",
    )
    parser.add_argument("--repo", required=True, help="课程资料库根目录")
    parser.add_argument("--limits", help="限额 JSON 配置路径")
    parser.add_argument("--pretty", action="store_true", help="缩进输出 JSON")

    sub = parser.add_subparsers(dest="command", required=True)

    p_dl = sub.add_parser("download", help="抓取并冻结清单，下载 ZIP 到暂存（不解压）")
    p_dl.add_argument("source", help="本地来源目录或 http(s)/file URL")
    p_dl.add_argument("--manifest", help="清单相对路径（默认 manifest.json）")

    p_check = sub.add_parser("check", help="下载并完整流式校验、安全暂存，不发布")
    p_check.add_argument("source")
    p_check.add_argument("--manifest")

    p_accept = sub.add_parser("accept", help="校验通过后原子发布到资料库")
    p_accept.add_argument("source")
    p_accept.add_argument("--manifest")
    p_accept.add_argument(
        "--crash-after-rename",
        action="store_true",
        help="演练用：在目录改名后、索引登记前退出进程",
    )

    p_rev = sub.add_parser("reverify", help="离线重验已接收版本")
    p_rev.add_argument("package_id")
    p_rev.add_argument("revision", type=int)

    sub.add_parser("recover", help="恢复/清理上次崩溃留下的暂存半成品")
    sub.add_parser("index", help="打印当前资料库索引")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    limits = Limits.load(args.limits) if args.limits else Limits()
    service = CollectorService(args.repo, limits)

    try:
        if args.command == "download":
            outcome = service.download(args.source, args.manifest)
        elif args.command == "check":
            outcome = service.check(args.source, args.manifest)
        elif args.command == "accept":
            outcome = service.accept(
                args.source, args.manifest,
                crash_after_rename=args.crash_after_rename,
            )
        elif args.command == "reverify":
            outcome = service.reverify(args.package_id, args.revision)
        elif args.command == "recover":
            outcome = service.recover()
        elif args.command == "index":
            print(json.dumps(
                service.repo.read_index(),
                ensure_ascii=False,
                indent=2 if args.pretty else None,
            ))
            return 0
        else:  # pragma: no cover - argparse 已拦截
            return 1
    except CollectorError as exc:
        payload = {"ok": False, "error": getattr(exc, "message", str(exc))}
        print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
        return 2

    payload = outcome.to_dict()
    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
    return 0 if payload.get("ok", True) else 2
