#!/usr/bin/env python3
"""采集器命令行引导。

本文件设计为可在 ``python -I``（隔离模式）下运行：解释器不会把 CWD 或
PYTHONPATH 加入 sys.path，因此这里显式把项目根（本文件的上两级）插入
sys.path，避免在不可信数据目录中被植入的 json.py 等模块劫持。
"""
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from collector.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
