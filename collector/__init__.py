"""提交包采集器：清单驱动的安全下载、流式校验与原子发布。

模块划分：

* manifest   清单结构与解析（来源数据只在解析时读取一次）
* paths      成员路径安全规则与跨平台碰撞键
* limits     流式预算（包字节、成员数、解压字节、压缩比）
* fetcher    本地资料接口（环回HTTP与file URL），一次接收内固定清单
* verifier   手工解析本地文件头的流式校验与安全暂存（不调用 extractall）
* quarantine 拒收报告与原始包摘要留存
* repository 已接收库、索引、崩溃恢复与离线重验
* service    下载/检查/接收/重验的入口编排
"""

__all__ = [
    "manifest",
    "paths",
    "limits",
    "fetcher",
    "verifier",
    "quarantine",
    "repository",
    "service",
]
