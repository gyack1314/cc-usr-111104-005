# 提交包采集器

清单驱动的提交包安全采集器：从本地资料接口取得**清单与归档的冻结快照**，
流式校验通过后，才把整包作为不可变版本原子发布到课程资料库。无第三方依赖，
仅使用 Python 3.11 标准库。

## 威胁模型与设计原则

| 风险 | 对策 |
| --- | --- |
| 同名文件被覆盖（前队资料被盖掉） | 成员文件全部 `O_CREAT|O_EXCL|O_NOFOLLOW` 独占创建，目录也独占创建；绝不调用 `extractall`，任何已存在路径都导致拒收 |
| 路径穿越/符号链接逃逸 | 拒绝绝对路径、盘符、反斜杠、`..`/`.` 段、NUL 与控制字符、Windows 保留设备名；落盘前再做 `realpath` containment 兜底；符号链接与特殊文件模式在解压前拒收 |
| 跨平台同名碰撞 | 成员键统一为 `unicodedata.normalize("NFC", p).casefold()`，清单与 ZIP 两侧都查重；原始路径逐字保留，键同而写法不同也拒收 |
| 只信中央目录被造假 | 本地文件头手工解析，压缩字节从文件真实读取并计数；解压长度、SHA-256、CRC32、压缩比全部在流循环里按真实计数计算，再与本地头/中央目录/清单三方对账 |
| 解压炸弹/超限 | 包字节、成员数、单成员解压字节、总解压字节、压缩比、清单字节均有预算，在流途中超限立即中止；每次只持有一个 64KiB 块 |
| 坏包留下半成品 | 任意步骤失败都整体清空暂存目录；拒收报告与原始包 blob 进入 `quarantine/`，不保存任何解压内容 |
| 清单在接收过程中被更新 | 一次接收只消费**一个冻结信封**（HTTP 单响应同时含清单与归档；file 来源在读取时冻结地址），后续不再访问来源 |
| 进程在发布中途退出 | 发布顺序固定为「核验→原子改名→登记索引」，`recover` 按索引与 `VERIFIED.json` 判定完成/清理；已发布目录永不被改写 |
| 同 ID+修订内容漂移 | 已接收的 `(包ID, 修订)` 不可变；摘要相同则幂等复用，摘要不同报 `revision-conflict` |

## 目录与模块

```
collector/
  manifest.py    清单严格解析与结构校验
  paths.py       成员路径安全规则、NFC+casefold 碰撞键、containment 兜底
  limits.py      流式预算 Budget / 限额配置 Limits
  fetcher.py     冻结信封抓取（HTTP intake-envelope 与 file 来源）
  verifier.py    手工本地头解析 + zlib 流式解压 + 独占安全暂存
  quarantine.py  拒收报告与原始包摘要留存
  repository.py  资料库、索引、文件锁、崩溃恢复、离线重验
  service.py     download/check/accept/reverify/recover 编排
  cli.py         命令行
source_lab/
  envelope_server.py  本地环回信封服务（含轮换响应模式）
bin/
  collector.py        CLI 引导（可在 python -I 下运行）
  make_samples.py     生成 16 类合成样本
  demo_scenarios.py   逐项演示脚本
demo/
  limits-tight.json   成员/总量小预算
  limits-ratio.json   压缩比小预算
```

资料库布局：

```
<repo>/
  index.json                 索引（原子替换）
  .lock                      fcntl 进程间锁
  blobs/<sha256>             原始 ZIP 内容寻址存储
  packages/<id>/<rev>/       不可变发布目录（_meta.json + 成员文件）
  staging/<token>/           暂存单元（PIN.json、VERIFIED.json、root/、archive.zip）
  quarantine/
    blobs/<sha256>           被拒收原始包
    reports/<ts>-<code>-*.json
```

## 四个入口

```sh
# 下载：冻结清单信封、归档落暂存，不解压
python -I bin/collector.py --repo local-repo download demo-data --manifest normal-manifest.json

# 检查：下载 + 全量流式校验 + 安全暂存，不改动索引
python -I bin/collector.py --repo local-repo check demo-data --manifest normal-manifest.json

# 正式接收：校验通过后原子发布
python -I bin/collector.py --repo local-repo accept demo-data --manifest normal-manifest.json

# 离线重验已接收版本（不触网，在独立暂存里重跑全部校验并逐字节对账）
python -I bin/collector.py --repo local-repo reverify demo-package 1

# 崩溃恢复 / 查看索引
python -I bin/collector.py --repo local-repo recover
python -I bin/collector.py --repo local-repo index
```

拒收时进程退出码为 `2`，标准输出为含稳定错误码的 JSON，并生成拒收报告。

## 本地 HTTP 信封来源

```sh
python -I source_lab/envelope_server.py demo-data/normal-envelope.json --port 8801
python -I bin/collector.py --repo local-repo accept http://127.0.0.1:8801/intake-envelope
```

`shifting-envelope.json` 让服务端在两个修订的信封间轮换，可用来观察：每次接收
只消费一个响应快照，两次接收各自冻结、互不串用。

## 限额

`--limits` 指向 JSON，字段：`package_bytes`、`member_count`、`member_bytes`、
`total_bytes`、`max_ratio`（解压字节/实际压缩字节；零压缩长度且非空输出视为
无限）、`manifest_bytes`、`chunk_size`；`0` 表示不限制。所有阈值按**实际流过
的字节**计数，在读取/解压循环中即时生效。

## 拒收错误码

| 代码 | 含义 |
| --- | --- |
| `unsafe-path` / `path-escape` | 非法路径或越出暂存目录 |
| `manifest-collision` / `manifest-not-nfc` | 清单侧碰撞或非 NFC |
| `duplicate-zip-member` / `member-missing` / `member-extra` | 一一对应校验失败 |
| `member-name-mismatch` | 碰撞键相同但原始路径写法不同 |
| `special-file` / `encrypted-entry` / `unsupported-compression` / `unsupported-flags` / `zip64-entry` | 危险条目 |
| `bad-zip-structure` / `bad-compressed-stream` / `crc-mismatch` | 结构、压缩流、CRC 损坏 |
| `member-size-mismatch` / `member-digest-mismatch` / `archive-*-mismatch` | 长度或摘要对账失败 |
| `limit-package-bytes` / `limit-member-count` / `limit-member-bytes` / `limit-total-bytes` / `limit-ratio` / `limit-manifest-bytes` | 预算触发 |
| `revision-conflict` | 同 ID+修订对应不同内容 |
| `envelope-*` / `source-*` | 信封与来源问题 |

## 测试与演示

```sh
python -m unittest discover -s tests -v          # 全部 29 个测试
python -I bin/demo_scenarios.py                  # 六类拒收 + 崩溃恢复逐项演示
python -I bin/make_samples.py demo-data          # 重新生成合成样本
```

所有样本均为本地程序生成的合成文本与确定性字节，不含真实赛事提交或可执行附件。
