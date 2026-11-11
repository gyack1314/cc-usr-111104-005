# 参赛提交包的清单驱动安全资料

此项目维护本地合成来源、协议资料及原始字节工具，用于复查机器人赛事与课程资料。所有名称、数据和地址都不代表真实组织或设备。

`source_lab` 提供资料服务，`sources` 保存业务样本，`workbench.raw_store` 按摘要存取原始字节。HTTP来源的每条路由可依次返回多个响应，最后一个响应会重复；服务仅绑定环回地址。详细数据格式见 [资料约定](docs/source-format.md)。

使用 Python 3.11 或以上版本，无第三方Python依赖。在项目根目录执行：

```sh
python -m unittest discover -s tests -v
python -m compileall -q workbench source_lab collector tests bin
python -m workbench.cli inspect sources
```

启动本地HTTP资料服务：

```sh
python -m source_lab.http sources/normal.json --port 8765
```

## 提交包采集器

`collector` 实现清单驱动的安全采集：从本地资料接口取得清单与归档的冻结信封，
流式校验（路径安全、一一对应、真实字节计数的限额、CRC/摘要/压缩流）通过后，
把整包作为不可变版本原子发布到资料库，并支持崩溃恢复与离线重验。架构、入口、
错误码与威胁模型见 [采集器说明](docs/collector.md)。

```sh
# 生成合成样本（16 类场景，全部为本地合成数据）
python -I bin/make_samples.py demo-data
# 逐项演示：碰撞、穿越、缺项、坏压缩流、限额、中途退出
python -I bin/demo_scenarios.py
# 四个入口：download / check / accept / reverify（外加 recover、index）
python -I bin/collector.py --repo local-repo accept demo-data --manifest normal-manifest.json
python -I bin/collector.py --repo local-repo reverify demo-package 1
# 本地环回 HTTP 信封来源（单次响应即冻结快照）
python -I source_lab/envelope_server.py demo-data/normal-envelope.json --port 8801
```

容器方式可执行 `docker build -t resource-source .`，随后 `docker run --rm resource-source python -m unittest discover -s tests -v`。服务地址只对本次运行有效，客户端应从配置取得地址。输出资料写入单独目录，原始样本保持只读。
