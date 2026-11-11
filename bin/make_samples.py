#!/usr/bin/env python3
"""生成采集器演示所需的全部合成样本（本地程序生成，无真实提交/可执行附件）。

每个场景在输出目录下生成三件套：
``<name>.zip``、``<name>-manifest.json``、``<name>.json``（本地HTTP路由配置，
可直接交给 source_lab.http 启动）。

场景覆盖：
normal 正常包（含零字节成员）、collision 路径碰撞、traversal 穿越、
missing 清单缺项、extra ZIP 多项、duplicate ZIP 重复成员、
bad-stream 压缩流损坏、crc 篡改、oversized 解压超限、bomb 压缩比超限、
symlink 符号链接条目、conflict 同ID修订不同内容、unicode Unicode 归一化。
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import zipfile
import zlib
from pathlib import Path

# 让本脚本在 python -I 下也能导入项目模块。
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_manifest(package_id: str, revision: int, archive: str,
                  members: list[tuple[str, bytes, str]], mode: int | None = None) -> dict:
    return {
        "package_id": package_id,
        "revision": revision,
        "archive": "/" + archive,
        "size": 0,  # 由 build_zip 回填
        "sha256": "",
        "members": [
            {
                "path": path,
                "size": len(content),
                "sha256": sha256_hex(content),
                "role": role,
                **({"mode": mode} if mode is not None else {}),
            }
            for path, content, role in members
        ],
    }


def build_zip(path: Path, entries: list, *, comment: bytes = b"") -> None:
    """entries: (name, data|None, compress_type, external_attr|None)。

    data 为 None 时表示目录条目。external_attr 可用于制造符号链接条目。
    重复传入同名条目即可在一个 ZIP 中产生重复成员。
    """
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.comment = comment
        for entry in entries:
            name, data, compress, external = entry
            info = zipfile.ZipInfo(name)
            info.compress_type = compress
            if external is not None:
                info.external_attr = external
            else:
                info.external_attr = (0o100644 << 16) if data is not None else (0o040755 << 16)
            if data is None:
                zf.writestr(info, b"")
            else:
                zf.writestr(info, data, compress_type=compress)


def finalize_manifest(manifest_path: Path, zip_path: Path, manifest: dict) -> None:
    raw = zip_path.read_bytes()
    manifest["size"] = len(raw)
    manifest["sha256"] = sha256_hex(raw)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_route(out: Path, name: str) -> None:
    config = {
        "routes": [
            {"path": "/manifest.json", "responses": [
                {"status": 200, "headers": [], "file": f"{name}-manifest.json"}]},
            {"path": f"/{name}.zip", "responses": [
                {"status": 200, "headers": [["Content-Type", "application/zip"]],
                 "file": f"{name}.zip"}]},
        ]
    }
    (out / f"{name}.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_envelope_config(out: Path, name: str) -> None:
    """信封服务端配置：指向同目录下的清单文件。"""
    config = {"dir": ".", "manifest": f"{name}-manifest.json"}
    (out / f"{name}-envelope.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def scenario(out: Path, name: str, manifest: dict, entries: list) -> None:
    zip_path = out / f"{name}.zip"
    build_zip(zip_path, entries)
    finalize_manifest(out / f"{name}-manifest.json", zip_path, manifest)
    write_route(out, name)
    write_envelope_config(out, name)


# ---- 特殊篡改工具 --------------------------------------------------------

def corrupt_deflate_stream(zip_path: Path) -> None:
    """翻转第一个 deflate 数据块中的一个字节，制造 CRC/流错误而不破坏中央目录。"""
    with zipfile.ZipFile(zip_path) as zf:
        info = zf.infolist()[0]
        offset = info.header_offset
        with open(zip_path, "rb") as f:
            f.seek(offset)
            header = f.read(30)
        name_len = struct.unpack("<H", header[26:28])[0]
        extra_len = struct.unpack("<H", header[28:30])[0]
        data_offset = offset + 30 + name_len + extra_len
    with open(zip_path, "r+b") as f:
        f.seek(data_offset + 1)  # 偏移 1 通常落在 deflate 压缩数据内部
        original = f.read(1)
        f.seek(data_offset + 1)
        f.write(bytes([original[0] ^ 0xFF]))


def truncate_central_directory(zip_path: Path) -> None:
    """截断 EOCD，模拟中央目录损坏的坏包。"""
    raw = zip_path.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    # 保留 EOCD 签名但截掉其后的大部分内容。
    zip_path.write_bytes(raw[: eocd + 6])


def corrupt_deflate_block(zip_path: Path) -> None:
    """原地用随机字节覆盖压缩数据尾部，保持 ZIP 布局与中央目录不变。

    被覆盖的是 deflate 流末端，通常令 zlib 在收尾时报“不完整块”错误。
    """
    with zipfile.ZipFile(zip_path) as zf:
        info = zf.infolist()[0]
        offset = info.header_offset
        with open(zip_path, "rb") as f:
            f.seek(offset)
            header = f.read(30)
        name_len = struct.unpack("<H", header[26:28])[0]
        extra_len = struct.unpack("<H", header[28:30])[0]
        data_offset = offset + 30 + name_len + extra_len
        csize = info.compress_size
    raw = bytearray(zip_path.read_bytes())
    start = data_offset + max(0, csize - 4)
    for pos in range(start, data_offset + csize):
        raw[pos] = (raw[pos] + 0x5A) & 0xFF
    zip_path.write_bytes(bytes(raw))


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-data")
    out.mkdir(parents=True, exist_ok=True)

    # 公共合成内容
    readme_a = b"team-a synthetic readme\n"
    data_bin = bytes((i * 7 + 3) % 256 for i in range(128))
    readme_b = b"team-b"
    empty = b""

    # 1) normal：含零字节成员的有效包
    normal_members = [
        ("team-a/readme.txt", readme_a, "readme"),
        ("team-a/data.bin", data_bin, "resource"),
        ("team-b/readme.txt", readme_b, "document"),
        ("empty.txt", empty, "resource"),
    ]
    scenario(out, "normal",
             make_manifest("demo-package", 1, "normal.zip", normal_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in normal_members])

    # 2) collision：A.txt 与 a.txt 在 casefold 后碰撞
    collision_members = [("A.txt", b"a", "resource"), ("a.txt", b"b", "resource")]
    scenario(out, "collision",
             make_manifest("demo-package", 1, "collision.zip", collision_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in collision_members])

    # 3) traversal：父路径穿越成员
    trav_members = [("../escape.txt", b"x", "resource")]
    scenario(out, "traversal",
             make_manifest("demo-package", 1, "traversal.zip", trav_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in trav_members])

    # 4) missing：清单 4 个成员，ZIP 只有 3 个（empty.txt 缺失）
    missing_manifest = make_manifest("demo-package", 1, "missing.zip", normal_members)
    scenario(out, "missing", missing_manifest,
             [(n, d, zipfile.ZIP_DEFLATED, None)
              for n, d, _ in normal_members if n != "empty.txt"])

    # 5) extra：清单 3 个成员，ZIP 多出一个
    extra_manifest_members = normal_members[:3]
    scenario(out, "extra",
             make_manifest("demo-package", 1, "extra.zip", extra_manifest_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in normal_members])

    # 6) duplicate：ZIP 内同名成员出现两次（中央目录层面重复）
    dup_members = [("note.txt", b"first\n", "resource")]
    dup_entries = [
        ("note.txt", b"first\n", zipfile.ZIP_DEFLATED, None),
        ("note.txt", b"second-content\n", zipfile.ZIP_DEFLATED, None),
    ]
    scenario(out, "duplicate",
             make_manifest("demo-package", 1, "duplicate.zip", dup_members),
             dup_entries)

    # 7) bad-stream：压缩流字节被篡改（deflate 仍可解压但内容改变，CRC 对账失败）。
    #    清单按篡改后的 ZIP 字节回填摘要，使包级摘要检查通过，
    #    从而暴露出内层的 CRC 错误（而不是停在摘要层）。
    bad_members = [("team-a/readme.txt", readme_a, "readme")]
    bad_manifest = make_manifest("demo-package", 1, "bad-stream.zip", bad_members)
    build_zip(out / "bad-stream.zip",
              [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in bad_members])
    corrupt_deflate_stream(out / "bad-stream.zip")
    finalize_manifest(out / "bad-stream-manifest.json", out / "bad-stream.zip", bad_manifest)
    write_route(out, "bad-stream")
    write_envelope_config(out, "bad-stream")

    # 7a) truncated-stream：压缩数据末端被破坏，zlib 解压阶段即失败
    trunc_members = [("team-a/readme.txt", readme_a, "readme")]
    trunc_manifest = make_manifest("demo-package", 1, "truncated-stream.zip", trunc_members)
    build_zip(out / "truncated-stream.zip",
              [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in trunc_members])
    corrupt_deflate_block(out / "truncated-stream.zip")
    finalize_manifest(
        out / "truncated-stream-manifest.json", out / "truncated-stream.zip", trunc_manifest
    )
    write_route(out, "truncated-stream")
    write_envelope_config(out, "truncated-stream")

    # 8) crc：内容被换但伪造清单长度/摘要为新内容，触发 CRC 与成员摘要对账
    #    做法：ZIP 内放替换内容，清单仍声明旧内容。
    crc_zip_members = [("team-a/readme.txt", b"tampered content!!\n", "readme")]
    scenario(out, "crc",
             make_manifest("demo-package", 1, "crc.zip", bad_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in crc_zip_members])

    # 9) oversized：单成员 200000 字节，配合小预算触发 member_bytes 限制
    large = (b"0123456789abcdef" * 12500)  # 200000
    oversized_members = [("large.txt", large, "resource")]
    scenario(out, "oversized",
             make_manifest("demo-package", 1, "oversized.zip", oversized_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in oversized_members])

    # 10) bomb：高压缩比 deflate 流（100KB 零 -> 约 100 字节压缩数据）
    bomb = b"\x00" * (100 * 1024)
    bomb_members = [("zeros.bin", bomb, "resource")]
    scenario(out, "bomb",
             make_manifest("demo-package", 1, "bomb.zip", bomb_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in bomb_members])

    # 11) symlink：ZIP 中放入符号链接模式条目（链接目标也是合成字符串）
    link_target = b"normal-target.txt"
    sym_entries = [
        ("normal-target.txt", b"reachable\n", zipfile.ZIP_DEFLATED, None),
        ("link.txt", link_target, zipfile.ZIP_STORED, (0o120777 << 16)),
    ]
    sym_manifest = make_manifest(
        "demo-package", 1, "symlink.zip",
        [("normal-target.txt", b"reachable\n", "resource"),
         ("link.txt", link_target, "resource")],
    )
    scenario(out, "symlink", sym_manifest, sym_entries)

    # 12) conflict：与 normal 同 ID 同修订，但内容不同
    conflict_members = [("team-a/readme.txt", b"different revision body\n", "readme"),
                        ("empty.txt", empty, "resource")]
    scenario(out, "conflict",
             make_manifest("demo-package", 1, "conflict.zip", conflict_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in conflict_members])

    # 13) unicode：清单使用 NFC 名，ZIP 同键成员使用 NFD 异写名，
    #     碰撞键相同但原始路径逐字不一致，验证“保留原名、拒绝静默改名”。
    import unicodedata
    nfc_name = unicodedata.normalize("NFC", "café/Note.txt")
    nfd_name = unicodedata.normalize("NFD", "café/Note.txt")
    unicode_members_manifest = [
        (nfc_name, b"upper", "resource"),
    ]
    unicode_entries = [
        (nfd_name, b"upper", zipfile.ZIP_DEFLATED, None),
    ]
    uni_manifest = make_manifest("demo-package", 1, "unicode.zip", unicode_members_manifest)
    scenario(out, "unicode", uni_manifest, unicode_entries)

    # 14) broken-central：中央目录截断（结构损坏）。
    #     清单按截断后的字节回填摘要，使下载与包摘要通过，
    #     由 verifier 在打开 ZIP 时给出 bad-zip-structure。
    broken_manifest = make_manifest(
        "demo-package", 1, "broken-central.zip", normal_members
    )
    build_zip(out / "broken-central.zip",
              [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in normal_members])
    truncate_central_directory(out / "broken-central.zip")
    finalize_manifest(
        out / "broken-central-manifest.json", out / "broken-central.zip", broken_manifest
    )
    write_route(out, "broken-central")
    write_envelope_config(out, "broken-central")

    # 15) revision2：demo-package 的合法修订 2，用于验证多版本与复用
    rev2_members = [("team-a/readme.txt", b"revision two body\n", "readme"),
                    ("empty.txt", empty, "resource")]
    scenario(out, "revision2",
             make_manifest("demo-package", 2, "revision2.zip", rev2_members),
             [(n, d, zipfile.ZIP_DEFLATED, None) for n, d, _ in rev2_members])

    # 轮换信封配置：服务端在 rev1 与 rev2 两个信封间轮换，用于演示一次接收固定。
    (out / "shifting-envelope.json").write_text(
        json.dumps(
            {"dir": ".", "manifest": "normal-manifest.json",
             "shift_to": "revision2-manifest.json"},
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )

    print(f"generated {len(list(out.glob('*.zip')))} zip scenarios in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
