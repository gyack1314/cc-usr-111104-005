"""本地接收信封 HTTP 服务（合成资料专用，仅绑定环回地址）。

关键语义：对 ``/intake-envelope`` 的**一次** GET 响应同时携带清单文档与归档
字节（均 base64），构成不可分割的冻结快照。采集器在一次接收内只发这一个
请求，因此服务端随后更新清单不会影响进行中的接收。

用法::

    python -I source_lab/envelope_server.py demo-data/normal-envelope.json --port 8801

配置 JSON：{"dir": "demo-data", "manifest": "normal-manifest.json"}
"""
from __future__ import annotations

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def build_envelope(config_path: Path, *, base_url: str | None = None,
                   manifest_name: str | None = None) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    base = config_path.parent / config["dir"]
    manifest_file = manifest_name or config["manifest"]
    manifest_path = base / manifest_file
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    archive_name = manifest["archive"].lstrip("/")
    archive_raw = (base / archive_name).read_bytes()
    if base_url is None:
        manifest_url = manifest_path.as_uri()
        archive_url = (base / archive_name).as_uri()
    else:
        manifest_url = base_url.rstrip("/") + "/" + manifest_file
        archive_url = base_url.rstrip("/") + "/" + archive_name
    return {
        "envelope_version": 1,
        "manifest": base64.b64encode(manifest_raw).decode("ascii"),
        "archive": base64.b64encode(archive_raw).decode("ascii"),
        "manifest_url": manifest_url,
        "archive_url": archive_url,
    }


def start(config: str, host: str = "127.0.0.1", port: int = 0):
    config_path = Path(config).resolve()
    fixed_config = json.loads(config_path.read_text(encoding="utf-8"))
    # 可选 shift_to：每次请求在主清单与替代清单间轮换，用于演示“一次接收固定”。
    alt_manifest = fixed_config.get("shift_to")
    state = {"count": 0}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != "/intake-envelope":
                self.send_error(404, "use /intake-envelope")
                return
            # 按本次请求的 Host 盖 HTTP 地址，保证采集器的地址一致性对账通过。
            base_url = f"http://{self.headers.get('Host', f'{host}:{port}')}"
            chosen = None
            if alt_manifest:
                chosen = fixed_config["manifest"] if state["count"] == 0 else alt_manifest
                state["count"] += 1
            envelope = build_envelope(config_path, base_url=base_url, manifest_name=chosen)
            payload = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    parser.add_argument("--port", type=int, default=8801)
    args = parser.parse_args()
    server = start(args.config, port=args.port)
    print(json.dumps({"host": "127.0.0.1", "port": server.server_port}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
