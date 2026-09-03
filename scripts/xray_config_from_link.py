#!/usr/bin/env python3
"""把 vless:// 分享链接转换成 xray-core 配置文件。

仅支持本项目实际使用的两种组合：
- VLESS + XTLS-RPRX-Vision + REALITY（type=tcp）
- VLESS + TLS + XHTTP（type=xhttp）
生成的配置会同时监听本地 SOCKS 与 HTTP 入站，供浏览器与 Python 进程共用。
"""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import parse_qs, unquote, urlsplit

SOCKS_PORT = 10808
HTTP_PORT = 10809


def _stream_settings(query: dict[str, str]) -> tuple[dict, str]:
    """返回 (streamSettings, flow)。xhttp 传输层不支持 Vision，flow 为空。"""
    security = query.get("security", "")
    network = query.get("type", "tcp")
    sni = query.get("sni", "")
    if not sni:
        raise SystemExit("Share link is missing the sni parameter")

    if security == "reality" and network == "tcp":
        if not query.get("pbk"):
            raise SystemExit("Share link is missing the REALITY pbk parameter")
        return (
            {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": query.get("fp", "chrome"),
                    "publicKey": query["pbk"],
                    "shortId": query.get("sid", ""),
                    "spiderX": query.get("spx", ""),
                },
            },
            query.get("flow", "xtls-rprx-vision"),
        )

    if security == "tls" and network == "xhttp":
        return (
            {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "fingerprint": query.get("fp", "chrome"),
                    "allowInsecure": query.get("allowInsecure", "0") == "1",
                },
                "xhttpSettings": {
                    "host": query.get("host", sni),
                    "path": query.get("path", "/"),
                    "mode": query.get("mode", "auto"),
                },
            },
            "",
        )

    raise SystemExit(
        f"Unsupported combination security={security!r} type={network!r}; "
        "expected reality+tcp or tls+xhttp"
    )


def _build_config(link: str) -> dict:
    parsed = urlsplit(link)
    if parsed.scheme != "vless":
        raise SystemExit(f"Unsupported share link scheme: {parsed.scheme!r}, expected 'vless'")
    if not parsed.username:
        raise SystemExit("Share link is missing the UUID part before '@'")
    if not parsed.hostname or not parsed.port:
        raise SystemExit("Share link is missing the server address or port")

    query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
    stream_settings, flow = _stream_settings(query)

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": HTTP_PORT,
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": parsed.hostname,
                            "port": parsed.port,
                            "users": [
                                {
                                    "id": unquote(parsed.username),
                                    "encryption": query.get("encryption", "none"),
                                    "flow": flow,
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }
        ],
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: xray_config_from_link.py <output-config-path>")

    link = os.getenv("XRAY_LINK", "").strip()
    if not link:
        raise SystemExit("XRAY_LINK is empty; set it to a vless:// share link")

    config = _build_config(link)
    with open(sys.argv[1], "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)

    print(f"xray config written | socks=127.0.0.1:{SOCKS_PORT} http=127.0.0.1:{HTTP_PORT}")


if __name__ == "__main__":
    main()
