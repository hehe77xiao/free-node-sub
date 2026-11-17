"""导出 sing-box 格式订阅：{"outbounds": [...]}（Satelite 可直接作为订阅导入）。"""

from __future__ import annotations

import json
from datetime import datetime

from freenodes.export.clash import _unique_tag
from freenodes.model import Node

_SINGBOX_TYPE = {
    "ss": "shadowsocks",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
}

# sing-box 不支持的协议会被跳过
_SKIP_PROTOCOLS = {"ssr"}

# 当前 Satelite 自带的 sing-box 构建（1.14.1）里确认可用的传输类型白名单；
# 名单外的传输（如 xhttp / raw）会被跳过，避免整份配置校验失败
_SUPPORTED_TRANSPORTS = {"tcp", "ws", "grpc", "http", "h2", "httpupgrade"}

# sing-box uTLS 支持的指纹（其余如 "unsafe" 直接省略，避免校验失败）
_VALID_FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq"}

# sing-box 支持的 flow；其余（如 xtls-rprx-vision-udp443）省略
_VALID_FLOWS = {"xtls-rprx-vision", "xtls-rprx-origin", "xtls-rprx-direct", "xtls-rprx-splice"}


def _outbound_dict(node: Node, tag: str) -> dict[str, object]:
    outbound: dict[str, object] = {
        "type": _SINGBOX_TYPE[node.protocol],
        "tag": tag,
        "server": node.server,
        "server_port": node.port,
    }
    if node.protocol == "ss":
        outbound["method"] = node.method or "aes-256-gcm"
        outbound["password"] = node.password or ""
    elif node.protocol == "vmess":
        outbound["uuid"] = node.uuid or ""
        outbound["security"] = node.cipher or "auto"
    elif node.protocol == "vless":
        outbound["uuid"] = node.uuid or ""
        if node.flow in _VALID_FLOWS:
            outbound["flow"] = node.flow
        # sing-box 只认 xudp / packetaddr；"none" 必须省略否则校验失败
        if node.encryption in ("xudp", "packetaddr"):
            outbound["packet_encoding"] = node.encryption
    elif node.protocol == "trojan":
        outbound["password"] = node.password or ""
    elif node.protocol == "hysteria2":
        outbound["password"] = node.password or ""
        if node.obfs:
            outbound["obfs"] = {"type": node.obfs, "password": node.obfs_password or ""}
    elif node.protocol == "tuic":
        outbound["uuid"] = node.uuid or ""
        outbound["password"] = node.password or ""

    tls_obj: dict[str, object] = {}
    if node.tls or node.sni or node.reality_public_key or node.protocol == "hysteria2":
        tls_obj["enabled"] = True
        if node.sni:
            tls_obj["server_name"] = node.sni
        if node.insecure:
            tls_obj["insecure"] = True
        if node.alpn:
            tls_obj["alpn"] = list(node.alpn)
        elif node.protocol == "hysteria2":
            tls_obj["alpn"] = ["h3"]
        if node.fingerprint in _VALID_FINGERPRINTS:
            tls_obj["utls"] = {"enabled": True, "fingerprint": node.fingerprint}
        if node.reality_public_key:
            tls_obj["reality"] = {
                "enabled": True,
                "public_key": node.reality_public_key,
                "short_id": node.reality_short_id or "",
            }
            # sing-box reality 客户端强制要求 uTLS；无有效指纹时回落 chrome
            fp = node.fingerprint if node.fingerprint in _VALID_FINGERPRINTS else "chrome"
            tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
    if tls_obj:
        outbound["tls"] = tls_obj

    if node.network and node.network != "tcp" and node.protocol not in ("hysteria2", "tuic"):
        transport: dict[str, object] = {}
        if node.network == "ws":
            transport["type"] = "ws"
        elif node.network == "grpc":
            transport["type"] = "grpc"
            if node.path:
                transport["service_name"] = node.path
        elif node.network in ("h2", "http"):
            transport["type"] = "http"
        elif node.network == "xhttp":
            transport["type"] = "xhttp"
        else:
            transport["type"] = node.network
        if node.path and node.network != "grpc":
            transport["path"] = node.path
        if node.host:
            transport["headers"] = {"Host": node.host}
        if transport:
            outbound["transport"] = transport
    return outbound


def build_singbox_json(nodes: list[Node], generated_at: datetime | None = None) -> tuple[str, int]:
    """渲染 sing-box outbounds 订阅文本；返回 (文本, 跳过数)。"""
    used_tags: set[str] = set()
    outbounds: list[dict[str, object]] = []
    skipped = 0
    for node in nodes:
        if node.protocol in _SKIP_PROTOCOLS:
            skipped += 1
            continue
        if node.network and node.network not in _SUPPORTED_TRANSPORTS:
            skipped += 1
            continue
        tag = _unique_tag(node.name, used_tags)
        outbounds.append(_outbound_dict(node, tag))
    document: dict[str, object] = {
        "log": {"level": "info"},
        "outbounds": outbounds,
    }
    return json.dumps(document, ensure_ascii=False, indent=2), skipped
