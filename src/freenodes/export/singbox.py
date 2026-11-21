"""导出 sing-box 格式订阅：{"outbounds": [...]}（Satelite 可直接作为订阅导入）。"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

from freenodes.credentials import fix_reality_key, fix_ss_password
from freenodes.export.clash import _unique_tag
from freenodes.model import Node, normalize_network

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

# 实测 Satelite 内嵌 sing-box 1.14.1 接受的 shadowsocks 加密方式。
# 名单外（salsa20 / chacha20 / table / 2022-blake3-chacha8-poly1305 …）会让
# outbound 初始化失败（unknown method），从而带崩整份订阅，必须跳过。
_SS_METHODS = frozenset(
    {
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-cfb",
        "aes-128-ctr",
        "aes-128-gcm",
        "aes-192-cfb",
        "aes-192-ctr",
        "aes-192-gcm",
        "aes-256-cfb",
        "aes-256-ctr",
        "aes-256-gcm",
        "chacha20-ietf",
        "chacha20-ietf-poly1305",
        "rc4-md5",
        "xchacha20",
        "xchacha20-ietf-poly1305",
    }
)

# hysteria2 的 obfs 类型（未知类型是配置级错误，整份配置 decode 失败）
_HY2_OBFS_TYPES = frozenset({"salamander"})

# sing-box 支持的 flow；其余（如 xtls-rprx-vision-udp443）省略
_VALID_FLOWS = {"xtls-rprx-vision", "xtls-rprx-origin", "xtls-rprx-direct", "xtls-rprx-splice"}


def _skip_reason(node: Node) -> str | None:
    """返回该节点不适合 sing-box 的原因；None 表示可以导出。

    sing-box 对 outbound 是「全部初始化成功才算配置合法」，一个坏节点会让
    整份订阅在 Satelite 里直接不可用，所以这里必须先把明显非法的条目剔除。
    """
    if node.protocol in _SKIP_PROTOCOLS:
        return f"协议 {node.protocol} 不支持"
    network = normalize_network(node.network)
    if network and network not in _SUPPORTED_TRANSPORTS:
        return f"传输 {network} 不支持"
    if node.protocol == "ss":
        if not (node.password or "").strip():
            return "缺少口令"
        method = (node.method or "").strip().lower()
        if method and method not in _SS_METHODS:
            return f"加密方式 {method} 不支持"
        fixed = fix_ss_password(node.method, node.password)
        if fixed is not None and not fixed.acceptable:
            return f"口令不是合法的 {node.method} 密钥"
    if node.protocol == "hysteria2" and node.obfs and node.obfs.strip().lower() not in _HY2_OBFS_TYPES:
        return f"hysteria2 obfs 类型 {node.obfs} 不支持"
    reality = fix_reality_key(node.reality_public_key, node.reality_short_id)
    if reality is not None and not reality.acceptable:
        return "reality public_key / short_id 非法"
    return None


def _outbound_dict(node: Node, tag: str) -> dict[str, object]:
    outbound: dict[str, object] = {
        "type": _SINGBOX_TYPE[node.protocol],
        "tag": tag,
        "server": node.server,
        "server_port": node.port,
    }
    reality = fix_reality_key(node.reality_public_key, node.reality_short_id)
    if node.protocol == "ss":
        outbound["method"] = node.method or "aes-256-gcm"
        fixed = fix_ss_password(node.method, node.password)
        outbound["password"] = fixed.password if fixed is not None else ""
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
        if node.obfs and node.obfs.strip().lower() in _HY2_OBFS_TYPES:
            outbound["obfs"] = {
                "type": node.obfs.strip().lower(),
                "password": node.obfs_password or "",
            }
    elif node.protocol == "tuic":
        outbound["uuid"] = node.uuid or ""
        outbound["password"] = node.password or ""

    tls_obj: dict[str, object] = {}
    # tuic 走 QUIC，sing-box 强制要求 tls（缺了会 TLS required 直接失败）
    if node.tls or node.sni or reality is not None or node.protocol in ("hysteria2", "tuic"):
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
        if reality is not None:
            tls_obj["reality"] = {
                "enabled": True,
                "public_key": reality.public_key,
                "short_id": reality.short_id,
            }
            # sing-box reality 客户端强制要求 uTLS；无有效指纹时回落 chrome
            fp = node.fingerprint if node.fingerprint in _VALID_FINGERPRINTS else "chrome"
            tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
    if tls_obj:
        outbound["tls"] = tls_obj

    network = normalize_network(node.network)
    if network and network != "tcp" and node.protocol not in ("hysteria2", "tuic"):
        transport: dict[str, object] = {}
        if network == "ws":
            transport["type"] = "ws"
        elif network == "grpc":
            transport["type"] = "grpc"
            if node.path:
                transport["service_name"] = node.path
        elif network in ("h2", "http"):
            transport["type"] = "http"
        elif network == "xhttp":
            transport["type"] = "xhttp"
        else:
            transport["type"] = network
        if node.path and network != "grpc":
            transport["path"] = node.path
        if node.host:
            transport["headers"] = {"Host": node.host}
        if transport:
            outbound["transport"] = transport
    return outbound


def build_singbox_json(
    nodes: list[Node],
    generated_at: datetime | None = None,
    log: Callable[[str], None] | None = None,
) -> tuple[str, int]:
    """渲染 sing-box outbounds 订阅文本；返回 (文本, 跳过数)。"""
    used_tags: set[str] = set()
    outbounds: list[dict[str, object]] = []
    skipped = 0
    for node in nodes:
        reason = _skip_reason(node)
        if reason is not None:
            skipped += 1
            if log is not None:
                log(f"[sing-box 跳过] {node.name}: {reason}")
            continue
        tag = _unique_tag(node.name, used_tags)
        outbounds.append(_outbound_dict(node, tag))
    document: dict[str, object] = {
        "log": {"level": "info"},
        "outbounds": outbounds,
    }
    return json.dumps(document, ensure_ascii=False, indent=2), skipped
