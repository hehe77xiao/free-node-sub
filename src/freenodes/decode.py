"""订阅内容自动嗅探解码：Clash YAML / sing-box JSON / Base64 / 明文分享链接。"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field

from freenodes.model import Node
from freenodes.parsers import clash_yaml, singbox_json, uri

_SCHEMES = ("ss://", "ssr://", "vmess://", "vless://", "trojan://", "hy2://", "hysteria2://", "tuic://")


@dataclass
class DecodeResult:
    nodes: list[Node] = field(default_factory=list)
    skipped: int = 0
    format_name: str = "unknown"


def _is_base64_blob(text: str) -> bool:
    compact = "".join(text.split())
    if len(compact) < 32 or len(compact) % 4 != 0:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(ch in allowed for ch in compact)


def _decode_base64(text: str) -> str | None:
    try:
        raw = base64.b64decode("".join(text.split()), validate=True)
        return raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _parse_uri_lines(lines: list[str], source: str, result: DecodeResult) -> None:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        node = uri.parse_share_link(line, source)
        if node is not None:
            result.nodes.append(node)
        else:
            result.skipped += 1


def decode_content(content: str, source: str, depth: int = 0) -> DecodeResult:
    """识别订阅文本格式并解析为 Node 列表。"""
    result = DecodeResult()
    text = content.strip()
    if not text or depth > 3:
        return result

    # 1) sing-box JSON（数组 / outbounds 对象 / 字符串数组）
    if text.startswith("{") or text.startswith("["):
        nodes, skipped = singbox_json.parse_singbox_content(text, source)
        if nodes:
            result.nodes = nodes
            result.skipped = skipped
            result.format_name = "singbox_json"
            return result

    # 2) 明文分享链接行
    plain_lines = [ln for ln in text.splitlines() if ln.strip().lower().startswith(_SCHEMES)]
    if plain_lines:
        _parse_uri_lines(plain_lines, source, result)
        result.format_name = "uri"
        return result

    # 3) Clash YAML
    if "proxies:" in text or text.startswith("- name:") or "proxy-groups:" in text:
        nodes, skipped = clash_yaml.parse_clash_content(text, source)
        if nodes:
            result.nodes = nodes
            result.skipped = skipped
            result.format_name = "clash_yaml"
            return result

    # 4) Base64 包裹，解出后递归识别
    if _is_base64_blob(text):
        decoded = _decode_base64(text)
        if decoded:
            inner = decode_content(decoded, source, depth + 1)
            if inner.nodes:
                inner.format_name = f"base64({inner.format_name})"
                return inner

    # 5) 兜底：逐行尝试分享链接（混合文本）
    fallback_lines = [ln for ln in text.splitlines() if ln.strip().lower().startswith(_SCHEMES)]
    if fallback_lines:
        _parse_uri_lines(fallback_lines, source, result)
        result.format_name = "uri-mixed"
    return result
