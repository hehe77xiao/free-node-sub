"""解析 sing-box JSON 订阅（outbounds）为 Node。"""

from __future__ import annotations

import json

from freenodes.credentials import fix_ss_password, repair_percent_encoding
from freenodes.model import Node, is_valid_server, normalize_network

_TYPE_MAP = {
    "shadowsocks": "ss",
    "ssr": "ssr",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
}


def _as_mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    return None


def _str_at(mapping: dict[str, object], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value != "":
            return value
    return None


def _cred_at(mapping: dict[str, object], *keys: str) -> str | None:
    """读取凭证类字段（uuid / password / token / 公钥），并还原被 URL 转义的写法。"""
    value = _str_at(mapping, *keys)
    if value is None:
        return None
    return repair_percent_encoding(value)


def _int_at(mapping: dict[str, object], *keys: str) -> int | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                continue
    return None


def _node_from_outbound(item: dict[str, object], source: str | None) -> Node | None:
    raw_type = _str_at(item, "type")
    if raw_type is None:
        return None
    protocol = _TYPE_MAP.get(raw_type.lower())
    if protocol is None:
        return None
    server = _str_at(item, "server")
    port = _int_at(item, "server_port", "port")
    if not server or not is_valid_server(server) or port is None or port <= 0 or port > 65535:
        return None
    tag = _str_at(item, "tag") or f"{protocol}-{server}:{port}"
    transport = _as_mapping(item.get("transport")) or {}
    network = normalize_network(_str_at(transport, "type"))
    path = _str_at(transport, "path", "service_name")
    headers = _as_mapping(transport.get("headers")) or {}
    host = _str_at(headers, "Host", "host")
    tls_obj = _as_mapping(item.get("tls")) or {}
    sni = _str_at(tls_obj, "server_name")
    tls_enabled = _str_at(tls_obj, "enabled") is None and bool(sni)
    if tls_obj.get("enabled") is True:
        tls_enabled = True
    insecure = tls_obj.get("insecure") is True
    alpn_value = tls_obj.get("alpn")
    alpn = tuple(str(v) for v in alpn_value) if isinstance(alpn_value, list) else ()
    utls = _as_mapping(tls_obj.get("utls")) or {}
    fingerprint = _str_at(utls, "fingerprint") or _str_at(tls_obj, "fingerprint")
    reality_obj = _as_mapping(tls_obj.get("reality")) or {}
    reality_public_key = _cred_at(reality_obj, "public_key") or _cred_at(
        tls_obj, "reality_public_key", "public_key"
    )
    reality_short_id = _str_at(reality_obj, "short_id") or _str_at(tls_obj, "reality_short_id", "short_id")
    common: dict[str, object] = dict(
        name=tag,
        protocol=protocol,
        server=server,
        port=port,
        network=network,
        path=path,
        host=host,
        tls=tls_enabled,
        sni=sni,
        insecure=insecure,
        alpn=alpn,
        fingerprint=fingerprint,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        source=source,
    )
    if protocol == "ss":
        method = _str_at(item, "method")
        common["method"] = method
        fixed = fix_ss_password(method, _str_at(item, "password"))
        common["password"] = fixed.password if fixed is not None else None
    elif protocol == "ssr":
        common["password"] = _cred_at(item, "password")
        common["method"] = _str_at(item, "method")
    elif protocol == "vmess":
        common["uuid"] = _cred_at(item, "uuid")
        common["cipher"] = _str_at(item, "security") or "auto"
    elif protocol == "vless":
        common["uuid"] = _cred_at(item, "uuid")
        common["flow"] = _str_at(item, "flow")
        common["encryption"] = _str_at(item, "packet_encoding") or "none"
    elif protocol == "trojan":
        common["password"] = _cred_at(item, "password")
    elif protocol == "hysteria2":
        common["password"] = _cred_at(item, "password")
        obfs = _as_mapping(item.get("obfs"))
        if obfs:
            common["obfs"] = _str_at(obfs, "type")
            common["obfs_password"] = _cred_at(obfs, "password")
    elif protocol == "tuic":
        common["uuid"] = _cred_at(item, "uuid")
        common["password"] = _cred_at(item, "password")
    node_kwargs = {k: v for k, v in common.items() if v is not None}
    return Node(**node_kwargs)  # type: ignore[arg-type]


def parse_singbox_content(content: str, source: str | None) -> tuple[list[Node], int]:
    """支持完整配置、outbounds 对象、outbound 数组或单个 outbound。"""
    try:
        data: object = json.loads(content)
    except json.JSONDecodeError:
        return [], 0
    candidates: list[object] = []
    if isinstance(data, list):
        candidates = data
    elif isinstance(data, dict):
        outbounds = data.get("outbounds")
        if isinstance(outbounds, list):
            candidates = outbounds
        elif _str_at(data, "type"):
            candidates = [data]
    nodes: list[Node] = []
    skipped = 0
    for entry in candidates:
        mapping = _as_mapping(entry)
        if mapping is None:
            skipped += 1
            continue
        node = _node_from_outbound(mapping, source)
        if node is None:
            skipped += 1
        else:
            nodes.append(node)
    return nodes, skipped
