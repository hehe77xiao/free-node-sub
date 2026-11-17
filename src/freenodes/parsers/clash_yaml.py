"""解析 Clash YAML 订阅（proxies 列表）为 Node。"""

from __future__ import annotations

import yaml

from freenodes.model import Node, is_valid_server

_SUPPORTED_TYPES = {
    "ss": "ss",
    "shadowsocks": "ss",
    "ssr": "ssr",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
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
        if isinstance(value, int):
            return str(value)
    return None


def _int_at(mapping: dict[str, object], key: str) -> int | None:
    value = mapping.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _bool_at(mapping: dict[str, object], *keys: str) -> bool:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"true", "1", "yes"}
    return False


def _alpn_at(mapping: dict[str, object]) -> tuple[str, ...]:
    value = mapping.get("alpn")
    if isinstance(value, list):
        return tuple(str(v) for v in value if isinstance(v, (str, int)))
    return ()


def _node_from_mapping(item: dict[str, object], source: str | None) -> Node | None:
    raw_type = _str_at(item, "type")
    if raw_type is None:
        return None
    protocol = _SUPPORTED_TYPES.get(raw_type.lower())
    if protocol is None:
        return None
    server = _str_at(item, "server")
    port = _int_at(item, "port")
    if not server or not is_valid_server(server) or port is None or port <= 0 or port > 65535:
        return None
    name = _str_at(item, "name") or f"{protocol}-{server}:{port}"
    network = _str_at(item, "network")
    path = _str_at(item, "ws-path", "path", "h2-path")
    grpc_service = _str_at(item, "grpc-service-name")
    if grpc_service:
        network = "grpc"
        path = grpc_service
    host = _str_at(item, "host", "ws-host", "h2-host")
    sni = _str_at(item, "servername", "sni", "peer")
    tls = _bool_at(item, "tls") or bool(sni) or _str_at(item, "security") in ("tls", "reality")
    insecure = _bool_at(item, "skip-cert-verify")
    fingerprint = _str_at(item, "client-fingerprint", "fingerprint")
    reality = _as_mapping(item.get("reality-opts")) or {}
    common: dict[str, object] = dict(
        name=name,
        protocol=protocol,
        server=server,
        port=port,
        network=network,
        path=path,
        host=host,
        tls=tls,
        sni=sni,
        insecure=insecure,
        alpn=_alpn_at(item),
        fingerprint=fingerprint,
        reality_public_key=_str_at(reality, "public-key"),
        reality_short_id=_str_at(reality, "short-id"),
        source=source,
    )
    if protocol == "ss":
        common["method"] = _str_at(item, "cipher", "method")
        common["password"] = _str_at(item, "password")
    elif protocol == "ssr":
        common["password"] = _str_at(item, "password")
        common["method"] = _str_at(item, "cipher", "method")
        common["ssr_protocol"] = _str_at(item, "protocol")
        common["obfs"] = _str_at(item, "obfs")
        common["obfs_param"] = _str_at(item, "obfs-param")
    elif protocol == "vmess":
        common["uuid"] = _str_at(item, "uuid")
        common["aid"] = _str_at(item, "alterId", "alter_id") or "0"
        common["cipher"] = _str_at(item, "cipher") or "auto"
    elif protocol == "vless":
        common["uuid"] = _str_at(item, "uuid")
        common["flow"] = _str_at(item, "flow")
        common["encryption"] = _str_at(item, "client-encryption", "encryption") or "none"
        if _str_at(item, "security") == "reality":
            common["tls"] = True
    elif protocol == "trojan":
        common["password"] = _str_at(item, "password")
    elif protocol == "hysteria2":
        common["password"] = _str_at(item, "password")
        common["obfs"] = _str_at(item, "obfs")
        common["obfs_password"] = _str_at(item, "obfs-password")
    elif protocol == "tuic":
        common["uuid"] = _str_at(item, "uuid")
        common["password"] = _str_at(item, "password") or _str_at(item, "token")
    node_kwargs = {k: v for k, v in common.items() if v is not None}
    return Node(**node_kwargs)  # type: ignore[arg-type]


def parse_clash_content(content: str, source: str | None) -> tuple[list[Node], int]:
    """返回 (nodes, skipped)。支持多文档 YAML。"""
    nodes: list[Node] = []
    skipped = 0
    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return nodes, skipped
    for document in documents:
        root = _as_mapping(document)
        entries: list[object] = []
        if root is not None:
            proxies = root.get("proxies")
            if isinstance(proxies, list):
                entries = proxies
        elif isinstance(document, list):
            entries = document
        for entry in entries:
            mapping = _as_mapping(entry)
            if mapping is None:
                skipped += 1
                continue
            node = _node_from_mapping(mapping, source)
            if node is None:
                skipped += 1
            else:
                nodes.append(node)
    return nodes, skipped
