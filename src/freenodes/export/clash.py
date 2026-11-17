"""导出 Clash Meta（mihomo）格式订阅：proxies + 策略组 + 基础分流规则。"""

from __future__ import annotations

from collections import OrderedDict
from datetime import UTC, datetime

import yaml

from freenodes.model import Node
from freenodes.region import Region, detect_region

SELECT_GROUP = "🚀 节点选择"
AUTO_GROUP = "⚡ 自动选择"
SPEEDTEST_URL = "http://www.google.com/generate_204"


def _unique_tag(name: str, used: set[str]) -> str:
    tag = name.strip() or "node"
    candidate = tag
    counter = 2
    while candidate in used:
        candidate = f"{tag}-{counter}"
        counter += 1
    used.add(candidate)
    return candidate


def _proxy_dict(node: Node, tag: str) -> dict[str, object]:
    proxy: dict[str, object] = {"name": tag, "type": node.protocol, "server": node.server, "port": node.port}
    if node.protocol == "ss":
        proxy["cipher"] = node.method or "aes-256-gcm"
        proxy["password"] = node.password or ""
    elif node.protocol == "ssr":
        proxy["cipher"] = node.method or "aes-256-cfb"
        proxy["password"] = node.password or ""
        proxy["protocol"] = node.ssr_protocol or "origin"
        proxy["obfs"] = node.obfs or "plain"
        if node.obfs_param:
            proxy["obfs-param"] = node.obfs_param
    elif node.protocol == "vmess":
        proxy["uuid"] = node.uuid or ""
        proxy["alterId"] = int(node.aid or 0) if (node.aid or "0").isdigit() else 0
        proxy["cipher"] = node.cipher or "auto"
        if node.tls:
            proxy["tls"] = True
        if node.sni:
            proxy["servername"] = node.sni
        if node.reality_public_key:
            proxy["security"] = "reality"
            proxy["reality-opts"] = {
                "public-key": node.reality_public_key,
                "short-id": node.reality_short_id or "",
            }
    elif node.protocol == "vless":
        proxy["uuid"] = node.uuid or ""
        if node.flow:
            proxy["flow"] = node.flow
        proxy["client-encryption"] = node.encryption or "none"
        if node.tls or node.reality_public_key:
            proxy["tls"] = True
        if node.reality_public_key:
            proxy["security"] = "reality"
            proxy["reality-opts"] = {
                "public-key": node.reality_public_key,
                "short-id": node.reality_short_id or "",
            }
    elif node.protocol == "trojan":
        proxy["password"] = node.password or ""
        if node.tls:
            proxy["tls"] = True
    elif node.protocol == "hysteria2":
        proxy["password"] = node.password or ""
        if node.sni:
            proxy["sni"] = node.sni
        if node.obfs:
            proxy["obfs"] = node.obfs
        if node.obfs_password:
            proxy["obfs-password"] = node.obfs_password
    elif node.protocol == "tuic":
        proxy["uuid"] = node.uuid or ""
        proxy["password"] = node.password or ""
        if node.sni:
            proxy["sni"] = node.sni
    if node.network and node.protocol not in ("hysteria2", "tuic", "ss", "ssr"):
        proxy["network"] = node.network
        if node.path and node.network != "grpc":
            proxy["path"] = node.path
        elif node.path:
            proxy["grpc-service-name"] = node.path
        if node.host:
            proxy["host"] = node.host
    if node.tls and node.protocol not in ("hysteria2",):
        proxy["tls"] = True
    if node.sni and "servername" not in proxy and node.protocol not in ("hysteria2", "tuic"):
        proxy["servername"] = node.sni
    if node.fingerprint:
        proxy["client-fingerprint"] = node.fingerprint
    if node.alpn:
        proxy["alpn"] = list(node.alpn)
    if node.insecure:
        proxy["skip-cert-verify"] = True
    return proxy


def build_clash_yaml(nodes: list[Node], generated_at: datetime | None = None) -> str:
    """把节点列表渲染成完整 mihomo YAML 配置文本。"""
    stamp = (generated_at or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M:%S UTC")
    used_tags: set[str] = set()
    proxies: list[dict[str, object]] = []
    tags_by_region: OrderedDict[Region, list[str]] = OrderedDict()
    for node in nodes:
        tag = _unique_tag(node.name, used_tags)
        proxies.append(_proxy_dict(node, tag))
        region = detect_region(node.name)
        tags_by_region.setdefault(region, []).append(tag)

    region_groups: list[dict[str, object]] = []
    region_names: list[str] = []
    for region, tags in tags_by_region.items():
        group_name = region.group_name
        region_names.append(group_name)
        region_groups.append(
            {
                "name": group_name,
                "type": "url-test",
                "url": SPEEDTEST_URL,
                "interval": 600,
                "tolerance": 50,
                "proxies": tags,
            }
        )

    all_tags = [str(p["name"]) for p in proxies]
    proxy_groups: list[dict[str, object]] = [
        {
            "name": SELECT_GROUP,
            "type": "select",
            "proxies": [AUTO_GROUP, *region_names, "DIRECT"],
        },
        {
            "name": AUTO_GROUP,
            "type": "url-test",
            "url": SPEEDTEST_URL,
            "interval": 600,
            "tolerance": 50,
            "proxies": all_tags,
        },
        *region_groups,
    ]
    rules = [
        "GEOSITE,category-ads-all,REJECT",
        "GEOIP,LAN,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        f"MATCH,{SELECT_GROUP}",
    ]
    document: dict[str, object] = {
        "#": f"free-node-sub generated at {stamp}",
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
    }
    return yaml.safe_dump(document, allow_unicode=True, sort_keys=False, width=100)
