from __future__ import annotations

import json

import yaml

from freenodes.export import clash, singbox
from freenodes.model import Node


def _nodes() -> list[Node]:
    return [
        Node(
            name="🇭🇰 HK-1",
            protocol="vmess",
            server="hk.example.com",
            port=443,
            uuid="u1",
            tls=True,
            sni="hk.example.com",
            network="ws",
            path="/ray",
        ),
        Node(
            name="US-2",
            protocol="vless",
            server="us.example.com",
            port=443,
            uuid="u2",
            tls=True,
            sni="us.example.com",
            reality_public_key="pk",
            reality_short_id="si",
            flow="xtls-rprx-vision",
        ),
        Node(
            name="JP-3",
            protocol="hysteria2",
            server="jp.example.com",
            port=443,
            password="pwd",
            sni="jp.example.com",
        ),
        Node(
            name="SSR-4",
            protocol="ssr",
            server="ssr.example.com",
            port=443,
            password="p",
            method="aes-256-cfb",
            ssr_protocol="origin",
            obfs="plain",
        ),
        Node(
            name="HK-1", protocol="trojan", server="tj.example.com", port=443, password="p"
        ),  # 与首个重名，测试唯一 tag
        Node(
            name="US-xhttp",
            protocol="vless",
            server="xhttp.example.com",
            port=443,
            uuid="u9",
            network="xhttp",
            tls=True,
            sni="xhttp.example.com",
        ),
    ]


def test_clash_yaml_structure() -> None:
    text = clash.build_clash_yaml(_nodes())
    doc: dict[str, object] = yaml.safe_load(text)
    proxies = doc["proxies"]
    assert isinstance(proxies, list) and len(proxies) == 6
    names = [p["name"] for p in proxies]
    assert len(set(names)) == 6  # tag 唯一
    groups = doc["proxy-groups"]
    assert isinstance(groups, list)
    group_names = [g["name"] for g in groups]
    assert "🚀 节点选择" in group_names
    assert "⚡ 自动选择" in group_names
    # 所有组引用的节点 / 组名都存在
    known = set(names) | set(group_names) | {"DIRECT"}
    for group in groups:
        for ref in group["proxies"]:
            assert ref in known, ref
    assert isinstance(doc["rules"], list)


def test_singbox_export_skips_ssr_xhttp_and_valid_json() -> None:
    text, skipped = singbox.build_singbox_json(_nodes())
    assert skipped == 2  # ssr + xhttp
    doc = json.loads(text)
    outbounds = doc["outbounds"]
    assert len(outbounds) == 4
    tags = [o["tag"] for o in outbounds]
    assert len(set(tags)) == 4
    types = {o["type"] for o in outbounds}
    assert types == {"vmess", "vless", "hysteria2", "trojan"}
    vless = next(o for o in outbounds if o["type"] == "vless")
    assert vless["tls"]["reality"]["public_key"] == "pk"
    hy2 = next(o for o in outbounds if o["type"] == "hysteria2")
    assert hy2["password"] == "pwd"
