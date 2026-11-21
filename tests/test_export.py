from __future__ import annotations

import base64
import json

import yaml

from freenodes.export import clash, singbox
from freenodes.model import Node

# sing-box 要求 reality public_key 是 base64url（无 padding）且解码后 32 字节
REALITY_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


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
            reality_public_key=REALITY_KEY,
            reality_short_id="ab0a",
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
    assert vless["tls"]["reality"]["public_key"] == REALITY_KEY
    hy2 = next(o for o in outbounds if o["type"] == "hysteria2")
    assert hy2["password"] == "pwd"


def test_singbox_repairs_blake3_keys_and_skips_unusable_one() -> None:
    nodes: list[Node] = [
        Node(
            name="SS-escaped",
            protocol="ss",
            server="a.example.com",
            port=50356,
            method="2022-blake3-chacha20-poly1305",
            password="qG5HzrJO2OAzMFY6WDz991qHHonSP2ix6l6jKlHwokY%3D",
        ),
        Node(
            name="SS-unpadded",
            protocol="ss",
            server="b.example.com",
            port=8443,
            method="2022-blake3-aes-128-gcm",
            password="jUbDNsFamcyDfpm+rI3Zyw",
        ),
        Node(
            name="SS-badkey",
            protocol="ss",
            server="c.example.com",
            port=8443,
            method="2022-blake3-aes-256-gcm",
            password="jUbDNsFamcyDfpm+rI3Zyw==",  # 16 字节，长度不符
        ),
    ]
    messages: list[str] = []
    text, skipped = singbox.build_singbox_json(nodes, log=messages.append)
    assert skipped == 1
    by_tag = {o["tag"]: o for o in json.loads(text)["outbounds"]}
    assert by_tag["SS-escaped"]["password"] == "qG5HzrJO2OAzMFY6WDz991qHHonSP2ix6l6jKlHwokY="
    assert by_tag["SS-unpadded"]["password"] == "jUbDNsFamcyDfpm+rI3Zyw=="
    assert "SS-badkey" not in by_tag
    assert any("SS-badkey" in message for message in messages)


def test_singbox_normalizes_reality_key_and_forces_tuic_tls() -> None:
    raw = bytes([0xFF, 0xEF, 0x00]) + bytes(range(29))
    std_key = base64.b64encode(raw).decode()  # 带 padding，sing-box 会拒绝
    url_key = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    nodes: list[Node] = [
        Node(
            name="VL-reality",
            protocol="vless",
            server="a.example.com",
            port=443,
            uuid="11111111-1111-1111-1111-111111111111",
            tls=True,
            reality_public_key=std_key,
            reality_short_id="ab0a5b56",
        ),
        Node(name="TUIC-1", protocol="tuic", server="b.example.com", port=443, uuid="u", password="p"),
    ]
    text, skipped = singbox.build_singbox_json(nodes)
    assert skipped == 0
    by_tag = {o["tag"]: o for o in json.loads(text)["outbounds"]}
    reality = by_tag["VL-reality"]["tls"]["reality"]
    assert reality["public_key"] == url_key
    assert reality["short_id"] == "ab0a5b56"
    assert by_tag["TUIC-1"]["tls"]["enabled"] is True


def test_raw_transport_is_normalized_to_tcp() -> None:
    # v2fly / sing-box 新叫法 raw 就是 TCP；meow / sing-box 都不认 raw，必须归一化
    node = Node(
        name="US-raw",
        protocol="vless",
        server="raw.example.com",
        port=28190,
        uuid="11111111-2222-3333-4444-555555555555",
        network="raw",
        tls=True,
        flow="xtls-rprx-vision",
    )
    proxy = yaml.safe_load(clash.build_clash_yaml([node]))["proxies"][0]
    assert proxy["network"] == "tcp"
    sb_text, skipped = singbox.build_singbox_json([node])
    assert skipped == 0
    outbound = json.loads(sb_text)["outbounds"][0]
    assert "transport" not in outbound  # tcp 用 sing-box 默认直连传输，写出来反而校验失败


def test_singbox_skips_entries_that_would_break_the_whole_config() -> None:
    good_key = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    nodes: list[Node] = [
        Node(
            name="SS-salsa20",
            protocol="ss",
            server="a.example.com",
            port=1,
            method="salsa20",
            password="pw",
        ),
        Node(name="SS-nopw", protocol="ss", server="b.example.com", port=2, method="aes-256-gcm"),
        Node(
            name="HY2-obfs4",
            protocol="hysteria2",
            server="c.example.com",
            port=3,
            password="p",
            obfs="obfs4",
            obfs_password="x",
        ),
        Node(
            name="VL-badsid",
            protocol="vless",
            server="d.example.com",
            port=4,
            uuid="11111111-1111-1111-1111-111111111111",
            tls=True,
            reality_public_key=good_key,
            reality_short_id="zz",
        ),
        Node(
            name="HY2-salamander",
            protocol="hysteria2",
            server="e.example.com",
            port=5,
            password="p",
            obfs="salamander",
            obfs_password="x",
        ),
    ]
    messages: list[str] = []
    text, skipped = singbox.build_singbox_json(nodes, log=messages.append)
    assert skipped == 4
    tags = [o["tag"] for o in json.loads(text)["outbounds"]]
    assert tags == ["HY2-salamander"]
    assert json.loads(text)["outbounds"][0]["obfs"] == {"type": "salamander", "password": "x"}
    assert len(messages) == 4
