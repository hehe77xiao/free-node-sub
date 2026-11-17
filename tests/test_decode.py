from __future__ import annotations

import base64

from freenodes.decode import decode_content

_VMESS_JSON = (
    '{"v":"2","ps":"T1","add":"a.example.com","port":"443",'
    '"id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"tcp","tls":""}'
)


def _link() -> str:
    return "vmess://" + base64.b64encode(_VMESS_JSON.encode()).decode()


def test_decode_plain_uri_lines() -> None:
    content = f"{_link()}\n{_link()}\n"
    result = decode_content(content, "src")
    assert result.format_name == "uri"
    assert len(result.nodes) == 2


def test_decode_base64_wrapped() -> None:
    content = base64.b64encode(f"{_link()}\n".encode()).decode()
    result = decode_content(content, "src")
    assert result.format_name.startswith("base64")
    assert len(result.nodes) == 1


def test_decode_clash_yaml() -> None:
    content = """
proxies:
  - name: HK-vmess
    type: vmess
    server: hk.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    servername: hk.example.com
  - name: US-hy2
    type: hysteria2
    server: us.example.com
    port: 443
    password: pwd
    sni: us.example.com
  - name: bad-wireguard
    type: wireguard
    server: wg.example.com
    port: 51820
"""
    result = decode_content(content, "src")
    assert result.format_name == "clash_yaml"
    assert len(result.nodes) == 2
    assert result.skipped == 1
    protocols = {n.protocol for n in result.nodes}
    assert protocols == {"vmess", "hysteria2"}


def test_decode_singbox_outbounds() -> None:
    content = """
{
  "outbounds": [
    {"type": "vless", "tag": "NL-1", "server": "nl.example.com", "server_port": 443,
     "uuid": "11111111-2222-3333-4444-555555555555",
     "tls": {"enabled": true, "server_name": "nl.example.com",
             "reality": {"enabled": true, "public_key": "pk", "short_id": "si"}}},
    {"type": "direct", "tag": "direct"}
  ]
}
"""
    result = decode_content(content, "src")
    assert result.format_name == "singbox_json"
    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.protocol == "vless"
    assert node.reality_public_key == "pk"
    assert node.reality_short_id == "si"


def test_decode_garbage_returns_empty() -> None:
    result = decode_content("hello world this is not a subscription at all", "src")
    assert result.nodes == []
