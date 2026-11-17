from __future__ import annotations

import base64
import json

from freenodes.parsers import uri


def test_parse_vmess_base64() -> None:
    payload = {
        "v": "2",
        "ps": "🇭🇰 香港 01",
        "add": "hk.example.com",
        "port": "443",
        "id": "b834ed04-a922-4ec3-95b9-c2f0e8e5a2f0",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "path": "/ray",
        "host": "www.example.com",
        "tls": "tls",
        "sni": "hk.example.com",
    }
    link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "vmess"
    assert node.name == "🇭🇰 香港 01"
    assert node.server == "hk.example.com"
    assert node.port == 443
    assert node.uuid == "b834ed04-a922-4ec3-95b9-c2f0e8e5a2f0"
    assert node.network == "ws"
    assert node.path == "/ray"
    assert node.tls is True
    assert node.sni == "hk.example.com"


def test_parse_vless_reality() -> None:
    link = (
        "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        "@1.2.3.4:443?encryption=none&security=reality&sni=www.microsoft.com"
        "&fp=chrome&pb=abc123&sid=dead&flow=xtls-rprx-vision&type=tcp#US-01"
    )
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "vless"
    assert node.name == "US-01"
    assert node.reality_public_key == "abc123"
    assert node.reality_short_id == "dead"
    assert node.fingerprint == "chrome"
    assert node.flow == "xtls-rprx-vision"
    assert node.tls is True


def test_parse_ss_sip002() -> None:
    cred = base64.urlsafe_b64encode(b"aes-256-gcm:my$pass").decode().rstrip("=")
    link = f"ss://{cred}@ss.example.com:8388#Tokyo"
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "ss"
    assert node.method == "aes-256-gcm"
    assert node.password == "my$pass"
    assert node.server == "ss.example.com"
    assert node.port == 8388
    assert node.name == "Tokyo"


def test_parse_ss_legacy() -> None:
    inner = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:pwd123@legacy.example.com:443").decode()
    link = f"ss://{inner}"
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "ss"
    assert node.server == "legacy.example.com"
    assert node.port == 443
    assert node.password == "pwd123"


def test_parse_trojan() -> None:
    link = "trojan://pass123@tj.example.com:443?sni=tj.example.com&type=ws&path=/tj#DE"
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "trojan"
    assert node.password == "pass123"
    assert node.network == "ws"
    assert node.path == "/tj"
    assert node.sni == "tj.example.com"


def test_parse_hysteria2() -> None:
    link = "hy2://uuid-token@hy.example.com:443?sni=hy.example.com&insecure=1&obfs=sotp&obfs-password=secret#HK-hy2"
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "hysteria2"
    assert node.password == "uuid-token"
    assert node.obfs == "sotp"
    assert node.obfs_password == "secret"
    assert node.insecure is True


def test_parse_tuic() -> None:
    link = "tuic://uuid-1:pwd@tuic.example.com:5000?alpn=h3&sni=tuic.example.com#SG-tuic"
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "tuic"
    assert node.uuid == "uuid-1"
    assert node.password == "pwd"
    assert node.alpn == ("h3",)


def test_parse_ssr() -> None:
    password_b64 = base64.urlsafe_b64encode(b"ssrpass").decode().rstrip("=")
    main = f"ssr.example.com:443:origin:plain:plain:{password_b64}"
    encoded = base64.urlsafe_b64encode(main.encode()).decode().rstrip("=")
    link = f"ssr://{encoded}/?obfsparam=&protoparam="
    node = uri.parse_share_link(link, "test")
    assert node is not None
    assert node.protocol == "ssr"
    assert node.password == "ssrpass"
    assert node.server == "ssr.example.com"
    assert node.port == 443


def test_unknown_scheme_returns_none() -> None:
    assert uri.parse_share_link("socks5://user:pass@host:1080", "test") is None
    assert uri.parse_share_link("not-a-link", "test") is None


def test_invalid_server_filtered() -> None:
    assert uri.parse_share_link("ss://YWVzLT1kZWY6cGFzcw@127.0.0.1:8388#x", "test") is None
