from __future__ import annotations

from freenodes.model import Node
from freenodes.pipeline import dedupe
from freenodes.region import detect_region


def _node(name: str, server: str, port: int, uuid: str | None = None, password: str | None = None) -> Node:
    return Node(name=name, protocol="vmess", server=server, port=port, uuid=uuid, password=password)


def test_dedupe_same_credential() -> None:
    a = _node("A", "hk.example.com", 443, uuid="u1")
    b = _node("B-same-host", "HK.example.com", 443, uuid="U1")
    c = _node("C", "us.example.com", 443, uuid="u2")
    result = dedupe([a, b, c])
    assert result == [a, c]


def test_region_flag_emoji() -> None:
    assert detect_region("🇭🇰 01").key == "hk"
    assert detect_region("US-LA-05").key == "us"
    assert detect_region("日本 東京").key == "jp"
    assert detect_region("random node").key == "unknown"
    assert detect_region("🇹🇯 Dushanbe").key == "other"
