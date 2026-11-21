"""统一的节点数据模型：所有来源解析后都归一化为 Node。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Protocol = Literal["ss", "ssr", "vmess", "vless", "trojan", "hysteria2", "tuic"]

# 各内核对同一种传输的不同叫法，统一归一化成 mihomo 风格写法。
# "raw" 是 v2fly / sing-box 对 TCP 传输的新称呼，mihomo、meow(Satelite 的 clash 内核)都不认，
# 会报 unsupported transport: raw；"plain" / "direct" 是 sing-box 对直连 TCP 传输的旧 / 新称呼。
_NETWORK_ALIASES: dict[str, str] = {
    "raw": "tcp",
    "plain": "tcp",
    "direct": "tcp",
}


def normalize_network(value: str | None) -> str | None:
    """把传输别名字段归一化（如 raw → tcp）；空值返回 None。"""
    if value is None:
        return None
    lowered = value.strip().lower()
    if not lowered:
        return None
    return _NETWORK_ALIASES.get(lowered, lowered)


@dataclass(frozen=True)
class Node:
    name: str
    protocol: Protocol
    server: str
    port: int
    # 凭证类字段
    uuid: str | None = None
    password: str | None = None
    method: str | None = None
    cipher: str | None = None
    aid: str | None = None
    # 传输类字段
    network: str | None = None
    path: str | None = None
    host: str | None = None
    # TLS 类字段
    tls: bool = False
    sni: str | None = None
    insecure: bool = False
    alpn: tuple[str, ...] = ()
    fingerprint: str | None = None
    reality_public_key: str | None = None
    reality_short_id: str | None = None
    # 协议私有字段
    flow: str | None = None
    encryption: str | None = None
    ssr_protocol: str | None = None
    obfs: str | None = None
    obfs_param: str | None = None
    obfs_password: str | None = None
    # 元信息
    source: str | None = None

    def dedupe_key(self) -> tuple[str, str, int, str]:
        """去重键：协议 + 服务器 + 端口 + 核心凭证。"""
        credential_parts: list[str] = []
        if self.uuid:
            credential_parts.append(self.uuid.lower())
        if self.password:
            credential_parts.append(self.password)
        if self.protocol in ("ss", "ssr") and self.method:
            credential_parts.append(self.method)
        if self.protocol == "ssr":
            credential_parts.append(self.ssr_protocol or "")
            credential_parts.append(self.obfs or "")
        if self.protocol == "hysteria2":
            credential_parts.append(self.sni or "")
        credential = ":".join(credential_parts)
        return (self.protocol, self.server.lower(), self.port, credential)


def is_valid_server(server: str) -> bool:
    """过滤明显无效的回环 / 占位服务器地址。"""
    lowered = server.strip().lower()
    if not lowered:
        return False
    if lowered in {"0.0.0.0", "127.0.0.1", "localhost", "::1", "example.com", "1.1.1.1", "8.8.8.8"}:  # noqa: S104
        return False
    if lowered.startswith("127."):
        return False
    return True
