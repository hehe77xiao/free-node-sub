"""凭证归一化。

上游免费订阅经常把 base64 口令做 URL 转义（``=`` → ``%3D``），或把 base64 末尾的
padding 去掉。Clash 内核（meow/mihomo）遇到非法口令只会 WARN 并丢掉该节点，
但 sing-box 是 ``initialize outbound`` 失败 → **整份配置 check 不通过**，
一份订阅里一个坏节点就会让 Satelite 全部无法使用。因此导出前统一修正。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import unquote

# 上游做 URL 转义时只会转义这几个在 URL 里有特殊含义的字符；
# 若口令里没有这些转义，就认为 % 是口令本身的内容，不解码，避免误伤
_URL_ESCAPES = ("%3d", "%2f", "%2b", "%3a")

# reality short_id 是 hex 字符串
_HEX_RE = re.compile(r"[0-9a-fA-F]*")

# sing-box 对 SIP002 2022-blake3 系列的要求：口令必须是标准 base64，
# 且解码后的字节数严格等于该方法的密钥长度（实测 sing-box 1.14.1）
_BLAKE3_KEY_LENGTHS: dict[str, int] = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}


@dataclass(frozen=True)
class SsPassword:
    """修正后的 SS 口令。

    acceptable=False 表示这是 2022-blake3 系列且无论如何都凑不出合法密钥，
    导出 sing-box 时必须跳过，否则会带崩整份订阅。
    """

    password: str
    acceptable: bool


def repair_percent_encoding(value: str) -> str:
    """还原被 URL 转义的凭证，如 ``abc%3D%3D`` → ``abc==``。"""
    if "%" not in value:
        return value
    lowered = value.lower()
    if not any(escape in lowered for escape in _URL_ESCAPES):
        return value
    repaired = unquote(value)
    return repaired if repaired != value else value


def _decode_strict(value: str, *, urlsafe: bool) -> bytes | None:
    """严格按给定字母表解码 base64（padding 必须已经正确）；非法写法返回 None。"""
    try:
        return base64.b64decode(value, altchars=b"-_" if urlsafe else None, validate=True)
    except (binascii.Error, ValueError):
        return None


def _base64_bytes(value: str, *, urlsafe: bool) -> bytes | None:
    """严格解码 base64（自动尝试补 / 去 padding）；字母表不匹配则返回 None。

    实测 sing-box 1.14.1：SS 的 2022-blake3 口令只接受标准字母表 + padding，
    reality 的 public_key 只接受 base64url 字母表 + 无 padding。
    """
    missing = -len(value) % 4
    candidates = [value]
    if missing:
        candidates.append(value + "=" * missing)
    if value.endswith("="):
        candidates.append(value.rstrip("="))
    for candidate in candidates:
        raw = _decode_strict(candidate, urlsafe=urlsafe)
        if raw is not None:
            return raw
    return None


def _key_candidates(password: str) -> list[str]:
    """给出候选写法：原样 → 补齐 padding → base64url 字母表转标准字母表。"""
    candidates: list[str] = [password]
    missing = -len(password) % 4
    if missing and "=" not in password:
        candidates.append(password + "=" * missing)
    if "-" in password or "_" in password:
        alternate = password.replace("-", "+").replace("_", "/")
        candidates.append(alternate)
        if missing and "=" not in alternate:
            candidates.append(alternate + "=" * missing)
    return candidates


def fix_ss_password(method: str | None, password: str | None) -> SsPassword | None:
    """修正 SS 口令：先还原 URL 转义，再按 sing-box 要求补齐 base64 padding、转成标准字母表。

    非 2022-blake3 方法的口令是任意字节，无法校验，只做起码的转义还原。
    """
    if password is None:
        return None
    repaired = repair_percent_encoding(password)
    required = _BLAKE3_KEY_LENGTHS.get((method or "").strip().lower())
    if required is None:
        return SsPassword(password=repaired, acceptable=True)
    for candidate in _key_candidates(repaired):
        raw = _decode_strict(candidate, urlsafe=False)
        if raw is not None and len(raw) == required:
            return SsPassword(password=candidate, acceptable=True)
    return SsPassword(password=repaired, acceptable=False)


@dataclass(frozen=True)
class RealityKey:
    """修正后的 reality public_key / short_id；acceptable=False 时该节点必须跳过。"""

    public_key: str
    short_id: str
    acceptable: bool


def fix_reality_key(public_key: str | None, short_id: str | None) -> RealityKey | None:
    """按 sing-box 的要求修正 reality 参数。

    sing-box 1.14.1 实测：public_key 必须是 base64url 字母表、不带 padding、解码后 32 字节；
    short_id 必须是偶数长度且不超过 16 个 hex 字符（更长的会让 sing-box 直接 panic）。
    两者任一非法都会让整份订阅 check 失败，而该节点本身也连不通，所以应当跳过。
    """
    if public_key is None:
        return None
    repaired = repair_percent_encoding(public_key).rstrip("=")
    raw = _base64_bytes(repaired, urlsafe=True) or _base64_bytes(repaired, urlsafe=False)
    if raw is None or len(raw) != 32:
        return RealityKey(public_key=repaired, short_id=short_id or "", acceptable=False)
    normalized_key = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sid = (short_id or "").strip()
    if len(sid) > 16 or len(sid) % 2 != 0 or not _HEX_RE.fullmatch(sid):
        return RealityKey(public_key=normalized_key, short_id=sid, acceptable=False)
    return RealityKey(public_key=normalized_key, short_id=sid, acceptable=True)
