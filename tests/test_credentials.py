from __future__ import annotations

import base64

from freenodes.credentials import fix_reality_key, fix_ss_password, repair_percent_encoding
from freenodes.parsers import clash_yaml

# 线上样本：MetaFetch 订阅把 base64 口令 URL 转义后写进 clash YAML，
# 直接导出给 sing-box 会报 decode key: illegal base64 data at input byte 43
ESCAPED_KEY = "qG5HzrJO2OAzMFY6WDz991qHHonSP2ix6l6jKlHwokY%3D"
REAL_KEY = "qG5HzrJO2OAzMFY6WDz991qHHonSP2ix6l6jKlHwokY="
CHACHA = "2022-blake3-chacha20-poly1305"

# 含 + / 的 32 字节密钥：标准字母表带 padding 与 base64url 无 padding 两种写法
_RAW = bytes([0xFF, 0xEF, 0x00]) + bytes(range(29))
STD_KEY = base64.b64encode(_RAW).decode()
URL_KEY = base64.urlsafe_b64encode(_RAW).decode().rstrip("=")


def test_repair_percent_encoding_recovers_escaped_base64() -> None:
    assert repair_percent_encoding(ESCAPED_KEY) == REAL_KEY
    assert repair_percent_encoding("a%2Fb%2Bc%3A") == "a/b+c:"


def test_repair_percent_encoding_keeps_plain_percent_signs() -> None:
    # 没有 = / + / : 的转义，认为 % 属于口令本身，不解码
    assert repair_percent_encoding("pw%z1") == "pw%z1"
    assert repair_percent_encoding("plain-password") == "plain-password"


def test_blake3_escaped_key_is_recovered() -> None:
    fixed = fix_ss_password(CHACHA, ESCAPED_KEY)
    assert fixed is not None
    assert fixed.acceptable
    assert fixed.password == REAL_KEY


def test_blake3_missing_padding_is_restored() -> None:
    fixed = fix_ss_password(CHACHA, REAL_KEY.rstrip("="))
    assert fixed is not None
    assert fixed.acceptable
    assert fixed.password == REAL_KEY


def test_blake3_rejects_base64url_alphabet_and_repairs_it() -> None:
    # sing-box 只接受标准字母表，base64url 写法必须转回来
    fixed = fix_ss_password(CHACHA, URL_KEY)
    assert fixed is not None
    assert fixed.acceptable
    assert base64.b64decode(fixed.password) == _RAW


def test_blake3_wrong_key_length_is_unacceptable() -> None:
    fixed = fix_ss_password("2022-blake3-aes-256-gcm", "jUbDNsFamcyDfpm+rI3Zyw==")
    assert fixed is not None
    assert not fixed.acceptable


def test_non_blake3_password_only_needs_unescaping() -> None:
    fixed = fix_ss_password("aes-256-gcm", "pw%3Dx")
    assert fixed is not None
    assert fixed.acceptable
    assert fixed.password == "pw=x"
    assert fix_ss_password("aes-256-gcm", None) is None


def test_reality_public_key_is_normalized_to_urlsafe_base64() -> None:
    # sing-box 的 reality public_key 要求 base64url 且不带 padding，
    # 否则报 decode public_key: illegal base64 data at input byte 43
    fixed = fix_reality_key(STD_KEY, "ab0a5b56")
    assert fixed is not None
    assert fixed.acceptable
    assert fixed.public_key == URL_KEY
    assert fixed.short_id == "ab0a5b56"
    assert fix_reality_key(URL_KEY, "") is not None
    assert fix_reality_key(URL_KEY, "").acceptable
    assert fix_reality_key(None, "ab") is None


def test_reality_bad_keys_are_unacceptable() -> None:
    assert not fix_reality_key("short", "ab").acceptable
    assert not fix_reality_key(URL_KEY, "zz").acceptable  # 非 hex
    assert not fix_reality_key(URL_KEY, "abc").acceptable  # 奇数长度
    assert not fix_reality_key(URL_KEY, "ab" * 16).acceptable  # 过长会让 sing-box panic
    assert fix_reality_key(URL_KEY, "").acceptable


def test_clash_yaml_password_is_normalized_at_parse_time() -> None:
    content = f"""
proxies:
  - name: SS-escaped
    type: ss
    server: a.example.com
    port: 50356
    cipher: {CHACHA}
    password: {ESCAPED_KEY}
"""
    nodes, skipped = clash_yaml.parse_clash_content(content, "test")
    assert skipped == 0 and len(nodes) == 1
    assert nodes[0].password == REAL_KEY
