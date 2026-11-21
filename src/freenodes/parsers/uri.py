"""解析节点分享链接 URI：ss / ssr / vmess / vless / trojan / hysteria2 / tuic。"""

from __future__ import annotations

import base64
import binascii
import json
from urllib.parse import parse_qs, unquote, urlsplit

from freenodes.credentials import fix_ss_password, repair_percent_encoding
from freenodes.model import Node, is_valid_server, normalize_network


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded)


def _query_first(params: dict[str, list[str]], *keys: str) -> str | None:
    for key in keys:
        values = params.get(key)
        if values and values[0] != "":
            return values[0]
    return None


def _truthy(value: str | None) -> bool:
    return value is not None and value.lower() in {"1", "true", "yes"}


def _parse_alpn(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part for part in value.replace(",", "|").split("|") if part)


def parse_vmess(rest: str, source: str | None) -> Node | None:
    body: str | None = None
    try:
        body = _b64url_decode(rest).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError):
        body = rest if rest.lstrip().startswith("{") else None
    if body is None:
        return None
    try:
        data: object = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    add = data.get("add")
    port = data.get("port")
    user_id = data.get("id")
    if not isinstance(add, str) or not isinstance(user_id, str) or not is_valid_server(add):
        return None
    try:
        port_int = int(str(port))
    except (TypeError, ValueError):
        return None
    if port_int <= 0 or port_int > 65535:
        return None
    remarks = data.get("ps") or data.get("name") or data.get("remark")
    net = data.get("net") or data.get("type") or "tcp"
    path = data.get("path") or ""
    host = data.get("host") or ""
    aid = str(data.get("aid", "0"))
    cipher = data.get("scy") or data.get("cipher") or "auto"
    tls = str(data.get("tls", "")).lower() == "tls" or str(data.get("security", "")).lower() == "tls"
    sni = data.get("sni")
    name = str(remarks) if remarks else f"vmess-{add}"
    return Node(
        name=name,
        protocol="vmess",
        server=add,
        port=port_int,
        uuid=user_id,
        aid=aid,
        cipher=str(cipher),
        network=normalize_network(str(net)) or "tcp",
        path=str(path) or None,
        host=str(host) or None,
        tls=tls,
        sni=str(sni) if isinstance(sni, str) and sni else None,
        source=source,
    )


def _parse_generic(rest: str, source: str | None, protocol: str) -> Node | None:
    split = urlsplit(f"//{rest}", allow_fragments=True)
    userinfo = split.username or ""
    password = repair_percent_encoding(unquote(userinfo))
    server = split.hostname or ""
    if not is_valid_server(server) or not password:
        return None
    try:
        port = split.port
    except ValueError:
        return None
    if port is None or port <= 0 or port > 65535:
        return None
    params = parse_qs(split.query)
    name = unquote(split.fragment) if split.fragment else f"{protocol}-{server}"
    network = normalize_network(_query_first(params, "type", "network")) or "tcp"
    path = _query_first(params, "path")
    host = _query_first(params, "host")
    security = (_query_first(params, "security") or "").lower()
    sni = _query_first(params, "sni", "peer", "server_name")
    tls = security in {"tls", "reality"} or _truthy(_query_first(params, "tls")) or bool(sni)
    fingerprint = _query_first(params, "fp", "fingerprint")
    alpn = _parse_alpn(_query_first(params, "alpn"))
    insecure = _truthy(_query_first(params, "allowInsecure", "insecure"))
    reality_public_key = _query_first(params, "pb", "publicKey")
    reality_short_id = _query_first(params, "sid", "shortId")
    flow = _query_first(params, "flow")
    encryption = _query_first(params, "encryption")
    node_kwargs: dict[str, object] = dict(
        name=name,
        protocol=protocol,
        server=server,
        port=port,
        password=password,
        network=network,
        path=path,
        host=host,
        tls=tls,
        sni=sni,
        insecure=insecure,
        alpn=alpn,
        fingerprint=fingerprint,
        flow=flow,
        encryption=encryption,
        source=source,
    )
    if reality_public_key:
        node_kwargs["reality_public_key"] = reality_public_key
    if reality_short_id:
        node_kwargs["reality_short_id"] = reality_short_id
    if protocol == "hysteria2":
        node_kwargs["obfs"] = _query_first(params, "obfs")
        node_kwargs["obfs_password"] = _query_first(params, "obfs-password")
    return Node(**node_kwargs)  # type: ignore[arg-type]


def parse_vless(rest: str, source: str | None) -> Node | None:
    split = urlsplit(f"//{rest}", allow_fragments=True)
    uuid = unquote(split.username or "")
    server = split.hostname or ""
    if not is_valid_server(server) or not uuid:
        return None
    try:
        port = split.port
    except ValueError:
        return None
    if port is None or port <= 0 or port > 65535:
        return None
    params = parse_qs(split.query)
    name = unquote(split.fragment) if split.fragment else f"vless-{server}"
    security = (_query_first(params, "security") or "").lower()
    return Node(
        name=name,
        protocol="vless",
        server=server,
        port=port,
        uuid=uuid,
        network=normalize_network(_query_first(params, "type", "network")) or "tcp",
        path=_query_first(params, "path"),
        host=_query_first(params, "host"),
        tls=security in {"tls", "reality"},
        sni=_query_first(params, "sni", "peer"),
        insecure=_truthy(_query_first(params, "allowInsecure")),
        alpn=_parse_alpn(_query_first(params, "alpn")),
        fingerprint=_query_first(params, "fp", "fingerprint"),
        reality_public_key=_query_first(params, "pb", "publicKey"),
        reality_short_id=_query_first(params, "sid", "shortId"),
        flow=_query_first(params, "flow"),
        encryption=_query_first(params, "encryption") or "none",
        source=source,
    )


def parse_trojan(rest: str, source: str | None) -> Node | None:
    return _parse_generic(rest, source, "trojan")


def parse_hysteria2(rest: str, source: str | None) -> Node | None:
    node = _parse_generic(rest, source, "hysteria2")
    return node


def parse_ss(rest: str, source: str | None) -> Node | None:
    fragment = ""
    body = rest
    if "#" in body:
        body, fragment = body.split("#", 1)
    server: str | None = None
    port: int | None = None
    method: str | None = None
    password: str | None = None
    if "@" in body:
        creds, _, hostpart = body.rpartition("@")
        decoded: str | None = None
        if ":" not in creds:
            try:
                decoded = _b64url_decode(creds).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                decoded = None
        credential = decoded if decoded is not None else unquote(creds)
        if ":" in credential:
            method, _, password = credential.partition(":")
        split = urlsplit(f"//{hostpart}")
        server = split.hostname
        port = split.port
    else:
        try:
            decoded_all = _b64url_decode(body).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
        hostpart = decoded_all
        if "@" not in hostpart:
            return None
        credential, _, hostport = hostpart.rpartition("@")
        if ":" not in credential:
            return None
        method, _, password = credential.partition(":")
        split = urlsplit(f"//{hostport}")
        server = split.hostname
        port = split.port
    if not server or port is None or not is_valid_server(server):
        return None
    name = unquote(fragment) if fragment else f"ss-{server}"
    fixed = fix_ss_password(method, password)
    return Node(
        name=name,
        protocol="ss",
        server=server,
        port=port,
        method=method,
        password=fixed.password if fixed is not None else None,
        source=source,
    )


def parse_ssr(rest: str, source: str | None) -> Node | None:
    if "#" in rest:
        rest, _ = rest.split("#", 1)
    try:
        main, _, query = rest.partition("/")
        decoded = _b64url_decode(main).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    fields = decoded.split(":")
    if len(fields) < 6:
        return None
    server, port_s, ssr_protocol, method, obfs, password_b64 = fields[:6]
    try:
        port = int(port_s)
        password = _b64url_decode(password_b64).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not is_valid_server(server) or not password:
        return None
    obfs_param: str | None = None
    remark: str | None = None
    if query.startswith("?"):
        params = parse_qs(query[1:])
        obfs_param = _query_first(params, "obfsparam")
        remark_raw = _query_first(params, "remark")
        if remark_raw:
            try:
                remark = _b64url_decode(remark_raw).decode("utf-8", errors="ignore")
            except binascii.Error:
                remark = None
    name = remark or f"ssr-{server}"
    return Node(
        name=name,
        protocol="ssr",
        server=server,
        port=port,
        password=password,
        method=method,
        ssr_protocol=ssr_protocol,
        obfs=obfs,
        obfs_param=obfs_param or None,
        source=source,
    )


def parse_tuic(rest: str, source: str | None) -> Node | None:
    split = urlsplit(f"//{rest}", allow_fragments=True)
    uuid = unquote(split.username or "")
    password = unquote(split.password or "")
    server = split.hostname or ""
    if not is_valid_server(server) or not uuid:
        return None
    try:
        port = split.port
    except ValueError:
        return None
    if port is None or port <= 0 or port > 65535:
        return None
    params = parse_qs(split.query)
    token = _query_first(params, "token")
    if not password and token:
        password = token
    if not password:
        password = uuid
    name = unquote(split.fragment) if split.fragment else f"tuic-{server}"
    return Node(
        name=name,
        protocol="tuic",
        server=server,
        port=port,
        uuid=uuid,
        password=password,
        sni=_query_first(params, "sni"),
        alpn=_parse_alpn(_query_first(params, "alpn") or "h3"),
        source=source,
    )


_DISPATCH = {
    "ss": parse_ss,
    "ssr": parse_ssr,
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "hy2": parse_hysteria2,
    "hysteria2": parse_hysteria2,
    "tuic": parse_tuic,
}


def parse_share_link(line: str, source: str | None) -> Node | None:
    """解析一条分享链接；未知协议返回 None。"""
    scheme, sep, rest = line.strip().lower().partition("://")
    if not sep:
        scheme, sep, rest = line.strip().lower().partition("://")
        if not sep:
            return None
    handler = _DISPATCH.get(scheme)
    if handler is None:
        return None
    # 保留原始大小写：凭证与 name 区分大小写
    original_rest = line.strip()[len(scheme) + 3 :]
    try:
        return handler(original_rest, source)
    except Exception:
        return None
