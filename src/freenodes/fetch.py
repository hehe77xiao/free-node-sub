"""抓取订阅源：直连失败时自动尝试 jsDelivr 镜像。"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from freenodes.sources import Source

USER_AGENT = "clash-verge/v2.0 (free-node-sub)"
FETCH_TIMEOUT = 25.0


@dataclass(frozen=True)
class FetchResult:
    source: Source
    content: str | None
    used_url: str | None
    error: str | None


def candidate_urls(url: str) -> list[str]:
    """生成主地址与镜像地址列表。"""
    urls = [url]
    prefix = "https://raw.githubusercontent.com/"
    if url.startswith(prefix):
        tail = url[len(prefix) :]
        parts = tail.split("/", 2)
        if len(parts) == 3:
            owner, repo, rest = parts
            branch, slash, path = rest.partition("/")
            if slash:
                urls.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}")
    return urls


def fetch_source(source: Source, client: httpx.Client) -> FetchResult:
    """依次尝试各候选地址抓取订阅内容。"""
    errors: list[str] = []
    for url in candidate_urls(source.url):
        try:
            response = client.get(url, timeout=FETCH_TIMEOUT)
            if response.status_code != 200:
                errors.append(f"{url} -> HTTP {response.status_code}")
                continue
            content = response.text
            if len(content.strip()) < 16:
                errors.append(f"{url} -> 内容过短")
                continue
            return FetchResult(source=source, content=content, used_url=url, error=None)
        except httpx.HTTPError as exc:
            errors.append(f"{url} -> {exc}")
    return FetchResult(source=source, content=None, used_url=None, error="; ".join(errors))


def make_client() -> httpx.Client:
    return httpx.Client(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        timeout=FETCH_TIMEOUT,
    )
