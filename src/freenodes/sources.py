"""订阅源配置：从 sources.yaml 加载。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    enabled: bool = True


def load_sources(path: Path) -> list[Source]:
    """读取 sources.yaml，返回启用的源列表。"""
    raw_text = path.read_text(encoding="utf-8")
    data: object = yaml.safe_load(raw_text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} 顶层必须是映射")
    entries: object = data.get("sources")
    if not isinstance(entries, list):
        raise ValueError(f"{path} 缺少 sources 列表")
    sources: list[Source] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        url = entry.get("url")
        if not isinstance(name, str) or not isinstance(url, str):
            continue
        enabled = entry.get("enabled", True)
        sources.append(Source(name=name, url=url, enabled=bool(enabled)))
    return [s for s in sources if s.enabled]
