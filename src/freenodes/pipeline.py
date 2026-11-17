"""流水线：抓取 → 解码 → 去重 → TCP 测活 → 导出。"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from freenodes.decode import decode_content
from freenodes.export import clash, singbox
from freenodes.fetch import FetchResult, fetch_source, make_client
from freenodes.model import Node
from freenodes.region import detect_region
from freenodes.sources import Source, load_sources
from freenodes.tcptest import TcpTestStats, filter_alive

CLASH_FILENAME = "satelite-clash.yaml"
SINGBOX_FILENAME = "satelite-singbox.json"
NODES_FILENAME = "nodes.json"
META_FILENAME = "meta.json"


@dataclass
class RunOptions:
    sources_path: Path
    out_dir: Path
    test_tcp: bool = True
    timeout: float = 3.0
    workers: int = 300
    max_nodes: int = 0  # 0 = 不限制


@dataclass
class RunStats:
    source_results: list[FetchResult] = field(default_factory=list)
    fetched: int = 0
    fetch_failed: int = 0
    parsed: int = 0
    parse_skipped: int = 0
    after_dedupe: int = 0
    tcp: TcpTestStats = field(default_factory=TcpTestStats)
    exported: int = 0
    singbox_skipped: int = 0
    region_counts: dict[str, int] = field(default_factory=dict)
    protocol_counts: dict[str, int] = field(default_factory=dict)


def dedupe(nodes: list[Node]) -> list[Node]:
    """按 dedupe_key 去重，保留先出现的节点（源列表顺序即优先级）。"""
    seen: set[tuple[str, str, int, str]] = set()
    result: list[Node] = []
    for node in nodes:
        key = node.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        result.append(node)
    return result


def run_pipeline(options: RunOptions, log: Callable[[str], None] = print) -> RunStats:
    sources: list[Source] = load_sources(options.sources_path)
    stats = RunStats()
    all_nodes: list[Node] = []
    with make_client() as client:
        for source in sources:
            result = fetch_source(source, client)
            stats.source_results.append(result)
            if result.content is None:
                stats.fetch_failed += 1
                log(f"[抓取失败] {source.name}: {result.error}")
                continue
            stats.fetched += 1
            decoded = decode_content(result.content, source.name)
            stats.parsed += len(decoded.nodes)
            stats.parse_skipped += decoded.skipped
            log(
                f"[抓取] {source.name}: 格式={decoded.format_name}"
                f" 解析={len(decoded.nodes)} 跳过={decoded.skipped}"
            )
            all_nodes.extend(decoded.nodes)

    deduped = dedupe(all_nodes)
    stats.after_dedupe = len(deduped)
    log(f"[去重] {len(all_nodes)} -> {len(deduped)}")

    if options.test_tcp:
        log(f"[TCP 测活] 共 {len(deduped)} 个，超时 {options.timeout}s，并发 {options.workers}")
        alive, stats.tcp = filter_alive(deduped, timeout=options.timeout, workers=options.workers)
        log(f"[TCP 测活] 存活 {stats.tcp.alive} / {stats.tcp.checked}")
    else:
        alive = deduped
        stats.tcp = TcpTestStats(checked=len(deduped), alive=len(deduped), dead=0)

    if options.max_nodes > 0:
        alive = alive[: options.max_nodes]

    stats.exported = len(alive)
    for node in alive:
        region = detect_region(node.name)
        stats.region_counts[region.group_name] = stats.region_counts.get(region.group_name, 0) + 1
        stats.protocol_counts[node.protocol] = stats.protocol_counts.get(node.protocol, 0) + 1

    now = datetime.now(UTC)
    options.out_dir.mkdir(parents=True, exist_ok=True)
    clash_text = clash.build_clash_yaml(alive, generated_at=now)
    (options.out_dir / CLASH_FILENAME).write_text(clash_text, encoding="utf-8")
    singbox_text, stats.singbox_skipped = singbox.build_singbox_json(alive, generated_at=now)
    (options.out_dir / SINGBOX_FILENAME).write_text(singbox_text, encoding="utf-8")

    node_records = [
        {
            "name": node.name,
            "protocol": node.protocol,
            "server": node.server,
            "port": node.port,
            "region": detect_region(node.name).group_name,
            "source": node.source or "",
        }
        for node in alive
    ]
    (options.out_dir / NODES_FILENAME).write_text(
        json.dumps(node_records, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    meta = {
        "generated_at": now.isoformat(),
        "sources_ok": stats.fetched,
        "sources_failed": stats.fetch_failed,
        "parsed": stats.parsed,
        "after_dedupe": stats.after_dedupe,
        "tcp_alive": stats.tcp.alive,
        "exported": stats.exported,
        "protocols": stats.protocol_counts,
        "regions": stats.region_counts,
    }
    (options.out_dir / META_FILENAME).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log(f"[导出] {options.out_dir / CLASH_FILENAME} 与 {options.out_dir / SINGBOX_FILENAME}")
    return stats


def format_stats(stats: RunStats) -> str:
    lines = [
        f"源: 成功 {stats.fetched} / 失败 {stats.fetch_failed}",
        f"解析节点: {stats.parsed}（跳过条目 {stats.parse_skipped}）",
        f"去重后: {stats.after_dedupe}",
        f"TCP 存活: {stats.tcp.alive} / {stats.tcp.checked}",
        f"导出节点: {stats.exported}（sing-box 跳过 {stats.singbox_skipped}）",
        f"协议分布: {stats.protocol_counts}",
        f"地区分布: {stats.region_counts}",
    ]
    return "\n".join(lines)
