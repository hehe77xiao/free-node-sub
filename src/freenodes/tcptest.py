"""TCP 连通性预筛：并发建连测试，过滤死节点。"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from freenodes.model import Node


@dataclass
class TcpTestStats:
    checked: int = 0
    alive: int = 0
    dead: int = 0


def _can_connect(node: Node, timeout: float) -> bool:
    try:
        with socket.create_connection((node.server, node.port), timeout=timeout):
            return True
    except (TimeoutError, OSError):
        return False


def filter_alive(nodes: list[Node], timeout: float, workers: int) -> tuple[list[Node], TcpTestStats]:
    """并发 TCP 测试，返回 (存活节点, 统计)。"""
    stats = TcpTestStats(checked=len(nodes))
    if not nodes:
        return [], stats
    results: dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_can_connect, node, timeout): index for index, node in enumerate(nodes)}
        for future, index in futures.items():
            results[index] = future.result()
    alive_nodes = [node for index, node in enumerate(nodes) if results.get(index)]
    stats.alive = len(alive_nodes)
    stats.dead = stats.checked - stats.alive
    return alive_nodes, stats
