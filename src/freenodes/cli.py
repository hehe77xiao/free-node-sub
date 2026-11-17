"""命令行入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from freenodes.pipeline import RunOptions, format_stats, run_pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="freenodes", description="GitHub 免费节点收集器")
    sub = parser.add_subparsers(dest="command", required=True)
    update = sub.add_parser("update", help="抓取 → 去重 → 测活 → 导出订阅文件")
    update.add_argument(
        "--sources", type=Path, default=PROJECT_ROOT / "config" / "sources.yaml", help="订阅源配置"
    )
    update.add_argument("--out", type=Path, default=PROJECT_ROOT / "output", help="输出目录")
    update.add_argument("--timeout", type=float, default=3.0, help="抓取/TCP 超时秒数")
    update.add_argument("--workers", type=int, default=300, help="TCP 测活并发数")
    update.add_argument("--max-nodes", type=int, default=0, help="导出节点数上限（0=不限）")
    update.add_argument("--no-test", action="store_true", help="跳过 TCP 测活")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "update":
        options = RunOptions(
            sources_path=args.sources,
            out_dir=args.out,
            test_tcp=not args.no_test,
            timeout=args.timeout,
            workers=args.workers,
            max_nodes=args.max_nodes,
        )
        stats = run_pipeline(options)
        print()
        print(format_stats(stats))
        return 0 if stats.exported > 0 else 1
    return 2
