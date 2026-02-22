#!/usr/bin/env python3
"""
benchmark_pipeline.py — measure ingestion and query-path performance.

Outputs:
- Ingestion health from audit_log (processed/new messages, msg/s percentiles)
- Query latency percentiles for filtered hybrid search
- Query latency percentiles for browse-mode search
"""

from __future__ import annotations

import argparse
import asyncio
import random
import re
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import toml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from querybot.search import MessageSearch  # noqa: E402
from shared.db import get_connection_pool  # noqa: E402
from syncer.embeddings import create_embedding_provider  # noqa: E402


_STOPWORDS = {
    "that", "this", "with", "from", "have", "will", "just", "your", "about",
    "what", "when", "where", "which", "there", "their", "they", "them", "into",
    "also", "were", "been", "only", "would", "could", "should", "after", "before",
    "again", "some", "more", "than", "then", "here", "chat", "team", "group",
}


@dataclass
class TimingStats:
    avg_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    n: int


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * p
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def _timing_stats(values: List[float]) -> TimingStats:
    if not values:
        return TimingStats(0.0, 0.0, 0.0, 0.0, 0.0, 0)
    return TimingStats(
        avg_ms=statistics.mean(values),
        p50_ms=_percentile(values, 0.50),
        p95_ms=_percentile(values, 0.95),
        p99_ms=_percentile(values, 0.99),
        max_ms=max(values),
        n=len(values),
    )


def _print_stats(label: str, stats: TimingStats) -> None:
    print(f"{label}:")
    print(f"  runs: {stats.n}")
    print(f"  avg:  {stats.avg_ms:.1f} ms")
    print(f"  p50:  {stats.p50_ms:.1f} ms")
    print(f"  p95:  {stats.p95_ms:.1f} ms")
    print(f"  p99:  {stats.p99_ms:.1f} ms")
    print(f"  max:  {stats.max_ms:.1f} ms")


async def _load_auto_queries(pool, query_count: int, sample_messages: int) -> List[str]:
    rows = await pool.fetch(
        """
        SELECT text
        FROM messages
        WHERE text IS NOT NULL AND LENGTH(text) > 20
        ORDER BY timestamp DESC
        LIMIT $1
        """,
        sample_messages,
    )
    tokens: Dict[str, int] = {}
    for row in rows:
        text = row["text"] or ""
        for tok in re.findall(r"[A-Za-z]{4,}", text):
            word = tok.lower()
            if word in _STOPWORDS:
                continue
            tokens[word] = tokens.get(word, 0) + 1

    ranked = sorted(tokens.items(), key=lambda x: x[1], reverse=True)
    queries = [word for word, _ in ranked[: query_count * 2]]
    random.shuffle(queries)
    return queries[:query_count]


def _load_queries_from_file(path: Path, query_count: int) -> List[str]:
    queries: List[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        queries.append(line)
    return queries[:query_count]


async def _print_ingestion_summary(pool, hours: int) -> None:
    print("Ingestion summary:")
    totals = await pool.fetchrow(
        """
        SELECT
          COUNT(*) AS total_messages,
          COUNT(DISTINCT chat_id) AS total_chats,
          MAX(timestamp) AS last_message_ts
        FROM messages
        """
    )
    print(f"  messages: {totals['total_messages'] or 0}")
    print(f"  chats:    {totals['total_chats'] or 0}")
    print(f"  last msg: {totals['last_message_ts'] or 'none'}")

    try:
        window = await pool.fetchrow(
            """
            WITH sync_rows AS (
              SELECT
                NULLIF(details->>'messages_processed', '')::bigint AS processed,
                NULLIF(details->>'new_messages', '')::bigint AS inserted,
                NULLIF(details->>'rate_msg_per_sec', '')::double precision AS rate
              FROM audit_log
              WHERE service = 'syncer'
                AND action = 'sync_chat'
                AND success = true
                AND timestamp >= NOW() - ($1::int * INTERVAL '1 hour')
            )
            SELECT
              COUNT(*) AS rows_count,
              COALESCE(SUM(processed), 0) AS processed_total,
              COALESCE(SUM(inserted), 0) AS inserted_total,
              COALESCE(AVG(rate), 0) AS avg_rate,
              COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY rate), 0) AS p50_rate,
              COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY rate), 0) AS p95_rate
            FROM sync_rows
            WHERE processed IS NOT NULL AND processed > 0
            """,
            hours,
        )
        print(f"  sync rows ({hours}h): {window['rows_count'] or 0}")
        print(f"  processed:            {window['processed_total'] or 0}")
        print(f"  inserted:             {window['inserted_total'] or 0}")
        print(f"  avg msg/s:            {float(window['avg_rate'] or 0):.1f}")
        print(f"  p50 msg/s:            {float(window['p50_rate'] or 0):.1f}")
        print(f"  p95 msg/s:            {float(window['p95_rate'] or 0):.1f}")
    except Exception:
        print(f"  sync rows ({hours}h): unavailable (no audit_log SELECT permission)")


async def _run_query_benchmark(
    search: MessageSearch,
    queries: List[str],
    runs_per_query: int,
    limit: int,
    days_back: Optional[int],
) -> tuple[TimingStats, Dict[str, TimingStats]]:
    # Warmup one pass to load model/index paths.
    for q in queries:
        await search.filtered_search(
            search_terms=q,
            days_back=days_back,
            limit=limit,
        )

    all_times: List[float] = []
    by_query: Dict[str, List[float]] = {q: [] for q in queries}

    shuffled = list(queries)
    for _ in range(runs_per_query):
        random.shuffle(shuffled)
        for q in shuffled:
            t0 = time.perf_counter()
            await search.filtered_search(
                search_terms=q,
                days_back=days_back,
                limit=limit,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            by_query[q].append(elapsed_ms)
            all_times.append(elapsed_ms)

    per_query_stats = {q: _timing_stats(v) for q, v in by_query.items()}
    return _timing_stats(all_times), per_query_stats


async def _run_browse_benchmark(
    search: MessageSearch,
    runs: int,
    limit: int,
    days_back: int,
) -> TimingStats:
    times: List[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        await search.filtered_search(
            search_terms=None,
            days_back=days_back,
            limit=limit,
        )
        times.append((time.perf_counter() - t0) * 1000.0)
    return _timing_stats(times)


async def _main_async(args: argparse.Namespace) -> int:
    config = toml.load(args.config)
    db_config = dict(config["database"])
    db_config["user"] = args.db_user or config.get("querybot", {}).get("db_user", "tg_querybot")
    db_config["min_size"] = 1
    db_config["max_size"] = max(2, args.pool_size)
    pool = await get_connection_pool(db_config)

    try:
        await _print_ingestion_summary(pool, args.ingestion_hours)

        embedder = create_embedding_provider(config.get("embeddings", {}))
        search = MessageSearch(pool, embedder)

        if args.queries_file:
            queries = _load_queries_from_file(args.queries_file, args.query_count)
        else:
            queries = await _load_auto_queries(pool, args.query_count, args.sample_messages)
        queries = [q for q in queries if q]

        if not queries:
            print("")
            print("No benchmark queries available.")
            print("Provide --queries-file or ensure messages table has enough text.")
            return 2

        print("")
        print("Search benchmark config:")
        print(f"  queries:         {len(queries)}")
        print(f"  runs/query:      {args.runs_per_query}")
        print(f"  result limit:    {args.limit}")
        print(f"  days_back:       {args.days_back if args.days_back is not None else 'all'}")
        print(f"  embedding dim:   {getattr(embedder, 'dimension', 'unknown')}")

        overall, per_query = await _run_query_benchmark(
            search=search,
            queries=queries,
            runs_per_query=args.runs_per_query,
            limit=args.limit,
            days_back=args.days_back,
        )
        print("")
        _print_stats("Hybrid filtered-search latency", overall)

        print("")
        slowest = sorted(per_query.items(), key=lambda kv: kv[1].avg_ms, reverse=True)[:5]
        print("Slowest queries (avg):")
        for q, stat in slowest:
            print(f"  {stat.avg_ms:7.1f} ms  {q}")

        browse_stats = await _run_browse_benchmark(
            search=search,
            runs=args.browse_runs,
            limit=args.browse_limit,
            days_back=args.browse_days_back,
        )
        print("")
        _print_stats("Browse-mode latency (no search_terms)", browse_stats)
        return 0
    finally:
        await pool.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark ingestion + query latency")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/tg-assistant/settings.toml"),
        help="Path to settings.toml",
    )
    parser.add_argument(
        "--db-user",
        type=str,
        default=None,
        help="Database user override (defaults to querybot.db_user)",
    )
    parser.add_argument(
        "--pool-size",
        type=int,
        default=2,
        help="DB pool max size for benchmark client",
    )
    parser.add_argument(
        "--queries-file",
        type=Path,
        default=None,
        help="Optional newline-delimited query list",
    )
    parser.add_argument(
        "--query-count",
        type=int,
        default=12,
        help="How many queries to benchmark",
    )
    parser.add_argument(
        "--sample-messages",
        type=int,
        default=4000,
        help="Recent message rows sampled for auto-query generation",
    )
    parser.add_argument(
        "--runs-per-query",
        type=int,
        default=4,
        help="Benchmark runs per query",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Search result limit",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=30,
        help="days_back filter for filtered search",
    )
    parser.add_argument(
        "--browse-runs",
        type=int,
        default=20,
        help="Browse-mode benchmark runs",
    )
    parser.add_argument(
        "--browse-limit",
        type=int,
        default=50,
        help="Browse-mode result limit",
    )
    parser.add_argument(
        "--browse-days-back",
        type=int,
        default=2,
        help="Browse-mode days_back",
    )
    parser.add_argument(
        "--ingestion-hours",
        type=int,
        default=24,
        help="Window for ingestion summary from audit_log",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if not args.config.exists():
        print(f"Config not found: {args.config}", file=sys.stderr)
        return 1
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
