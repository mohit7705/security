#!/usr/bin/env python3
"""Offline microbenchmarks for endpoint normalization and report rendering.

This script uses synthetic data only. It performs no DNS lookups, HTTP requests,
subprocess execution, or target interaction.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from security_analyzer.core.scope_engine import ScopeEngine, ScopePolicy  # noqa: E402
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer  # noqa: E402
from security_analyzer.reporting.html_renderer import HtmlRenderer  # noqa: E402
from security_analyzer.reporting.markdown_renderer import MarkdownRenderer  # noqa: E402


def _measure(operation: Callable[[], None], rounds: int) -> dict[str, float]:
    samples: list[float] = []
    for _ in range(rounds):
        started = time.perf_counter()
        operation()
        samples.append(time.perf_counter() - started)
    median_sec = statistics.median(samples)
    return {
        "median_seconds": round(median_sec, 6),
        "min_seconds": round(min(samples), 6),
        "max_seconds": round(max(samples), 6),
    }


def _synthetic_report(finding_count: int) -> dict:
    findings = []
    for index in range(finding_count):
        findings.append(
            {
                "finding_id": f"bench-{index:06d}",
                "title": f"Synthetic finding {index}",
                "severity": ("HIGH", "MEDIUM", "LOW")[index % 3],
                "verdict": "NEEDS_HUMAN_REVIEW",
                "confidence": 0.5,
                "category": "BENCHMARK",
                "description": "Synthetic benchmark record; not a real vulnerability.",
                "metadata": {
                    "target_url": f"https://bench.example.test/items/{index}",
                    "severity_assessment": {
                        "risk_score": 3.0,
                        "risk_band": "LOW",
                    },
                },
                "resolved_evidence": [],
            }
        )
    return {
        "scan_id": "offline-benchmark",
        "target": "https://bench.example.test",
        "generated_at": "2000-01-01T00:00:00Z",
        "overall_pipeline_status": "PARTIAL",
        "scope": {
            "fingerprint": "0" * 64,
            "allowed_domains": ["bench.example.test"],
            "excluded_paths": [],
            "out_of_scope_blocks_count": 0,
        },
        "coverage": {
            "total_assets": 1,
            "total_endpoints": finding_count,
            "stages": {},
            "skipped_checks": [],
        },
        "summary": {
            "confirmed_count": 0,
            "review_queue_count": finding_count,
            "suppressed_false_positives_count": 0,
            "confirmed_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
        },
        "confirmed_findings": [],
        "review_queue": findings,
        "suppressed_false_positives": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--findings", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    if not 1 <= args.iterations <= 100_000:
        parser.error("--iterations must be between 1 and 100000")
    if not 0 <= args.findings <= 2_000:
        parser.error("--findings must be between 0 and 2000")
    if not 1 <= args.rounds <= 10:
        parser.error("--rounds must be between 1 and 10")

    engine = ScopeEngine(
        ScopePolicy(allowed_domains=["bench.example.test"])
    )
    normalizer = EndpointNormalizer(engine)
    urls = [
        f"https://bench.example.test/api/v1/items/{index}?page={index % 20}&token=synthetic-secret"
        for index in range(args.iterations)
    ]

    def normalize_batch() -> None:
        for url in urls:
            normalizer.normalize(url, source="offline_benchmark")

    report = _synthetic_report(args.findings)
    markdown_renderer = MarkdownRenderer()
    html_renderer = HtmlRenderer()

    def render_batch() -> None:
        markdown_renderer.render(report)
        html_renderer.render(report)

    normalization = _measure(normalize_batch, args.rounds)
    rendering = _measure(render_batch, args.rounds)

    result = {
        "benchmark": "security-analyzer-offline-microbenchmarks",
        "network_access": False,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "rounds": args.rounds,
        "iterations": args.iterations,
        "findings": args.findings,
        "endpoint_normalization": {
            **normalization,
            "operations_per_second": round(
                args.iterations / normalization["median_seconds"], 2
            ) if normalization["median_seconds"] else None,
        },
        "report_rendering": {
            **rendering,
            "operations_per_second": round(
                1 / rendering["median_seconds"], 2
            ) if rendering["median_seconds"] else None,
        },
        "notes": [
            "Synthetic data only; no target traffic was generated.",
            "Results are local microbenchmarks, not end-to-end scan performance guarantees.",
        ],
    }
    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + chr(10), encoding="utf-8")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
