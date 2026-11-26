#!/usr/bin/env python3
"""Offline scorer for a completed scan against a versioned authorized-lab manifest.

This utility reads local JSON artifacts only. It does not contact targets,
launch scanners, or modify the source report/scan-state/manifest files.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any


def _load_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read valid JSON from {path}: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _finding_text(finding: dict[str, Any]) -> tuple[str, str, str]:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    endpoint = (
        _string(metadata.get("mutated_url"))
        or _string(metadata.get("target_url"))
        or _string(metadata.get("url"))
        or _string(finding.get("endpoint_id"))
    )
    return (
        _string(finding.get("category")).casefold(),
        _string(finding.get("title")).casefold(),
        endpoint.casefold(),
    )


def _matches(expected: dict[str, Any], finding: dict[str, Any]) -> bool:
    category, title, endpoint = _finding_text(finding)
    required_category = _string(expected.get("category")).casefold()
    if not required_category or category != required_category:
        return False

    title_fragment = _string(expected.get("title_contains")).casefold()
    endpoint_fragment = _string(expected.get("endpoint_contains")).casefold()
    if title_fragment and title_fragment not in title:
        return False
    if endpoint_fragment and endpoint_fragment not in endpoint:
        return False

    required_severity = _string(expected.get("severity")).upper()
    if required_severity and _string(finding.get("severity")).upper() != required_severity:
        return False
    return True


def _duration_seconds(scan_state: dict[str, Any]) -> float | None:
    stages = scan_state.get("stages") or {}
    if not isinstance(stages, dict):
        raise ValueError("scan_state.stages must be an object")
    values: list[float] = []
    for stage_id, item in stages.items():
        if not isinstance(item, dict):
            continue
        raw = item.get("duration_sec")
        if raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            continue
        value = float(raw)
        if math.isfinite(value) and value >= 0:
            values.append(value)
    return round(sum(values), 3) if values else None


def _nonnegative_int(mapping: dict[str, Any], key: str, label: str) -> int:
    value = mapping.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label}.{key} must be a non-negative integer")
    return value


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def score(
    report: dict[str, Any],
    manifest: dict[str, Any],
    scan_state: dict[str, Any],
) -> dict[str, Any]:
    """Calculate benchmark metrics from a report, manifest and matching scan state."""
    if not all(isinstance(item, dict) for item in (report, manifest, scan_state)):
        raise ValueError("report, manifest and scan_state must be JSON objects")

    report_scan_id = _string(report.get("scan_id"))
    state_scan_id = _string(scan_state.get("scan_id"))
    if not report_scan_id or report_scan_id != state_scan_id:
        raise ValueError("report.scan_id and scan_state.scan_id must both exist and match")

    report_target = _string(report.get("target"))
    state_target = _string(scan_state.get("target"))
    if report_target and state_target and report_target != state_target:
        raise ValueError("report.target and scan_state.target do not match")

    expected = manifest.get("expected_findings")
    if not isinstance(expected, list):
        raise ValueError("manifest.expected_findings must be an array (it may be empty for a safe control)")
    safe_controls = manifest.get("known_safe_controls", [])
    if not isinstance(safe_controls, list):
        raise ValueError("manifest.known_safe_controls must be an array")

    for index, item in enumerate(expected):
        if not isinstance(item, dict):
            raise ValueError(f"manifest.expected_findings[{index}] must be an object")
        if not _string(item.get("category")):
            raise ValueError(f"manifest.expected_findings[{index}].category must be non-empty")
        for key in ("title_contains", "endpoint_contains", "severity", "id"):
            if key in item and not isinstance(item[key], str):
                raise ValueError(f"manifest.expected_findings[{index}].{key} must be a string")

    for index, control in enumerate(safe_controls):
        if not isinstance(control, dict):
            raise ValueError(f"manifest.known_safe_controls[{index}] must be an object")
        if not _string(control.get("endpoint_contains")):
            raise ValueError(
                f"manifest.known_safe_controls[{index}].endpoint_contains must be non-empty"
            )

    confirmed = report.get("confirmed_vulnerabilities")
    if confirmed is None:
        confirmed = report.get("confirmed_findings", [])
    if not isinstance(confirmed, list):
        raise ValueError("report.confirmed_vulnerabilities/confirmed_findings must be an array")
    confirmed = [item for item in confirmed if isinstance(item, dict)]

    matched_indexes: set[int] = set()
    matched: list[dict[str, str]] = []
    missed: list[dict[str, Any]] = []
    for expected_item in expected:
        match_index = next(
            (
                index
                for index, finding in enumerate(confirmed)
                if index not in matched_indexes and _matches(expected_item, finding)
            ),
            None,
        )
        if match_index is None:
            missed.append(expected_item)
            continue
        matched_indexes.add(match_index)
        matched.append(
            {
                "expected_id": _string(expected_item.get("id")),
                "finding_id": _string(confirmed[match_index].get("finding_id")),
                "title": _string(confirmed[match_index].get("title")),
            }
        )

    true_positives = len(matched)
    false_negatives = len(missed)
    false_positives = len(confirmed) - true_positives
    precision = _safe_ratio(true_positives, true_positives + false_positives)
    recall = _safe_ratio(true_positives, true_positives + false_negatives)

    safe_control_hits: list[dict[str, str]] = []
    for index, finding in enumerate(confirmed):
        if index in matched_indexes:
            continue
        _category, _title, endpoint = _finding_text(finding)
        for control in safe_controls:
            fragment = _string(control.get("endpoint_contains")).casefold()
            if fragment in endpoint:
                safe_control_hits.append(
                    {
                        "control_id": _string(control.get("id")),
                        "finding_id": _string(finding.get("finding_id")),
                        "endpoint": endpoint,
                    }
                )
                break

    coverage = report.get("coverage") or {}
    if not isinstance(coverage, dict):
        raise ValueError("report.coverage must be an object")
    total_endpoints = _nonnegative_int(coverage, "total_endpoints", "report.coverage")
    unprobed_endpoints = _nonnegative_int(coverage, "unprobed_endpoints", "report.coverage")
    if unprobed_endpoints > total_endpoints:
        raise ValueError("report.coverage.unprobed_endpoints cannot exceed total_endpoints")
    tested_endpoints = total_endpoints - unprobed_endpoints

    potential = report.get("potential_findings") or []
    review = report.get("needs_human_review") or report.get("review_queue") or []
    if not isinstance(potential, list) or not isinstance(review, list):
        raise ValueError("potential_findings and needs_human_review/review_queue must be arrays")

    summary = {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "endpoint_coverage": _safe_ratio(tested_endpoints, total_endpoints),
        "endpoints_total": total_endpoints,
        "endpoints_unprobed": unprobed_endpoints,
        "endpoints_with_probe_result": tested_endpoints,
        "execution_seconds_sum_of_stage_durations": _duration_seconds(scan_state),
        "potential_findings": len(potential),
        "needs_human_review": len(review),
    }

    return {
        "schema_version": "1.1",
        "benchmark": _string(manifest.get("benchmark")) or "authorized-lab",
        "target_application": _string(manifest.get("target_application")) or "unspecified",
        "scan_id": report_scan_id,
        "target": report_target,
        "overall_pipeline_status": _string(report.get("overall_pipeline_status")) or "UNKNOWN",
        "metrics": summary,
        "matched_expectations": matched,
        "false_negative_expectations": missed,
        "confirmed_findings_on_known_safe_controls": safe_control_hits,
        "unmatched_confirmed_findings": [
            {
                "finding_id": _string(finding.get("finding_id")),
                "category": _string(finding.get("category")),
                "title": _string(finding.get("title")),
            }
            for index, finding in enumerate(confirmed)
            if index not in matched_indexes
        ],
        "limitations": [
            "Ground-truth matching uses exact category plus optional title/endpoint substrings.",
            "Precision and recall are null when their denominator is zero; they are not treated as 0 or 1.",
            "False-positive and false-negative rates are meaningful only when the manifest covers all expected findings and safe controls for this lab version.",
            "Stage-duration sum is not wall-clock elapsed time and can differ when stages overlap or are resumed.",
            "Only confirmed vulnerability findings are scored; configuration observations are reported separately.",
        ],
    }


def _write_json_atomic(destination: Path, payload: dict[str, Any]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--scan-state", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        input_paths = {
            path.resolve()
            for path in (args.report, args.scan_state, args.manifest)
        }
        if args.output is not None and args.output.resolve() in input_paths:
            raise ValueError("--output must not overwrite the report, scan state or manifest")
        result = score(
            _load_object(args.report),
            _load_object(args.manifest),
            _load_object(args.scan_state),
        )
        if args.output:
            _write_json_atomic(args.output, result)
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
