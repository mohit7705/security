from __future__ import annotations

import math
import re
from typing import Any


_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VECTOR_RE = re.compile(r"^CVSS:3\.1(?:/[A-Z]{1,2}:[A-Z])+$")


class CvssVectorError(ValueError):
    """Raised when a CVSS v3.1 base vector is malformed or incomplete."""


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value."""
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def calculate_cvss31(vector: str) -> dict[str, Any]:
    """Validate and calculate a CVSS v3.1 Base Score from a complete base vector.

    Temporal and Environmental metrics are deliberately not accepted here;
    the returned score is the Base Score only.
    """
    raw = str(vector or "").strip().upper()
    if not _VECTOR_RE.fullmatch(raw):
        raise CvssVectorError("Expected a CVSS:3.1 base vector")

    parsed: dict[str, str] = {}
    for component in raw.split("/")[1:]:
        key, value = component.split(":", 1)
        if key in parsed:
            raise CvssVectorError(f"Duplicate CVSS metric: {key}")
        parsed[key] = value

    if set(parsed) != set(_REQUIRED):
        missing = sorted(set(_REQUIRED) - set(parsed))
        extra = sorted(set(parsed) - set(_REQUIRED))
        raise CvssVectorError(f"Invalid CVSS base metrics; missing={missing}, extra={extra}")

    for key, value in parsed.items():
        metric_key = "CIA" if key in {"C", "I", "A"} else (
            "PR_C" if key == "PR" and parsed["S"] == "C" else
            "PR_U" if key == "PR" else key
        )
        if key == "S":
            if value not in {"U", "C"}:
                raise CvssVectorError("Scope must be U or C")
        elif value not in _METRICS[metric_key]:
            raise CvssVectorError(f"Invalid value for {key}: {value}")

    exploitability = (
        8.22
        * _METRICS["AV"][parsed["AV"]]
        * _METRICS["AC"][parsed["AC"]]
        * _METRICS["PR_C" if parsed["S"] == "C" else "PR_U"][parsed["PR"]]
        * _METRICS["UI"][parsed["UI"]]
    )

    confidentiality = _METRICS["CIA"][parsed["C"]]
    integrity = _METRICS["CIA"][parsed["I"]]
    availability = _METRICS["CIA"][parsed["A"]]
    isc_base = 1.0 - (
        (1.0 - confidentiality)
        * (1.0 - integrity)
        * (1.0 - availability)
    )

    if parsed["S"] == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        score = 0.0
    elif parsed["S"] == "U":
        score = _roundup(min(impact + exploitability, 10.0))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    if score == 0.0:
        rating = "NONE"
    elif score <= 3.9:
        rating = "LOW"
    elif score <= 6.9:
        rating = "MEDIUM"
    elif score <= 8.9:
        rating = "HIGH"
    else:
        rating = "CRITICAL"

    canonical = "CVSS:3.1/" + "/".join(f"{key}:{parsed[key]}" for key in _REQUIRED)
    return {
        "version": "3.1",
        "vector": canonical,
        "base_score": score,
        "base_severity": rating,
        "exploitability_subscore": round(exploitability, 4),
        "impact_subscore": round(impact, 4),
        "score_type": "CVSS_BASE_SCORE",
    }
