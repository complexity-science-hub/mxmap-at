"""Classification pipeline: orchestrate classify_many() and write data.json."""

from __future__ import annotations

import json
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from loguru import logger

from .classifier import classify_many
from .models import ClassificationResult, Provider


# Map internal Provider enum values to data.json output names
PROVIDER_OUTPUT_NAMES: dict[str, str] = {
    "ms365": "microsoft",
}

_CATEGORY_MAP: dict[str, str] = {
    # US cloud — keys must match _output_provider() output, not raw enum values
    "microsoft": "us-cloud",
    "google": "us-cloud",
    "aws": "us-cloud",
    # Named Austrian providers
    "a1": "austrian-based",
    "gemdat": "austrian-based",
    "ris": "austrian-based",
    "easyname": "austrian-based",
    "austria_isp": "austrian-based",
    "post": "austrian-based",
    "asp_bgld": "austrian-based",
    "w4ymail": "austrian-based",
    "bon": "austrian-based",
    "wien": "austrian-based",
    "cnv": "austrian-based",
    "salzburg": "austrian-based",
    "wvnet": "austrian-based",
    "magenta": "austrian-based",
    "net4you": "austrian-based",
    "mymailwall": "austrian-based",
    "secure_shield": "austrian-based",
    "kabelplus": "austrian-based",
    "cablelink": "austrian-based",
    "node4web": "austrian-based",
    "hiway": "austrian-based",
    "mynet": "austrian-based",
    "lgbs": "austrian-based",
    "flashnet": "austrian-based",
    "styrion": "austrian-based",
    "viennaweb": "austrian-based",
    "riepert": "austrian-based",
    # mostly german providers
    "hallo_cloud": "european-based",  # dutch
    "kas": "european-based",  # German host but dominant in AT municipalities
    "agenturserver": "european-based",  # German provider, no AT presence
    "ionos": "european-based",  # German/pan-European, no AT presence
    # Self-hosted
    "independent": "austrian-based",  # Austrian signals confirmed, no named provider
    # Cannot classify
    "unresolved": "unresolved",  # has mail infra, origin unclear
    "unknown": "unknown",  # no usable signals
}


_FRONTEND_FIELDS = {
    "name",
    "domain",
    "federal_state",
    "mx",
    "spf",
    "provider",
    "category",
    "classification_confidence",
    "classification_signals",
    "gateway",
    "domain_flags",
}

_INVALID_MX_HOSTS: frozenset[str] = frozenset({"localhost", ""})

# Maximum classification_confidence (0–100) allowed per resolve-stage flag.
# When multiple flags apply, the lowest cap wins.
_RESOLVE_CONFIDENCE_CAPS: dict[str, float] = {
    "sources_disagree": 90.0,
    "single_source": 80.0,
    "domain_mismatch": 70.0,
    "unresolved": 50.0,
    "unknown": 0.0,
}


def _is_reject_all_spf(spf_raw: str) -> bool:
    """True if the SPF record has no positive sending mechanisms.

    v=spf1 -all means no server is authorised to send from this domain — it is
    either decommissioned or a placeholder.  Any positive mechanism (include:,
    ip4:, ip6:, a, mx, exists:, redirect=) disqualifies the flag.
    """
    tokens = spf_raw.split()
    if len(tokens) < 2:
        return False
    mechanisms = [t for t in tokens[1:] if not t.lower().startswith("exp=")]
    return len(mechanisms) == 1 and mechanisms[0].lower().endswith("all")


def _detect_domain_flags(mx_hosts: list[str], spf_raw: str) -> list[str]:
    """Return anomaly flags for a domain's MX / SPF configuration."""
    flags: list[str] = []
    if mx_hosts and all(h.strip().lower() in _INVALID_MX_HOSTS for h in mx_hosts):
        flags.append("invalid_mx")
    if spf_raw and _is_reject_all_spf(spf_raw):
        flags.append("reject_all_spf")
    return flags


def _apply_resolve_caps(confidence: float, resolve_flags: list[str]) -> float:
    cap = min(
        (
            _RESOLVE_CONFIDENCE_CAPS[f]
            for f in resolve_flags
            if f in _RESOLVE_CONFIDENCE_CAPS
        ),
        default=100.0,
    )
    return min(confidence, cap)


def _minify_for_frontend(full_output: dict[str, Any]) -> dict[str, Any]:
    """Strip fields the frontend doesn't use, producing a compact payload."""
    municipalities = {}
    for gkz, entry in full_output["municipalities"].items():
        mini = {k: v for k, v in entry.items() if k in _FRONTEND_FIELDS}
        mini["classification_signals"] = [
            {
                "kind": s["kind"],
                "detail": s["detail"],
                "counts_toward_confidence": s["counts_toward_confidence"],
            }
            for s in entry.get("classification_signals", [])
        ]
        municipalities[gkz] = mini
    return {
        "generated": full_output["generated"],
        "commit": full_output.get("commit"),
        "municipalities": municipalities,
    }


def _output_provider(provider: Provider) -> str:
    """Map Provider enum to output name for data.json."""
    return PROVIDER_OUTPUT_NAMES.get(provider.value, provider.value)


def _serialize_result(
    entry: dict[str, Any], result: ClassificationResult
) -> dict[str, Any]:
    """Serialize a ClassificationResult into a data.json municipality entry."""
    provider = _output_provider(result.provider)
    category = _CATEGORY_MAP.get(provider, "unknown")
    resolve_flags: list[str] = entry.get("flags", [])
    raw_confidence = round(result.confidence * 100, 1)
    confidence = _apply_resolve_caps(raw_confidence, resolve_flags)
    out: dict[str, Any] = {
        "gkz": entry["gkz"],
        "name": entry["name"],
        "federal_state": entry.get("federal_state", ""),
        "domain": entry.get("domain", ""),
        "mx": result.mx_hosts,
        "spf": result.spf_raw,
        "provider": provider,
        "category": category,
        "classification_confidence": confidence,
        "classification_signals": [
            {
                "kind": e.kind.value,
                "provider": PROVIDER_OUTPUT_NAMES.get(
                    e.provider.value, e.provider.value
                ),
                "weight": e.weight,
                "detail": e.detail,
                # For INDEPENDENT all signals contribute to _independent_confidence;
                # for named winners only same-provider signals count.
                "counts_toward_confidence": (
                    result.provider == Provider.INDEPENDENT
                    or e.provider == result.provider
                ),
            }
            for e in result.evidence
        ],
    }

    if result.gateway:
        out["gateway"] = result.gateway

    # Dead domain gate: provably inactive domains are zeroed out regardless of
    # what the classifier found.  MX=localhost/empty or bare -all SPF means the
    # domain cannot receive (or send) email.
    if _detect_domain_flags(result.mx_hosts, result.spf_raw):
        out["provider"] = "unknown"
        out["category"] = "unknown"
        out["classification_confidence"] = 0.0
        out["classification_signals"] = []
        out["domain_flags"] = ["domain_inactive"]

    # Pass through resolve-level fields
    if "sources_detail" in entry:
        out["sources_detail"] = entry["sources_detail"]
    if "flags" in entry:
        out["resolve_flags"] = entry["flags"]

    return out


async def run(domains_path: Path, output_path: Path) -> None:
    with open(domains_path, encoding="utf-8") as f:
        domains_data = json.load(f)

    entries = domains_data["municipalities"]
    total = len(entries)

    logger.info("Classifying {} municipalities", total)
    t0 = time.monotonic()

    # Build domain -> entry mapping
    domain_to_entries: dict[str, list[dict[str, Any]]] = {}
    no_domain_entries: list[dict[str, Any]] = []
    for entry in entries.values():
        domain = entry.get("domain", "")
        if domain:
            domain_to_entries.setdefault(domain, []).append(entry)
        else:
            no_domain_entries.append(entry)

    unique_domains = list(domain_to_entries.keys())

    results: dict[str, dict[str, Any]] = {}
    done = 0

    # Handle entries without domains
    for entry in no_domain_entries:
        results[entry["gkz"]] = {
            "gkz": entry["gkz"],
            "name": entry["name"],
            "federal_state": entry.get("federal_state", ""),
            "domain": "",
            "mx": [],
            "spf": "",
            "provider": "unknown",
            "category": "unknown",
            "classification_confidence": 0.0,
            "classification_signals": [],
        }
        if "sources_detail" in entry:
            results[entry["gkz"]]["sources_detail"] = entry["sources_detail"]
        if "flags" in entry:
            results[entry["gkz"]]["resolve_flags"] = entry["flags"]

    # Classify domains
    async for domain, classification in classify_many(unique_domains):
        for entry in domain_to_entries[domain]:
            serialized = _serialize_result(entry, classification)
            results[entry["gkz"]] = serialized

        done += len(domain_to_entries[domain])
        cat_progress: dict[str, int] = {}
        for r in results.values():
            cat = _CATEGORY_MAP.get(r["provider"], "unknown")
            cat_progress[cat] = cat_progress.get(cat, 0) + 1
        logger.info(
            "[{:>4}/{}] {}: provider={} confidence={:.2f} signals={}",
            done,
            total,
            domain,
            classification.provider.value,
            classification.confidence,
            len(classification.evidence),
        )

    # Final counts
    counts = {}
    cat_counts: dict[str, int] = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1
        cat = _CATEGORY_MAP.get(r["provider"], "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    elapsed = time.monotonic() - t0
    logger.info(
        "--- Classification: {} municipalities in {:.1f}s ---", len(results), elapsed
    )
    # Group providers by category from _CATEGORY_MAP (picks up new providers automatically)
    cat_providers: dict[str, list[str]] = {}
    for _p, _c in _CATEGORY_MAP.items():
        cat_providers.setdefault(_c, []).append(_p)

    _CAT_ORDER = [
        "us-cloud",
        "austrian-based",
        "european-based",
        "unresolved",
        "unknown",
    ]
    _CAT_LABELS = {
        "us-cloud": "US Cloud",
        "austrian-based": "Austrian Based",
        "european-based": "European Based",
        "unresolved": "Unresolved",
        "unknown": "Unknown/No MX",
    }
    for _cat in _CAT_ORDER:
        _total = cat_counts.get(_cat, 0)
        _breakdown = "  ".join(
            f"{_p}={counts.get(_p, 0)}"
            for _p in sorted(
                cat_providers.get(_cat, []), key=lambda p: -counts.get(p, 0)
            )
            if counts.get(_p, 0) > 0
        )
        _label = _CAT_LABELS[_cat]
        if _breakdown:
            logger.info("  {:<16} {:>5}  ({})", _label, _total, _breakdown)
        else:
            logger.info("  {:<16} {:>5}", _label, _total)

    # Log remaining independent entries grouped by signal pattern + MX host,
    # to surface recurring patterns that could become new provider signatures.
    independent_entries = [
        r for r in results.values() if r["provider"] == "independent"
    ]
    if independent_entries:
        groups: dict[str, list[dict[str, Any]]] = {}
        for entry in independent_entries:
            signals = entry.get("classification_signals", [])
            combo = (
                "+".join(sorted({s["kind"] for s in signals})) if signals else "none"
            )
            mx_hosts = entry.get("mx", [])
            groups.setdefault(combo, []).append(
                {
                    "mx": ", ".join(mx_hosts) if mx_hosts else "none",
                    "signals": sorted(
                        {f"{s['provider']}:{s['kind']}" for s in signals}
                    ),
                }
            )
        lines = [f"Independent pattern summary ({len(independent_entries)} entries):"]
        for combo, entries in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            mx_counter: Counter[str] = Counter(e["mx"] for e in entries)
            top_mx = [mx for mx, _ in mx_counter.most_common(5)]
            all_signals: set[str] = set()
            for e in entries:
                all_signals.update(e["signals"])
            lines.append(
                f"  [{combo}] count={len(entries)}"
                f" signals=[{', '.join(sorted(all_signals))}]"
                f" mx=[{', '.join(top_mx)}]"
            )
        logger.info("\n".join(lines))

    sorted_counts = dict(sorted(counts.items()))
    sorted_munis = dict(sorted(results.items(), key=lambda kv: kv[1]["name"]))

    commit = (
        subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        or None
    )

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit": commit,
        "total": len(results),
        "counts": sorted_counts,
        "municipalities": sorted_munis,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024

    mini_output = _minify_for_frontend(output)
    mini_path = output_path.with_suffix(".min.json")
    with open(mini_path, "w", encoding="utf-8") as f:
        json.dump(mini_output, f, ensure_ascii=False, separators=(",", ":"))

    mini_size_kb = mini_path.stat().st_size / 1024
    logger.info("Wrote {} ({} KB)", output_path, size_kb)
    logger.info("Wrote {} ({:.0f} KB)", mini_path, mini_size_kb)
