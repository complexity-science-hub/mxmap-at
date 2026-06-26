import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
import stamina
from loguru import logger

from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    SPARQL_QUERY,
    SPARQL_URL,
    GKZ_TO_STATE,
    DEFAULT_MAP_TOPOJSON_URL,
    SOURCE_PRIORITY,
)

from mail_sovereignty.resolve_domains import resolve_municipality_domain


def _clean_string(value: Any) -> str:
    """Return a clean string for mixed CSV/JSON values."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def _normalise_gkz(value: Any) -> str:
    """Normalise municipality identifiers from map, CSV, JSON and pandas values."""
    raw = _clean_string(value)
    if not raw:
        return ""
    raw = re.sub(r"\.0$", "", raw)
    if raw.isdigit():
        return raw
    match = re.search(r"\d+", raw)
    return match.group(0) if match else ""


def _normalise_municipality_name(name: str) -> str:
    raw = _clean_string(name).lower()
    raw = re.sub(r"\s*\(.*?\)\s*", " ", raw)
    raw = (
        raw.replace("\u00fc", "ue")
        .replace("\u00e4", "ae")
        .replace("\u00f6", "oe")
        .replace("\u00df", "ss")
    )
    raw = re.sub(r"\bst[.]?\b", "sankt", raw)
    return re.sub(r"[^a-z0-9]+", "", raw)


def municipality_names_match(left: str, right: str) -> bool:
    """Loose enough for common St./Sankt and punctuation variants."""
    left_norm = _normalise_municipality_name(left)
    right_norm = _normalise_municipality_name(right)
    if not left_norm or not right_norm:
        return True
    return left_norm == right_norm


def municipality_identity_matches(
    base: dict[str, Any],
    source: dict[str, Any],
    source_name: str,
) -> bool:
    """Validate a source row before merging it into the map-backed base.

    GKZ is the authoritative join key. If GKZ matches, tolerate differences in
    state or municipality labels across sources and keep the row.
    """
    gkz = _normalise_gkz(source.get("gkz", ""))
    if gkz and _normalise_gkz(base.get("gkz", "")) != gkz:
        logger.warning(
            "Skipping {} for GKZ {}: joined to base GKZ {}",
            source_name,
            gkz,
            base.get("gkz", ""),
        )
        return False

    source_state = _clean_string(source.get("federal_state", ""))
    base_state = _clean_string(base.get("federal_state", ""))
    if source_state and base_state and source_state != base_state:
        logger.info(
            "{} federal state mismatch for GKZ {}: {} != {}",
            source_name,
            base.get("gkz", ""),
            source_state,
            base_state,
        )

    source_name_value = _clean_string(source.get("name", ""))
    base_name_value = _clean_string(base.get("name", ""))
    if (
        source_name_value
        and base_name_value
        and not municipality_names_match(base_name_value, source_name_value)
    ):
        logger.info(
            "{} name mismatch for GKZ {}: map='{}' source='{}'",
            source_name,
            base.get("gkz", ""),
            base_name_value,
            source_name_value,
        )

    return True


async def _load_json_from_path_or_url(source: Path | str) -> Any:
    source_text = str(source)
    if source_text.startswith(("http://", "https://")):
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.get(source_text, follow_redirects=True)
            response.raise_for_status()
            return response.json()

    with open(Path(source), encoding="utf-8") as f:
        return json.load(f)


def _iter_map_feature_properties(map_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return feature properties from either GeoJSON or TopoJSON."""
    if map_data.get("type") == "FeatureCollection":
        return [
            feature.get("properties", {}) for feature in map_data.get("features", [])
        ]

    if "objects" in map_data:
        topo_objects = map_data.get("objects", {})
        obj = topo_objects.get("gemeinden")
        if obj is None:
            obj = next(
                (
                    candidate
                    for candidate in topo_objects.values()
                    if candidate.get("geometries")
                ),
                None,
            )
        if obj is not None:
            return [
                geometry.get("properties", {}) for geometry in obj.get("geometries", [])
            ]

    return []


async def load_map_municipalities(
    map_topojson_path_or_url: Path | str = DEFAULT_MAP_TOPOJSON_URL,
) -> dict[str, dict[str, Any]]:
    """Load the visualisation map and create the GKZ-keyed municipality base."""
    map_data = await _load_json_from_path_or_url(map_topojson_path_or_url)
    municipalities: dict[str, dict[str, Any]] = {}

    for props in _iter_map_feature_properties(map_data):
        gkz = _normalise_gkz(
            props.get("iso") or props.get("gkz") or props.get("GKZ") or props.get("id")
        )
        name = _clean_string(
            props.get("name")
            or props.get("NAME")
            or props.get("municipality_name")
            or props.get("GEN")
        )
        if not gkz or not name:
            logger.debug("Skipping map feature without GKZ/name: {}", props)
            continue

        if gkz in municipalities:
            logger.warning(
                "Duplicate GKZ {} in map: keeping '{}' and ignoring '{}'",
                gkz,
                municipalities[gkz]["name"],
                name,
            )
            continue

        municipalities[gkz] = {
            "gkz": gkz,
            "name": name,
            "federal_state": GKZ_TO_STATE.get(_normalise_gkz(gkz)[:1], ""),
        }

    if not municipalities:
        raise ValueError(
            f"No municipalities found in map source {map_topojson_path_or_url}"
        )

    return dict(sorted(municipalities.items(), key=lambda kv: int(kv[0])))


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _fetch_sparql(
    client: httpx.AsyncClient, url: str, data: dict, headers: dict
) -> httpx.Response:
    response = await client.post(url, data=data, headers=headers)
    response.raise_for_status()
    return response


async def fetch_wikidata() -> dict[str, dict[str, str]]:
    """Query Wikidata for Austrian municipalities."""
    logger.info("Fetching municipalities from Wikidata")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        response = await _fetch_sparql(
            client, SPARQL_URL, {"query": SPARQL_QUERY}, headers
        )
        data = response.json()

    municipalities: dict[str, dict[str, str]] = {}
    for row in data["results"]["bindings"]:
        name = row.get("itemLabel", {}).get("value", "")
        gkz = _normalise_gkz(row.get("gkz", {}).get("value", ""))
        website = row.get("website", {}).get("value", "")

        if not gkz or not name:
            continue

        if gkz not in municipalities:
            municipalities[gkz] = {
                "name": name,
                "gkz": gkz,
                "website": website,
                "federal_state": GKZ_TO_STATE.get(_normalise_gkz(gkz)[:1], ""),
            }
        elif not municipalities[gkz]["website"] and website:
            municipalities[gkz]["website"] = website

    logger.info(
        "Wikidata: {} municipalities, {} with websites",
        len(municipalities),
        sum(1 for item in municipalities.values() if item["website"]),
    )
    return municipalities


def load_overrides(overrides_path: Path) -> dict[str, dict[str, str]]:
    """Load manual overrides from a JSON file."""
    if not overrides_path.exists():
        return {}
    try:
        with open(overrides_path, encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as exc:
        logger.warning("Failed to parse overrides file {}: {}", overrides_path, exc)
        return {}


def load_staedtebund(csv_path: Path) -> pd.DataFrame:
    """Load Staedtebund data from a CSV file."""
    if not csv_path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(csv_path)
    except (pd.errors.EmptyDataError, IOError) as exc:
        logger.warning("Failed to parse CSV file {}: {}", csv_path, exc)
        return pd.DataFrame()


def _set_string_field(
    entry: dict[str, Any],
    field: str,
    value: str | None,
) -> str | None:
    cleaned = _clean_string(value)
    if not cleaned:
        return None
    entry[field] = cleaned
    return cleaned


def merge_overrides_into_municipalities(
    municipalities: dict[str, dict[str, Any]],
    overrides: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    """Load manual overrides onto the map-backed base."""
    effective_overrides: dict[str, dict[str, str]] = {}

    for raw_gkz, override in overrides.items():
        gkz = _normalise_gkz(raw_gkz)
        if not gkz:
            logger.warning("Skipping override without GKZ: {}", override)
            continue
        if gkz not in municipalities:
            logger.warning(
                "Skipping override-only GKZ {}: not present in map base", gkz
            )
            continue

        entry = municipalities[gkz]
        source_identity = {
            "gkz": gkz,
            "name": override.get("name", ""),
            "federal_state": override.get("federal_state", ""),
        }
        if not municipality_identity_matches(entry, source_identity, "override"):
            continue

        override_domain = _set_string_field(
            entry,
            "override_domain",
            override.get("domain"),
        )
        override_website = _set_string_field(
            entry,
            "override_website",
            override.get("website"),
        )

        effective_overrides[gkz] = {
            "gkz": gkz,
            "name": entry["name"],
            "federal_state": entry.get("federal_state", ""),
            "override_domain": override_domain or "",
            "override_website": override_website or "",
        }

    return effective_overrides


def merge_staedtebund_into_municipalities(
    municipalities: dict[str, dict[str, Any]],
    staedtebund_data: pd.DataFrame,
) -> None:
    """Attach Staedtebund website candidates as website_sb."""
    if staedtebund_data.empty:
        return

    for _, row in staedtebund_data.iterrows():
        gkz = _normalise_gkz(row.get("gkz", ""))
        if not gkz:
            logger.warning("Skipping Staedtebund row without GKZ: {}", row.to_dict())
            continue
        if gkz not in municipalities:
            logger.warning(
                "Skipping Staedtebund-only GKZ {}: not present in map base", gkz
            )
            continue

        entry = municipalities[gkz]
        source_identity = {
            "gkz": gkz,
            "name": row.get("municipality_name", ""),
            "federal_state": row.get("bundesland", ""),
        }
        if not municipality_identity_matches(entry, source_identity, "Staedtebund"):
            continue

        _set_string_field(entry, "website_sb", row.get("domain", ""))


def merge_wikidata_into_municipalities(
    municipalities: dict[str, dict[str, Any]],
    wikidata: dict[str, dict[str, str]],
) -> None:
    """Attach Wikidata website candidates as website_wd."""
    for raw_gkz, wikidata_entry in wikidata.items():
        gkz = _normalise_gkz(raw_gkz or wikidata_entry.get("gkz", ""))
        if not gkz:
            logger.warning("Skipping Wikidata entry without GKZ: {}", wikidata_entry)
            continue
        if gkz not in municipalities:
            logger.warning(
                "Skipping Wikidata-only GKZ {}: not present in map base", gkz
            )
            continue

        entry = municipalities[gkz]
        source_identity = {
            "gkz": gkz,
            "name": wikidata_entry.get("name", ""),
            "federal_state": wikidata_entry.get("federal_state", ""),
        }
        if not municipality_identity_matches(entry, source_identity, "Wikidata"):
            continue

        _set_string_field(entry, "website_wd", wikidata_entry.get("website", ""))


def _add_shared_domain_flags(results: dict[str, dict[str, Any]]) -> None:
    """Flag domains used by more than one municipality.

    Mutates results in-place.
    """
    domain_to_gkz: dict[str, list[str]] = {}

    for gkz, result in results.items():
        domain = str(result.get("domain", "")).lower().strip().rstrip(".")
        if not domain:
            continue

        domain_to_gkz.setdefault(domain, []).append(gkz)

    for domain, gkzs in domain_to_gkz.items():
        if len(gkzs) < 2:
            continue

        for gkz in gkzs:
            result = results[gkz]
            flags = list(result.get("flags", []))

            if "shared_domain" not in flags:
                flags.append("shared_domain")

            result["flags"] = flags


def _gkz_sort_key(value: Any) -> tuple[int, str]:
    gkz = _normalise_gkz(value)
    return (int(gkz), gkz) if gkz.isdigit() else (10**9, str(value))


async def run(
    output_path: Path,
    overrides_path: Path,
    staedtebund_csv_path: Path,
    map_topojson_path_or_url: Path | str = DEFAULT_MAP_TOPOJSON_URL,
) -> None:
    """Resolve municipality email domains."""
    municipalities = await load_map_municipalities(map_topojson_path_or_url)
    logger.info("Loaded {} municipalities from map base.", len(municipalities))

    raw_overrides = load_overrides(overrides_path)
    logger.info("Loaded {} raw overrides.", len(raw_overrides))

    staedtebund_data = load_staedtebund(staedtebund_csv_path)
    if not staedtebund_data.empty and "gkz" in staedtebund_data.columns:
        staedtebund_data["gkz"] = staedtebund_data["gkz"].map(_normalise_gkz)
    elif not staedtebund_data.empty:
        logger.warning("Staedtebund data has no 'gkz' column; it will not be merged.")
        staedtebund_data = pd.DataFrame()
    logger.info("Loaded {} municipalities from Staedtebund.", len(staedtebund_data))

    wikidata = await fetch_wikidata()
    logger.info("Loaded {} municipalities from Wikidata.", len(wikidata))

    map_gkz = set(municipalities.keys())
    staedtebund_gkz = (
        set(staedtebund_data["gkz"]) - {""}
        if not staedtebund_data.empty and "gkz" in staedtebund_data.columns
        else set()
    )
    wikidata_gkz = set(wikidata.keys())

    staedtebund_only = staedtebund_gkz - map_gkz
    if staedtebund_only:
        logger.warning(
            "{} municipalities in Staedtebund but missing from map base",
            len(staedtebund_only),
        )
        for gkz in sorted(staedtebund_only, key=_gkz_sort_key):
            rows = staedtebund_data[staedtebund_data["gkz"] == gkz]
            name = rows.iloc[0].get("municipality_name", "") if not rows.empty else ""
            state = rows.iloc[0].get("bundesland", "") if not rows.empty else ""
            domain = rows.iloc[0].get("domain", "") if not rows.empty else ""
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}",
                gkz,
                name,
                state,
                domain,
            )

    wikidata_only = wikidata_gkz - map_gkz
    if wikidata_only:
        logger.warning(
            "{} municipalities in Wikidata but missing from map base",
            len(wikidata_only),
        )
        for gkz in sorted(wikidata_only, key=_gkz_sort_key):
            entry = wikidata[gkz]
            logger.warning(
                "  {:>5}  {:<30} {:<20} website={}",
                gkz,
                entry.get("name", ""),
                entry.get("federal_state", ""),
                entry.get("website", ""),
            )

    raw_override_gkz = {_normalise_gkz(raw_gkz) for raw_gkz, _ in raw_overrides.items()}
    raw_override_gkz.discard("")

    override_only = raw_override_gkz - map_gkz
    if override_only:
        logger.warning(
            "{} override municipalities missing from map base; they will be skipped",
            len(override_only),
        )
        for gkz in sorted(override_only, key=_gkz_sort_key):
            override = next(
                (
                    item
                    for raw_gkz, item in raw_overrides.items()
                    if _normalise_gkz(raw_gkz or item.get("gkz", "")) == gkz
                ),
                {},
            )
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={} website={}",
                gkz,
                override.get("name", ""),
                override.get("federal_state", ""),
                override.get("domain", ""),
                override.get("website", ""),
            )

    overrides = merge_overrides_into_municipalities(municipalities, raw_overrides)
    logger.info("Loaded {} manual overrides.", len(overrides))

    merge_staedtebund_into_municipalities(municipalities, staedtebund_data)
    merge_wikidata_into_municipalities(municipalities, wikidata)

    total = len(municipalities)
    logger.info("Resolving email domains for {} municipalities", total)

    scrape_semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)

    async def _resolve_with_shared_client(
        municipality: dict[str, str], shared_client: httpx.AsyncClient
    ) -> dict[str, Any] | None:
        async with scrape_semaphore:
            try:
                return await resolve_municipality_domain(
                    municipality, overrides, shared_client
                )
            except Exception:
                logger.exception("Resolution failed for {}", municipality["name"])
                return None

    results: dict[str, dict[str, Any]] = {}
    done = 0
    skipped = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": "mxmap.at/1.0 (https://github.com/davidhuser/mxmap)"},
        follow_redirects=True,
    ) as shared_client:
        tasks = [
            _resolve_with_shared_client(municipality, shared_client)
            for municipality in municipalities.values()
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is None:
                skipped += 1
                continue
            results[result["gkz"]] = result
            done += 1
            logger.info(
                "[{:>4}/{}] {} ({}): domain={} source={} confidence={}",
                done,
                total,
                result["name"],
                result["gkz"],
                result.get("domain", ""),
                result.get("source", ""),
                result.get("confidence", ""),
            )

    if skipped:
        logger.warning("Skipped {} municipalities due to errors", skipped)

    _add_shared_domain_flags(results)

    source_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for result in results.values():
        source_counts[result["source"]] = source_counts.get(result["source"], 0) + 1
        confidence_counts[result["confidence"]] = (
            confidence_counts.get(result["confidence"], 0) + 1
        )

    logger.info("--- Domain resolution: {} municipalities ---", len(results))
    logger.info("By source:")
    for source in SOURCE_PRIORITY + ["none"]:
        logger.info("  {:<20} {:>5}", source, source_counts.get(source, 0))
    logger.info("By confidence:")
    for confidence in ["high", "medium", "low", "none"]:
        logger.info("  {:<12} {:>5}", confidence, confidence_counts.get(confidence, 0))

    sorted_results = dict(sorted(results.items(), key=lambda kv: _gkz_sort_key(kv[0])))
    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "municipalities": sorted_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    size_kb = len(json.dumps(output, ensure_ascii=False)) / 1024
    logger.info("Wrote {} ({} KB)", output_path, size_kb)
