import asyncio
import pandas as pd
import json
import re
import ssl
import time
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import stamina
from loguru import logger

from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    EMAIL_RE,
    FEDERAL_STATES,
    SKIP_DOMAINS,
    SPARQL_QUERY,
    SPARQL_URL,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import lookup_mx


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def _slugify_name(name: str) -> set[str]:
    """Generate slug variants for a municipality name (umlaut/accent handling)."""
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

    # German umlaut transliteration
    de = (
        raw.replace("\u00fc", "ue")
        .replace("\u00e4", "ae")
        .replace("\u00f6", "oe")
        .replace("\u00df", "ss")
    )

    def slugify(s):
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    return {slugify(de), slugify(raw)} - {""}


def guess_domains(name: str, federal_state: str = "") -> list[str]:
    """Generate a set of plausible domain guesses for a municipality."""

    def _slugs_for(text: str) -> set[str]:
        raw = text.lower().strip()
        raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

        de = (
            raw.replace("\u00fc", "ue")
            .replace("\u00e4", "ae")
            .replace("\u00f6", "oe")
            .replace("\u00df", "ss")
        )

        def slugify(s):
            s = re.sub(r"['\u2019`]", "", s)
            s = re.sub(r"[^a-z0-9]+", "-", s)
            return s.strip("-")

        slugs = {slugify(de), slugify(raw)} - {""}

        # Compound name handling: join all words
        # e.g. "Rüti bei Lyssach" -> "ruetibeilyssach.ch"
        extras = set()
        for variant in [de, raw]:
            joined = slugify(variant).replace("-", "")
            if joined and joined not in slugs:
                extras.add(joined)

        # First-word handling
        # e.g. "Oggau am Neusiedler See" -> "oggau.at"
        for variant in [de, raw]:
            first = variant.split()[0] if variant.split() else ""
            if first != "sankt":
                first_slug = slugify(first)

                if first_slug and first_slug not in slugs:
                    extras.add(first_slug)

            if first == "sankt":
                second = variant.split()[1] if len(variant.split()) > 1 else ""
                second_slug = slugify(second)

                if second_slug and second_slug not in slugs:
                    extras.add(second_slug)
                    extras.add(f"sankt{second_slug}")
                    extras.add(f"st{second_slug}")
                    extras.add(f"sankt-{second_slug}")
                    extras.add(f"st-{second_slug}")

        return slugs, extras

    # Split on "/" to generate guesses for each part independently
    parts = [p.strip() for p in name.split("/") if p.strip()]

    all_slugs: set[str] = set()
    all_extras: set[str] = set()

    # Always generate from the full name
    slugs, extras = _slugs_for(name)
    all_slugs |= slugs
    all_extras |= extras

    # Also generate from each "/" part individually
    if len(parts) > 1:
        for part in parts:
            slugs, extras = _slugs_for(part)
            all_slugs |= slugs
            all_extras |= extras

    candidates = set()
    federal_state_key = FEDERAL_STATES.get(federal_state, "")

    for slug in all_slugs:
        candidates.add(f"{slug}.at")
        candidates.add(f"gemeinde-{slug}.at")
        candidates.add(f"stadt-{slug}.at")
        candidates.add(f"marktg-{slug}.at")
        candidates.add(f"markt-{slug}.at")
        if federal_state_key:
            candidates.add(f"{slug}.{federal_state_key}.at")

    for joined in all_extras:
        candidates.add(f"{joined}.at")

    return sorted(candidates)


def detect_website_mismatch(name: str, website_domain: str) -> bool:
    """Detect if a website domain doesn't match the municipality name.

    Returns True if the domain appears unrelated to the municipality name.
    """
    if not name or not website_domain:
        return False

    domain_lower = website_domain.lower()
    slugs = _slugify_name(name)

    # Handle common Austrian prefixes
    prefixes = ["stadt-", "gemeinde-", "marktg-", "markt-"]
    domain_stripped = domain_lower
    for prefix in prefixes:
        if domain_stripped.startswith(prefix):
            domain_stripped = domain_stripped[len(prefix) :]
            break

    # Remove TLD for matching
    domain_base = (
        domain_stripped.rsplit(".", 1)[0] if "." in domain_stripped else domain_stripped
    )
    # Strip federal state subdomain: e.g. wien.at -> wien
    parts = domain_base.split(".")
    domain_base_first = parts[0] if parts else domain_base

    for slug in slugs:
        if slug in domain_lower:
            return False
        if slug in domain_stripped:
            return False
        if slug == domain_base_first:
            return False

    # Check if any word from the name (4+ chars) appears in the domain
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)
    de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
    fr = raw
    for a, b in [
        ("\u00e9", "e"),
        ("\u00e8", "e"),
        ("\u00ea", "e"),
        ("\u00eb", "e"),
        ("\u00e0", "a"),
        ("\u00e2", "a"),
        ("\u00f4", "o"),
        ("\u00ee", "i"),
        ("\u00f9", "u"),
        ("\u00fb", "u"),
        ("\u00e7", "c"),
        ("\u00ef", "i"),
    ]:
        fr = fr.replace(a, b)

    for variant in [raw, de, fr]:
        words = re.findall(r"[a-z]{4,}", variant)
        for word in words:
            if word in domain_lower:
                return False

    return True


def score_domain_sources(
    sources: dict[str, set[str]],
    name: str,
    website_domain: str,
) -> dict[str, Any]:
    """Score domain sources and pick best domain based on agreement."""
    sources_detail: dict[str, list[str]] = {k: sorted(v) for k, v in sources.items()}

    # Collect all unique domains and which sources found them
    domain_sources: dict[str, list[str]] = {}
    for source_name, domains in sources.items():
        for domain in domains:
            if domain not in domain_sources:
                domain_sources[domain] = []
            domain_sources[domain].append(source_name)

    if not domain_sources:
        return {
            "domain": "",
            "source": "none",
            "confidence": "none",
            "sources_detail": sources_detail,
            "flags": [],
        }

    # Pick domain with most source agreement
    best_domain = max(
        domain_sources,
        key=lambda d: (len(domain_sources[d]), "scrape" in domain_sources[d]),
    )
    best_sources = domain_sources[best_domain]
    source_count = len(best_sources)

    # Determine primary source (in priority order)
    source_priority = ["staedtebund", "scrape", "redirect", "wikidata", "guess"]
    source = next((s for s in source_priority if s in best_sources), best_sources[0])

    flags: list[str] = []

    # Determine confidence
    if source_count >= 2:
        confidence = "high"
    elif source == "guess":
        confidence = "low"
        flags.append("guess_only")
    else:
        confidence = "medium"

    # Check for disagreement: only flag when a primary source found domains
    # but none match the best domain. Extra domains from guess or within scrape
    # don't count as disagreement.
    primary_sources = ["staedtebund", "scrape", "redirect", "wikidata"]
    for src in primary_sources:
        src_domains = sources.get(src, set())
        if src_domains and best_domain not in src_domains:
            flags.append("sources_disagree")
            if confidence == "high":
                confidence = "medium"
            break

    # Check website mismatch
    if website_domain and detect_website_mismatch(name, website_domain):
        flags.append("website_mismatch")
        if confidence == "high":
            confidence = "medium"

    return {
        "domain": best_domain,
        "source": source,
        "confidence": confidence,
        "sources_detail": sources_detail,
        "flags": flags,
    }


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _fetch_sparql(
    client: httpx.AsyncClient, url: str, data: dict, headers: dict
) -> httpx.Response:
    r = await client.post(url, data=data, headers=headers)
    r.raise_for_status()
    return r


async def fetch_wikidata() -> dict[str, dict[str, str]]:
    """Query Wikidata for Austrian municipalities."""
    logger.info("Fetching municipalities from Wikidata")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await _fetch_sparql(client, SPARQL_URL, {"query": SPARQL_QUERY}, headers)
        data = r.json()

    GKZ_TO_STATE = {
        "1": "Burgenland",
        "2": "Kärnten",
        "3": "Niederösterreich",
        "4": "Oberösterreich",
        "5": "Salzburg",
        "6": "Steiermark",
        "7": "Tirol",
        "8": "Vorarlberg",
        "9": "Wien",
    }
    municipalities = {}
    for row in data["results"]["bindings"]:
        name = row.get("itemLabel", {}).get("value", "")
        gkz = row.get("gkz", {}).get("value", "")
        website = row.get("website", {}).get("value", "")

        if not gkz or not name:
            continue

        if gkz not in municipalities:
            municipalities[gkz] = {
                "name": name,
                "gkz": gkz,
                "website": website,
                "federal_state": GKZ_TO_STATE[gkz[0]],
            }

    logger.info(
        "Wikidata: {} municipalities, {} with websites",
        len(municipalities),
        sum(1 for m in municipalities.values() if m["website"]),
    )
    return municipalities


def load_overrides(overrides_path: Path) -> dict[str, dict[str, str]]:
    """Load manual overrides from JSON file."""
    if not overrides_path.exists():
        return {}
    try:
        with open(overrides_path, encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning("Failed to parse overrides file {}: {}", overrides_path, e)
        return {}


def load_staedtebund(csv_path: Path) -> pd.DataFrame:
    """Load Städtebund data from CSV file."""
    if not csv_path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(csv_path)
    except (pd.errors.EmptyDataError, IOError) as e:
        logger.warning("Failed to parse CSV file {}: {}", csv_path, e)
        return pd.DataFrame()


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                size = end - start + 1
                n = start + (code - start + offset) % size
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def _is_valid_domain(domain: str) -> bool:
    """Quick syntactic check — reject domains that will fail DNS lookup."""
    if not domain or len(domain) > 253:
        return False
    if "\\" in domain or "/" in domain:
        return False
    return all(0 < len(label) <= 63 for label in domain.split("."))


def extract_email_domains(html: str) -> set[str]:
    """Extract email domains from HTML, including TYPO3-obfuscated emails."""
    domains = set()

    # simple @ in body
    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in SKIP_DOMAINS:
            domains.add(domain)

    # mailto:
    for email in re.findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower().rstrip("\\/.")
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    # typo3 obfuscated emails
    for encoded in TYPO3_RE.findall(html):
        for offset in range(-25, 26):
            decoded = decrypt_typo3(encoded, offset)
            decoded = decoded.replace("mailto:", "")
            if "@" in decoded and EMAIL_RE.search(decoded):
                domain = decoded.split("@")[1].lower()
                if domain not in SKIP_DOMAINS:
                    domains.add(domain)
                break

    # user(at)domain.ch and user[at]domain.ch variants
    for match in re.findall(
        r"[\w.-]+\s*[\[(]at[\])]\s*[\w.-]+\.\w+", html, re.IGNORECASE
    ):
        normalized = re.sub(r"\s*[\[(]at[\])]\s*", "@", match, flags=re.IGNORECASE)
        if "@" in normalized:
            domain = normalized.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    return {d for d in domains if _is_valid_domain(d)}


def build_urls(domain: str) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in SUBPAGES:
            urls.append(base + path)
    return urls


def _is_ssl_error(exc: BaseException) -> bool:
    """Check if an exception (or any in its chain) is an SSL verification error."""
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        # Some builds wrap the error as a string only
        if "CERTIFICATE_VERIFY_FAILED" in str(current):
            return True
        current = current.__cause__ if current.__cause__ is not current else None
    return False


async def _fetch_insecure(url: str) -> httpx.Response:
    """Fetch a URL with SSL verification disabled (single request)."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        async with httpx.AsyncClient(verify=False) as insecure_client:
            return await insecure_client.get(url, follow_redirects=True, timeout=15)


def _process_scrape_response(
    r: httpx.Response,
    domain: str,
    all_domains: set[str],
    redirect_domain: str | None,
) -> tuple[set[str], str | None]:
    """Extract emails and detect redirects from a scrape response.

    Mutates all_domains in place. Returns updated (all_domains, redirect_domain).
    """
    if r.status_code != 200:
        return all_domains, redirect_domain

    if redirect_domain is None:
        final_domain = url_to_domain(str(r.url))
        if final_domain and final_domain != domain:
            redirect_domain = final_domain
            logger.info("Redirect detected: {} -> {}", domain, redirect_domain)

    domains = extract_email_domains(r.text)
    all_domains |= domains
    return all_domains, redirect_domain


async def scrape_email_domains(
    client: httpx.AsyncClient, domain: str
) -> tuple[set[str], str | None]:
    """Scrape a municipality website for email domains.

    Returns:
        Tuple of (email_domains_found, redirect_target_domain_or_None).
        redirect_target_domain is set when the website redirects to a
        different domain (ignoring www prefix differences).
    """
    if not domain:
        return set(), None

    all_domains = set()
    redirect_domain: str | None = None
    urls = build_urls(domain)

    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
        except httpx.ConnectError as exc:
            if _is_ssl_error(exc):
                logger.info("SSL error on {}, retrying without verification", url)
                try:
                    r = await _fetch_insecure(url)
                except Exception as retry_exc:
                    logger.debug("Insecure retry {} failed: {}", url, retry_exc)
                    continue
            else:
                logger.debug("Scrape {} failed: {}", url, exc)
                continue
        except Exception as exc:
            logger.debug("Scrape {} failed: {}", url, exc)
            continue

        all_domains, redirect_domain = _process_scrape_response(
            r, domain, all_domains, redirect_domain
        )
        if all_domains:
            return all_domains, redirect_domain

    return all_domains, redirect_domain


async def resolve_municipality_domain(
    m: dict[str, str],
    overrides: dict[str, dict[str, str]],
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    """Resolve a municipality's email domain using multiple sources.

    1. Override -> immediate win, confidence: high
    2. Städtebund domain -> confidence: high
    3. Collect from scrape, wikidata, guess sources
    4. Score agreement to pick best domain
    """
    gkz = m["gkz"]
    name = m["name"]
    federal_state = m.get("federal_state", "")

    entry: dict[str, Any] = {
        "gkz": gkz,
        "name": name,
        "federal_state": federal_state,
    }

    sources: dict[str, set[str]] = {
        "staedtebund": set(),
        "wikidata": set(),
        "scrape": set(),
        "redirect": set(),
        "guess": set(),
    }

    # 1. Check overrides (immediate win)
    if gkz in overrides:
        override = overrides[gkz]
        domain = url_to_domain(override["website"])
        mx = await lookup_mx(domain) if domain else []
        entry["domain"] = domain
        entry["source"] = "override"
        entry["confidence"] = "high" if (mx or not domain) else "medium"
        entry["sources_detail"] = {"override": [domain] if domain else []}
        entry["flags"] = []
        return entry

    # 2. Collect from Städtebund domain
    staedtebund_domain = m.get("domain", "")
    if staedtebund_domain:
        if await lookup_mx(staedtebund_domain):
            sources["staedtebund"].add(staedtebund_domain)

        # Scrape website for email addresses
        email_domains, redirect_domain = await scrape_email_domains(
            client, staedtebund_domain
        )
        for email_domain in email_domains:
            if await lookup_mx(email_domain):
                sources["scrape"].add(email_domain)

        # Add redirect target as a source (if it has MX records)
        if redirect_domain:
            if await lookup_mx(redirect_domain):
                sources["redirect"].add(redirect_domain)

    # 3. Collect from wikidata
    wikidata_domain = url_to_domain(m.get("website", ""))
    if wikidata_domain:
        if await lookup_mx(wikidata_domain):
            sources["wikidata"].add(wikidata_domain)

        # Scrape website for email addresses
        if wikidata_domain:
            email_domains, redirect_domain = await scrape_email_domains(
                client, wikidata_domain
            )
            for email_domain in email_domains:
                if await lookup_mx(email_domain):
                    sources["scrape"].add(email_domain)

            # Add redirect target as a source (if it has MX records)
            if redirect_domain:
                if await lookup_mx(redirect_domain):
                    sources["redirect"].add(redirect_domain)

    # Guess domains
    for guess in guess_domains(name, federal_state):
        if await lookup_mx(guess):
            sources["guess"].add(guess)

    # 3. Score and pick best
    result = score_domain_sources(sources, name, wikidata_domain or "")
    entry.update(result)

    return entry


async def run(
    output_path: Path,
    overrides_path: Path,
    staedtebund_csv_path: Path,
    date: str | None = None,
) -> None:
    # 1. Load sources
    overrides = load_overrides(overrides_path)
    logger.info(f"Loaded {len(overrides)} overrides.")

    staedtebund_data = load_staedtebund(staedtebund_csv_path)
    staedtebund_data["gkz"] = staedtebund_data["gkz"].astype("Int64").astype(str)
    logger.info(f"Loaded {len(staedtebund_data)} municipalities from Städtebund.")

    wikidata = await fetch_wikidata()
    logger.info(f"Loaded {len(wikidata)} municipalities from Wikidata.")

    # 2. Log differences between Städtebund and Wikidata
    # Municipalities in Städtebund but missing from Wikidata
    staedtebund_gkz = set(staedtebund_data["gkz"])
    wikidata_gkz = set(wikidata.keys())
    staedtebund_only = staedtebund_gkz - wikidata_gkz
    if staedtebund_only:
        logger.warning(
            "{} municipalities in Städtebund but missing from Wikidata",
            len(staedtebund_only),
        )
        for gkz in sorted(staedtebund_only, key=int):
            m = staedtebund_data[staedtebund_data["gkz"] == gkz].iloc[0]
            logger.info("    {:>5}  {}", gkz, m["municipality_name"])
    # Municipalities in Wikidata but not in Städtebund (potentially dissolved)
    wikidata_only = wikidata_gkz - staedtebund_gkz
    if wikidata_only:
        logger.warning(
            "{} municipalities in Wikidata but missing from Städtebund",
            len(wikidata_only),
        )
        for gkz in sorted(wikidata_only):
            m = wikidata[gkz]
            logger.info("    {:>5}  {}", gkz, m["name"])

    # 3. Merge sources - Städtebund list is the primary source
    municipalities: dict[str, dict[str, Any]] = {}
    for _, row in staedtebund_data.iterrows():
        name = row["municipality_name"]
        gkz = str(row["gkz"]) if pd.notna(row["gkz"]) and row["gkz"] else ""
        federal_state = row["bundesland"]
        entry: dict[str, Any] = {
            "name": name,
            "federal_state": federal_state,
            "gkz": gkz,
            "domain": row["domain"],  # Städtebund domain - to be checked later
        }
        # if gkz or name+federal_state combo exists in wikidata, use website
        if gkz in wikidata:
            entry["website"] = wikidata[gkz].get("website", "")
        if name in [m["name"] for m in wikidata.values()]:
            federal_state_match = next(
                (
                    m
                    for m in wikidata.values()
                    if m["name"] == name and m.get("federal_state") == federal_state
                ),
                None,
            )
            if federal_state_match:
                entry["website"] = federal_state_match.get("website", "")

        municipalities[gkz] = entry

    for gkz, entry in wikidata.items():
        if gkz not in municipalities.keys():
            name = entry["name"]
            federal_state = entry.get("federal_state", "")
            # check if the name+federal state combo already exists in municipalities
            if any(
                m["name"] == name and m.get("federal_state") == federal_state
                for m in municipalities.values()
            ):
                logger.info(
                    "Skipping duplicate municipality: {} (federal state: {})",
                    name,
                    federal_state,
                )
                continue
            municipalities[gkz] = {
                "name": name,
                "website": entry.get("website", ""),
                "federal_state": federal_state,
                "gkz": gkz,
            }
            logger.info("Added Wikidata-only municipality: {}", name)

    # 4. Add municipalities that are only in overrides
    for gkz, override in overrides.items():
        if gkz not in municipalities.keys():
            municipalities[gkz] = {
                "name": override["name"],
                "domain": override.get("domain", ""),
                "website": override.get("website", ""),
                "federal_state": override.get("federal_state", ""),
                "gkz": gkz,
            }
            logger.info("Added override-only municipality: {}", override["name"])

    total = len(municipalities)
    logger.info("Resolving email domains for {} municipalities", total)

    # Use a shared client for scraping with limited concurrency
    scrape_semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)

    async def _resolve_with_shared_client(
        m: dict[str, str], shared_client: httpx.AsyncClient
    ) -> dict[str, Any] | None:
        async with scrape_semaphore:
            try:
                return await resolve_municipality_domain(m, overrides, shared_client)
            except Exception:
                logger.exception("Resolution failed for {}", m["name"])
                return None

    results: dict[str, dict[str, Any]] = {}
    done = 0
    skipped = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": "mxmap.at/1.0 (https://github.com/davidhuser/mxmap)"},
        follow_redirects=True,
    ) as shared_client:
        tasks = [
            _resolve_with_shared_client(m, shared_client)
            for m in municipalities.values()
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is None:
                skipped += 1
                continue
            results[result["gkz"]] = result
            done += 1
            counts: dict[str, int] = {}
            for r in results.values():
                counts[r["source"]] = counts.get(r["source"], 0) + 1
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

    # Print summary
    source_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for r in results.values():
        source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1
        confidence_counts[r["confidence"]] = (
            confidence_counts.get(r["confidence"], 0) + 1
        )

    logger.info("--- Domain resolution: {} municipalities ---", len(results))
    logger.info("By source:")
    for source in [
        "override",
        "staedtebund",
        "wikidata",
        "scrape",
        "redirect",
        "guess",
        "none",
    ]:
        logger.info("  {:<12} {:>5}", source, source_counts.get(source, 0))
    logger.info("By confidence:")
    for conf in ["high", "medium", "low", "none"]:
        logger.info("  {:<12} {:>5}", conf, confidence_counts.get(conf, 0))

    # Print flagged entries for review (skip overridden — already confirmed)
    unreviewed = {
        gkz: r for gkz, r in results.items() if gkz not in overrides and r.get("flags")
    }

    disagreements = [r for r in unreviewed.values() if "sources_disagree" in r["flags"]]
    if disagreements:
        logger.warning("{} domains with source disagreement:", len(disagreements))
        for r in sorted(disagreements, key=lambda x: int(x["gkz"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}  sources={}",
                r["gkz"],
                r["name"],
                r["federal_state"],
                r["domain"],
                r.get("sources_detail", {}),
            )

    mismatches = [r for r in unreviewed.values() if "website_mismatch" in r["flags"]]
    if mismatches:
        logger.warning("{} domains with website mismatch:", len(mismatches))
        for r in sorted(mismatches, key=lambda x: int(x["gkz"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}",
                r["gkz"],
                r["name"],
                r["federal_state"],
                r["domain"],
            )

    guess_only = [r for r in unreviewed.values() if "guess_only" in r["flags"]]
    if guess_only:
        logger.warning("{} domains resolved by guess only:", len(guess_only))
        for r in sorted(guess_only, key=lambda x: int(x["gkz"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}",
                r["gkz"],
                r["name"],
                r["federal_state"],
                r["domain"],
            )

    # Print low confidence and unresolved entries for review
    low_entries = [
        r
        for gkz, r in results.items()
        if gkz not in overrides and r["confidence"] in ("low", "none")
    ]
    if low_entries:
        logger.warning("{} domains needing review:", len(low_entries))
        for r in sorted(low_entries, key=lambda x: int(x["gkz"])):
            logger.warning(
                "  {:>5}  {:<30} {:<20} domain={}  source={}",
                r["gkz"],
                r["name"],
                r.get("federal_state", ""),
                r["domain"] or "(none)",
                r["source"],
            )

    sorted_results = dict(sorted(results.items(), key=lambda kv: kv[0]))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "municipalities": sorted_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    size_kb = len(json.dumps(output, ensure_ascii=False)) / 1024
    logger.info("Wrote {} ({} KB)", output_path, size_kb)
