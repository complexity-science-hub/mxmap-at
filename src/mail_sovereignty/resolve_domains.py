import re
import ssl
import warnings
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import httpx
from loguru import logger

from mail_sovereignty.constants import (
    EMAIL_RE,
    FEDERAL_STATES,
    MISMATCH_WORD_STOPLIST,
    NON_MUNICIPAL_DOMAIN_PATTERNS,
    SKIP_DOMAINS,
    SUBPAGES,
    TYPO3_RE,
    SOURCE_KEYS,
)
from mail_sovereignty.dns import lookup_mx

def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL or bare host string."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None

def _slugify(text: str) -> str:
    """Convert a pre-normalised string to a URL-safe slug."""
    text = re.sub(r"['\u2019`]", "", text)
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def _normalise_name(name: str) -> str:
    """Canonical normalisation for a municipality name.

    Lowercases, strips parenthetical qualifiers, expands umlauts, and
    resolves St./Sankt so that both slug generators and the mismatch
    checker operate on exactly the same text.
    """
    text = name.lower().strip()
    text = re.sub(r"\s*\(.*?\)\s*", " ", text).strip()
    text = re.sub(r"\bst[.]?\b", "sankt", text)
    return (
        text.replace("\u00fc", "ue")
        .replace("\u00e4", "ae")
        .replace("\u00f6", "oe")
        .replace("\u00df", "ss")
    )


def _name_slugs(name: str) -> set[str]:
    """Return all slug variants for a municipality name.

    Produces the full-name slug after normalisation (which expands
    St. → Sankt) and the corresponding st- abbreviation variant so that
    both forms are accepted by detect_domain_mismatch.
    """
    normalised = _normalise_name(name)
    full_slug = _slugify(normalised)
    slugs: set[str] = set()
    if full_slug:
        slugs.add(full_slug)
        if full_slug.startswith("sankt-"):
            slugs.add("st-" + full_slug[len("sankt-"):])
    return slugs - {""}


def guess_domains(name: str, federal_state: str = "") -> list[str]:
    """Generate plausible Austrian municipality email/website domains.

    Avoids dangerous generic guesses like st.at, bad.at, maria.at, deutsch.at,
    while still generating useful variants such as st-georgen.at,
    sankt-georgen.at, gemeinde-foo.at, and foo.<state>.at.
    """

    def _slugs_for(text: str) -> tuple[set[str], set[str]]:
        slugs = _name_slugs(text)
        extras: set[str] = set()

        # Joined (no-hyphen) variant — only if long enough to be unambiguous.
        for slug in list(slugs):
            joined = slug.replace("-", "")
            if joined != slug and len(joined) >= 8:
                extras.add(joined)

        return slugs, extras

    # Split on "/" to generate guesses for each part independently.
    parts = [part.strip() for part in name.split("/") if part.strip()]

    all_slugs: set[str] = set()
    all_extras: set[str] = set()

    slugs, extras = _slugs_for(name)
    all_slugs |= slugs
    all_extras |= extras

    if len(parts) > 1:
        for part in parts:
            slugs, extras = _slugs_for(part)
            all_slugs |= slugs
            all_extras |= extras

    candidates: set[str] = set()
    federal_state_key = FEDERAL_STATES.get(federal_state, "")

    for slug in all_slugs:
        candidates.add(f"{slug}.at")
        candidates.add(f"gemeinde-{slug}.at")
        candidates.add(f"stadt-{slug}.at")
        candidates.add(f"marktgemeinde-{slug}.at")
        candidates.add(f"markt-{slug}.at")

        if federal_state_key:
            candidates.add(f"{slug}.{federal_state_key}.at")
            candidates.add(f"{slug}.{federal_state_key}.gv.at")

    for extra in all_extras:
        candidates.add(f"{extra}.at")

    return sorted(candidates)


def detect_domain_mismatch(name: str, website_domain: str, federal_state: str | None) -> bool:
    """Detect if a website domain doesn't match the municipality name or federal state."""
    if not name or not website_domain:
        return False

    domain_lower = website_domain.lower()

    # Reject domains that are clearly non-municipal organisations.
    if any(pat in domain_lower for pat in NON_MUNICIPAL_DOMAIN_PATTERNS):
        return True

    # Reject domains that carry a different state's abbreviation as a label.
    if federal_state:
        expected_abbr = FEDERAL_STATES.get(federal_state)
        labels = re.split(r"[.-]+", domain_lower)
        if expected_abbr:
            for _state, abbr in FEDERAL_STATES.items():
                if abbr == expected_abbr:
                    continue
                if abbr in labels:
                    return True

    # Strip common municipality prefixes before slug comparison.
    for prefix in ("stadt-", "gemeinde-", "marktg-", "markt-"):
        if domain_lower.startswith(prefix):
            domain_lower = domain_lower[len(prefix):]
            break

    domain_base = domain_lower.rsplit(".", 1)[0] if "." in domain_lower else domain_lower
    domain_base_first = domain_base.split(".")[0]

    # Slug check — uses the same normalisation as guess_domains (St.→Sankt included).
    for slug in _name_slugs(name):
        if slug in domain_lower or slug == domain_base_first:
            return False

    # Word-level fallback: check ≥4-char non-stoplist tokens first.
    # If none of them match (or there are none — e.g. "Laa an der Thaya"),
    # retry with ≥3-char tokens so short but specific name components like
    # "laa" still catch their domain.
    normalised = _normalise_name(name)
    long_words = [w for w in re.findall(r"[a-z]{4,}", normalised) if w not in MISMATCH_WORD_STOPLIST]
    for word in long_words:
        if word in domain_lower:
            return False
    # No long word matched (covers both "no long words exist" and "long words exist but
    # none appear in the domain" — e.g. "Laa an der Thaya" has long word "thaya" that
    # isn't in "laa.at", so fall back to ≥3-char tokens to catch "laa").
    if not any(word in domain_lower for word in long_words):
        for word in re.findall(r"[a-z]{3,}", normalised):
            if word in domain_lower:
                return False

    return True


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher."""
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for char in encoded:
        code = ord(char)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                size = end - start + 1
                result.append(chr(start + (code - start + offset) % size))
                decrypted = True
                break
        if not decrypted:
            result.append(char)
    return "".join(result)


def _is_valid_domain(domain: str) -> bool:
    domain = domain.lower().strip().rstrip(".")

    if not domain or len(domain) > 253:
        return False
    if "\\" in domain or "/" in domain or "@" in domain:
        return False
    if ".." in domain:
        return False
    if "www." in domain and not domain.startswith("www."):
        return False
    if re.search(r"\.[a-z]{2,}www\.", domain):
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    return all(0 < len(label) <= 63 for label in labels)


def _source_domain_allowed(domain: str | None, source: str) -> bool:
    """Apply SKIP_DOMAINS to all sources except manual overrides and Staedtebund."""
    if not domain:
        return False
    if source in {"override", "staedtebund"}:
        return True
    return domain not in SKIP_DOMAINS


def extract_email_domain_counts(html: str) -> Counter[str]:
    """Count email domains found in HTML, including TYPO3-obfuscated emails."""
    counts: Counter[str] = Counter()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in SKIP_DOMAINS and _is_valid_domain(domain):
            counts[domain] += 1

    for email in re.findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower().rstrip("\\/.")
            if domain not in SKIP_DOMAINS and _is_valid_domain(domain):
                counts[domain] += 1

    for encoded in TYPO3_RE.findall(html):
        for offset in range(-25, 26):
            decoded = decrypt_typo3(encoded, offset).replace("mailto:", "")
            if "@" in decoded and EMAIL_RE.search(decoded):
                domain = decoded.split("@")[1].lower()
                if domain not in SKIP_DOMAINS and _is_valid_domain(domain):
                    counts[domain] += 1
                break

    for match in re.findall(
        r"[\w.-]+\s*[\[(]at[\])]\s*[\w.-]+\.\w+", html, re.IGNORECASE
    ):
        normalized = re.sub(r"\s*[\[(]at[\])]\s*", "@", match, flags=re.IGNORECASE)
        if "@" in normalized:
            domain = normalized.split("@")[1].lower()
            if domain not in SKIP_DOMAINS and _is_valid_domain(domain):
                counts[domain] += 1

    return counts


def build_urls(domain: str) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    bare = domain[4:] if domain.startswith("www.") else domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in SUBPAGES:
            urls.append(base + path)
    return urls


def _is_ssl_error(exc: BaseException) -> bool:
    """Check if an exception is an SSL verification error."""
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(current):
            return True
        current = current.__cause__ if current.__cause__ is not current else None
    return False


async def _fetch_insecure(url: str) -> httpx.Response:
    """Fetch a URL with SSL verification disabled."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        async with httpx.AsyncClient(verify=False) as insecure_client:
            return await insecure_client.get(url, follow_redirects=True, timeout=15)


def _process_scrape_response(
    response: httpx.Response,
    domain: str,
    all_domains: Counter[str],
    redirect_domain: str | None,
) -> tuple[Counter[str], str | None]:
    """Extract emails and detect redirects from a scrape response."""
    if response.status_code != 200:
        return all_domains, redirect_domain

    if redirect_domain is None:
        final_domain = url_to_domain(str(response.url))
        if final_domain and final_domain != domain:
            redirect_domain = final_domain
            logger.info("Redirect detected: {} -> {}", domain, redirect_domain)

    all_domains.update(extract_email_domain_counts(response.text))
    return all_domains, redirect_domain


async def scrape_email_domains(
    client: httpx.AsyncClient, domain: str
) -> tuple[Counter[str], str | None]:
    """Scrape a municipality website for email domains."""
    if not domain:
        return Counter(), None

    all_domains: Counter[str] = Counter()
    redirect_domain: str | None = None

    for url in build_urls(domain):
        try:
            response = await client.get(url, follow_redirects=True, timeout=15)
        except httpx.ConnectError as exc:
            if _is_ssl_error(exc):
                logger.info("SSL error on {}, retrying without verification", url)
                try:
                    response = await _fetch_insecure(url)
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
            response, domain, all_domains, redirect_domain
        )
        if all_domains:
            return all_domains, redirect_domain

    return all_domains, redirect_domain


async def _collect_website_source_candidates(
    client: httpx.AsyncClient,
    website_value: str | None,
) -> tuple[str | None, Counter[str], Counter[str]]:
    """Collect website-domain, scrape candidates, and redirect candidates."""
    website_domain = url_to_domain(website_value)
    scrape_counts: Counter[str] = Counter()
    redirect_counts: Counter[str] = Counter()

    if not website_domain:
        return None, scrape_counts, redirect_counts

    website_domains, redirect_domain = await scrape_email_domains(client, website_domain)

    for domain, count in website_domains.most_common():
        if await lookup_mx(domain):
            scrape_counts[domain] += count

    if redirect_domain and await lookup_mx(redirect_domain):
        redirect_counts[redirect_domain] += 1

    return website_domain, scrape_counts, redirect_counts


def _add_scrape_candidates(
    *,
    sources: dict[str, set[str]],
    scrape_counts: Counter[str],
    source_key: str,
    name: str,
    federal_state: str,
    evidence: Counter[str] | None = None,
) -> None:
    for email_domain, count in scrape_counts.most_common():
        is_valid_kaernten_shared_email = (
                federal_state == "Kärnten"
                and email_domain == "ktn.gde.at"
            )

        if (
            detect_domain_mismatch(name, email_domain, federal_state)
            and not is_valid_kaernten_shared_email
        ):
            logger.debug(
                "Filtered mismatching {} candidate for {}: {}",
                source_key,
                name,
                email_domain,
            )
            continue

        sources[source_key].add(email_domain)
        if evidence is not None:
            evidence[email_domain] += count


def _add_redirect_candidates(
    *,
    sources: dict[str, set[str]],
    redirect_counts: Counter[str],
    source_key: str,
    name: str,
    federal_state: str,
) -> None:
    for redirect_domain, _count in redirect_counts.most_common():
        if not _source_domain_allowed(redirect_domain, source_key):
            logger.debug(
                "Filtered skipped redirect candidate for {}: {}",
                name,
                redirect_domain,
            )
            continue

        if detect_domain_mismatch(name, redirect_domain, federal_state):
            logger.debug(
                "Filtered mismatching {} candidate for {}: {}",
                source_key,
                name,
                redirect_domain,
            )
            continue

        sources[source_key].add(redirect_domain)
        

async def resolve_municipality_domain(
    municipality: dict[str, str],
    overrides: dict[str, dict[str, str]],
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    """Resolve a municipality's email domain using sequential trust stages."""
    gkz = municipality["gkz"]
    name = municipality["name"]
    federal_state = municipality.get("federal_state", "")

    entry: dict[str, Any] = {
        "gkz": gkz,
        "name": name,
        "federal_state": federal_state,
    }

    sources: dict[str, set[str]] = {source: set() for source in SOURCE_KEYS}

    website_candidate_cache: dict[str, tuple[str | None, Counter[str], Counter[str]]] = {}

    async def _get_cached(
        website_value: str | None,
    ) -> tuple[str | None, Counter[str], Counter[str]]:
        website_domain = url_to_domain(website_value)
        if not website_domain:
            return None, Counter(), Counter()
        if website_domain not in website_candidate_cache:
            website_candidate_cache[website_domain] = await _collect_website_source_candidates(
                client, website_domain
            )
        cached_domain, cached_sc, cached_rc = website_candidate_cache[website_domain]
        return cached_domain, Counter(cached_sc), Counter(cached_rc)

    def _downgrade(confidence: str) -> str:
        return {"high": "medium", "medium": "low", "low": "low", "none": "none"}[confidence]

    def _make_result(domain: str, source: str, confidence: str, flags: list[str]) -> dict[str, Any]:
        final_flags = list(flags)
        final_confidence = confidence
        if domain and source != "override":
            is_valid_kaernten = federal_state == "Kärnten" and domain == "ktn.gde.at"
            if not is_valid_kaernten and detect_domain_mismatch(name, domain, federal_state):
                final_flags.append("domain_mismatch")
                final_confidence = _downgrade(final_confidence)
        entry.update({
            "domain": domain,
            "source": source,
            "confidence": final_confidence,
            "sources_detail": {k: sorted(v) for k, v in sources.items()},
            "flags": final_flags,
        })
        return entry

    domain_evidence: Counter[str] = Counter()

    def _best(candidates: set[str]) -> str:
        return min(candidates, key=lambda d: (-domain_evidence[d], d))

    def _two_families_agree(families: list[set[str]]) -> str | None:
        """Return best domain appearing in 2+ of the given non-empty family sets."""
        active = [f for f in families if f]
        if len(active) < 2:
            return None
        all_domains: set[str] = set().union(*active)
        agreed = {d for d in all_domains if sum(1 for f in active if d in f) >= 2}
        return _best(agreed) if agreed else None

    # ── Step 1: Override ──────────────────────────────────────────────────────
    override = overrides.get(gkz, {})
    override_domain = url_to_domain(
        override.get("override_domain") or municipality.get("override_domain", "")
    )
    override_website = url_to_domain(
        override.get("override_website") or municipality.get("override_website", "")
    )

    if override_domain and await lookup_mx(override_domain):
        sources["override"].add(override_domain)
        return _make_result(override_domain, "override", "high", [])

    if override_website and override_website != override_domain and await lookup_mx(override_website):
        sources["override"].add(override_website)
        return _make_result(override_website, "override", "high", [])

    if override_website:
        _, sc, rc = await _get_cached(override_website)
        _add_scrape_candidates(
            sources=sources, scrape_counts=sc, source_key="override_scrape",
            name=name, federal_state=federal_state, evidence=domain_evidence,
        )
        _add_redirect_candidates(
            sources=sources, redirect_counts=rc, source_key="override_redirect",
            name=name, federal_state=federal_state,
        )

    # ── Step 2: Städtebund ────────────────────────────────────────────────────
    website_sb = municipality.get("website_sb", "")
    sb_domain = url_to_domain(website_sb)

    if sb_domain and await lookup_mx(sb_domain):
        sources["staedtebund"].add(sb_domain)
        return _make_result(sb_domain, "staedtebund", "high", [])

    if website_sb:
        _, sb_sc, sb_rc = await _get_cached(website_sb)
        _add_scrape_candidates(
            sources=sources, scrape_counts=sb_sc, source_key="staedtebund_scrape",
            name=name, federal_state=federal_state, evidence=domain_evidence,
        )
        _add_redirect_candidates(
            sources=sources, redirect_counts=sb_rc, source_key="staedtebund_redirect",
            name=name, federal_state=federal_state,
        )

    # ── Step 3: Wikidata ──────────────────────────────────────────────────────
    website_wd = municipality.get("website_wd", "")
    wd_domain, wd_sc, wd_rc = await _get_cached(website_wd)

    if (
        wd_domain
        and _source_domain_allowed(wd_domain, "wikidata")
        and not detect_domain_mismatch(name, wd_domain, federal_state)
        and await lookup_mx(wd_domain)
    ):
        sources["wikidata"].add(wd_domain)

    _add_scrape_candidates(
        sources=sources, scrape_counts=wd_sc, source_key="wikidata_scrape",
        name=name, federal_state=federal_state, evidence=domain_evidence,
    )
    _add_redirect_candidates(
        sources=sources, redirect_counts=wd_rc, source_key="wikidata_redirect",
        name=name, federal_state=federal_state,
    )

    # ── Step 4: Agreement check (before guessing) ─────────────────────────────
    override_family = sources["override_scrape"] | sources["override_redirect"]
    sb_family = sources["staedtebund_scrape"] | sources["staedtebund_redirect"]
    wd_family = sources["wikidata"] | sources["wikidata_scrape"] | sources["wikidata_redirect"]

    agreed = _two_families_agree([override_family, sb_family, wd_family])
    if agreed:
        return _make_result(agreed, "source_agreement", "high", [])

    # ── Step 5: Guess — MX phase ──────────────────────────────────────────────
    for guess in guess_domains(name, federal_state):
        if not _source_domain_allowed(guess, "guess"):
            logger.debug("Filtered skipped guess candidate for {}: {}", name, guess)
            continue
        if await lookup_mx(guess):
            sources["guess"].add(guess)

    agreed = _two_families_agree([override_family, sb_family, wd_family, sources["guess"]])
    if agreed:
        return _make_result(agreed, "source_agreement", "medium", [])

    # ── Step 6: Guess — scrape phase ──────────────────────────────────────────
    for guess in sources["guess"]:
        _, sc, rc = await _get_cached(guess)
        _add_scrape_candidates(
            sources=sources, scrape_counts=sc, source_key="guess_scrape",
            name=name, federal_state=federal_state, evidence=domain_evidence,
        )
        _add_redirect_candidates(
            sources=sources, redirect_counts=rc, source_key="guess_redirect",
            name=name, federal_state=federal_state,
        )

    guess_family = sources["guess"] | sources["guess_scrape"] | sources["guess_redirect"]
    agreed = _two_families_agree([override_family, sb_family, wd_family, guess_family])
    if agreed:
        return _make_result(agreed, "source_agreement", "medium", [])

    # ── Step 7: Priority fallback ─────────────────────────────────────────────
    # Use sources_disagree only when 2+ trusted families contributed candidates
    # but couldn't agree. A lone trusted family plus guesses is single_source
    # (guesses don't count as a disagreeing party).
    trusted_families = [f for f in [override_family, sb_family, wd_family] if f]
    fallback_flags = ["sources_disagree"] if len(trusted_families) >= 2 else ["single_source"]

    for key, tier_confidence in [
        ("override_scrape", "medium"),
        ("override_redirect", "medium"),
        ("staedtebund_scrape", "medium"),
        ("staedtebund_redirect", "medium"),
        ("wikidata", "low"),
        ("wikidata_scrape", "low"),
        ("wikidata_redirect", "low"),
        ("guess", "low"),
        ("guess_scrape", "low"),
        ("guess_redirect", "low"),
    ]:
        if not sources[key]:
            continue
        flags = ["guess_only"] if key.startswith("guess") and not trusted_families else fallback_flags
        return _make_result(_best(sources[key]), key, tier_confidence, flags)

    # ── Step 8: No winner ────────────────────────────────────────────────────
    return _make_result("", "none", "none", [])
