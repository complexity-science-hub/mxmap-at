import json
from collections import Counter
from unittest.mock import AsyncMock, patch

import httpx
import pandas as pd
import pytest
import respx
import stamina

from mail_sovereignty.resolve_domains import (
    _is_ssl_error,
    _process_scrape_response,
    build_urls,
    decrypt_typo3,
    detect_domain_mismatch,
    extract_email_domain_counts,
    guess_domains,
    resolve_municipality_domain,
    scrape_email_domains,
    url_to_domain,
)
from mail_sovereignty.run_resolve import (
    _add_shared_domain_flags,
    _clean_string,
    _iter_map_feature_properties,
    _normalise_gkz,
    fetch_wikidata,
    load_map_municipalities,
    load_overrides,
    load_staedtebund,
    merge_overrides_into_municipalities,
    merge_staedtebund_into_municipalities,
    merge_wikidata_into_municipalities,
    municipality_identity_matches,
    municipality_names_match,
    run,
)


# ── Compatibility aliases for tests ─────────────────────────────────────


def detect_website_mismatch(
    name: str, domain: str, federal_state: str | None = None
) -> bool:
    return detect_domain_mismatch(name, domain, federal_state)


def extract_email_domains(html: str) -> set[str]:
    return set(extract_email_domain_counts(html))


# ── url_to_domain() ─────────────────────────────────────────────────


class TestUrlToDomain:
    def test_full_url_with_path(self):
        assert url_to_domain("https://www.eisenstadt.at/some/path") == "eisenstadt.at"

    def test_no_scheme(self):
        assert url_to_domain("eisenstadt.at") == "eisenstadt.at"

    def test_strips_www(self):
        assert url_to_domain("https://www.example.at") == "example.at"

    def test_empty_string(self):
        assert url_to_domain("") is None

    def test_none(self):
        assert url_to_domain(None) is None

    def test_bare_domain(self):
        assert url_to_domain("example.at") == "example.at"

    def test_http_scheme(self):
        assert url_to_domain("http://example.at/page") == "example.at"


# ── guess_domains() ─────────────────────────────────────────────────


class TestGuessDomains:
    def test_simple_name(self):
        domains = guess_domains("eisenstadt")
        assert "eisenstadt.at" in domains
        assert "gemeinde-eisenstadt.at" in domains

    def test_umlaut(self):
        domains = guess_domains("Mödling")
        assert "moedling.at" in domains

    def test_parenthetical_stripped(self):
        domains = guess_domains("Mödling (BE)")
        assert any("moedling" in d for d in domains)
        assert not any("BE" in d for d in domains)

    def test_stadt_prefix(self):
        domains = guess_domains("eisenstadt")
        assert "stadt-eisenstadt.at" in domains

    def test_state_subdomain(self):
        domains = guess_domains("Town", federal_state="Burgenland")
        assert "town.bgld.at" in domains

    def test_state_subdomain_not_added_without_federal_state(self):
        domains = guess_domains("Town", federal_state="")
        assert not any(".burgenland.at" in d for d in domains)

    def test_compound_name_joined(self):
        domains = guess_domains("Rüti bei Lyssach")
        assert "ruetibeilyssach.at" in domains

    def test_slash_name_generates_individual_parts(self):
        """'Celerina/Schlarigna' yields guesses for each part."""
        domains = guess_domains("Celerina/Schlarigna")
        assert "celerina.at" in domains
        assert "schlarigna.at" in domains
        assert "gemeinde-celerina.at" in domains

    def test_slash_name_with_spaces(self):
        """'Sils im Engadin/Segl' yields guesses for each part."""
        domains = guess_domains("Sils im Engadin/Segl")
        assert "segl.at" in domains
        assert "sils-im-engadin.at" in domains

    def test_no_slash_unchanged(self):
        """Names without '/' produce the same results as before."""
        domains = guess_domains("eisenstadt")
        assert "eisenstadt.at" in domains
        assert "gemeinde-eisenstadt.at" in domains


# ── detect_website_mismatch() ────────────────────────────────────────


class TestDetectWebsiteMismatch:
    def test_matching_domain(self):
        assert detect_website_mismatch("Schlieren", "schlieren.at") is False

    def test_umlaut_with_stadt_prefix(self):
        assert detect_website_mismatch("Wien", "stadt-wien.at") is False

    def test_mismatch(self):
        assert detect_website_mismatch("Schlieren", "totally-unrelated.at") is True

    def test_federal_state_subdomain(self):
        assert detect_website_mismatch("Teufen", "teufen.burgenland.at") is False

    def test_gemeinde_prefix(self):
        assert (
            detect_website_mismatch("Grindelwald", "gemeinde-grindelwald.at") is False
        )

    def test_empty_name(self):
        assert detect_website_mismatch("", "example.at") is False

    def test_empty_domain(self):
        assert detect_website_mismatch("Test", "") is False

    def test_word_match(self):
        # "Aeugst am Albis" — "aeugst" (5 chars) should match
        assert detect_website_mismatch("Aeugst am Albis", "aeugst-albis.at") is False


# ── fetch_wikidata() ─────────────────────────────────────────────────


class TestFetchWikidata:
    @respx.mock
    async def test_success(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "eisenstadt"},
                                "website": {"value": "https://www.eisenstadt.at"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert "10101" in result
        assert result["10101"]["name"] == "eisenstadt"

    @respx.mock
    async def test_deduplication(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "eisenstadt"},
                                "website": {"value": "https://www.eisenstadt.at"},
                            },
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "eisenstadt"},
                                "website": {"value": "https://www.eisenstadt.at/alt"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert len(result) == 1


# ── load_overrides() ─────────────────────────────────────────────────


class TestLoadOverrides:
    def test_load_existing(self, tmp_path):
        p = tmp_path / "overrides.json"
        p.write_text('{"261": {"domain": "zuerich.at", "reason": "test"}}')
        result = load_overrides(p)
        assert "261" in result
        assert result["261"]["domain"] == "zuerich.at"

    def test_load_nonexistent(self, tmp_path):
        result = load_overrides(tmp_path / "nonexistent.json")
        assert result == {}


# ── decrypt_typo3() ──────────────────────────────────────────────────


class TestDecryptTypo3:
    def test_known_encrypted(self):
        encrypted = "kygjrm8yYz,af"
        decrypted = decrypt_typo3(encrypted)
        assert decrypted == "mailto:a@b.ch"

    def test_empty_string(self):
        assert decrypt_typo3("") == ""

    def test_offset_10_celerina(self):
        """Site encrypted with +10 offset; decrypt with -10 (== 16 mod 26)."""
        encoded = "wksvdy4sxpyJmovobsxk8mr"
        decrypted = decrypt_typo3(encoded, offset=-10)
        assert decrypted == "mailto:info@celerina.ch"

    def test_standard_offset_still_works(self):
        """No regression: offset=2 (default) still decrypts standard TYPO3."""
        encrypted = "kygjrm8yYz,af"
        assert decrypt_typo3(encrypted, offset=2) == "mailto:a@b.ch"


# ── extract_email_domains() ──────────────────────────────────────────


class TestExtractEmailDomains:
    def test_plain_email(self):
        html = "Contact us at info@gemeinde.at for more info."
        assert "gemeinde.at" in extract_email_domains(html)

    def test_mailto_link(self):
        html = '<a href="mailto:contact@town.at">Email</a>'
        assert "town.at" in extract_email_domains(html)

    def test_typo3_obfuscated(self):
        html = """linkTo_UnCryptMailto('kygjrm8yYz,af')"""
        domains = extract_email_domains(html)
        assert "b.ch" in domains

    def test_typo3_url_encoded_quotes(self):
        """TYPO3 regex matches %27 (URL-encoded single quote)."""
        html = "linkTo_UnCryptMailto(%27kygjrm8yYz,af%27)"
        domains = extract_email_domains(html)
        assert "b.ch" in domains

    def test_typo3_auto_offset_detection(self):
        """Auto-detect offset for non-standard TYPO3 encryption (e.g. offset 10)."""
        html = "linkTo_UnCryptMailto(%27wksvdy4sxpyJmovobsxk8mr%27)"
        domains = extract_email_domains(html)
        assert "celerina.ch" in domains

    def test_skip_domains_filtered(self):
        html = "admin@example.com test@sentry.io"
        domains = extract_email_domains(html)
        assert "example.com" not in domains
        assert "sentry.io" not in domains

    def test_no_emails(self):
        html = "<html><body>No contact here</body></html>"
        assert extract_email_domains(html) == set()

    def test_mailto_trailing_backslash(self):
        """BadEscape: backslash in mailto href should be stripped."""
        html = '<a href="mailto:info@eisenstadtex.at\\">contact</a>'
        domains = extract_email_domains(html)
        assert "eisenstadtex.at" in domains

    def test_mailto_trailing_slash(self):
        """Trailing slash from malformed mailto should be stripped."""
        html = '<a href="mailto:info@example.org/">contact</a>'
        domains = extract_email_domains(html)
        assert "example.org" in domains

    def test_bracket_at_obfuscation(self):
        html = "gemeinde[at]graechen.at"
        assert "graechen.at" in extract_email_domains(html)

    def test_paren_at_obfuscation(self):
        html = "info(at)gemeinde.at"
        assert "gemeinde.at" in extract_email_domains(html)

    def test_bracket_at_with_spaces(self):
        html = "info [at] town.at"
        assert "town.at" in extract_email_domains(html)

    def test_bracket_at_uppercase(self):
        html = "admin[AT]village.at"
        assert "village.at" in extract_email_domains(html)

    def test_bracket_at_skip_domain(self):
        html = "user[at]example.com"
        assert extract_email_domains(html) == set()

    def test_domain_label_too_long(self):
        """Domains with labels > 63 chars should be filtered out."""
        long_label = "a" * 64
        html = f"contact@{long_label}.at"
        assert extract_email_domains(html) == set()

    def test_domain_with_slash_filtered(self):
        """Domains containing a slash (URL fragment) should be filtered out."""
        html = "user@galeriedelachampagne.at/subpage"
        domains = extract_email_domains(html)
        # The EMAIL_RE may capture "galeriedelachampagne.at" (valid part),
        # but any domain with "/" should be filtered
        for d in domains:
            assert "/" not in d


# ── build_urls() ─────────────────────────────────────────────────────


class TestBuildUrls:
    def test_bare_domain(self):
        urls = build_urls("example.at")
        assert "https://www.example.at/" in urls
        assert "https://example.at/" in urls
        assert any("/kontakt" in u for u in urls)

    def test_www_prefix(self):
        urls = build_urls("www.example.at")
        assert "https://www.example.at/" in urls
        assert "https://example.at/" in urls


# ── scrape_email_domains() ───────────────────────────────────────────


class TestScrapeEmailDomains:
    async def test_empty_domain(self):
        result, redirect = await scrape_email_domains(None, "")
        assert result == Counter()
        assert redirect is None

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeinde.at"
            url = httpx.URL("https://www.gemeinde.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde.at")
        # Early return after first URL with results; count is per-page occurrences
        assert result["gemeinde.at"] >= 1
        assert redirect is None

    async def test_ranks_domains_by_frequency(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@alpha.at alpha@alpha.at admin@beta.at"
            url = httpx.URL("https://www.example.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "example.at")

        assert [d for d, _ in result.most_common()] == ["alpha.at", "beta.at"]
        assert redirect is None

    async def test_cross_domain_redirect_detected(self):
        """When website redirects to a different domain, redirect_domain is returned."""

        class FakeResponse:
            status_code = 200
            text = "Contact us at gemeinde@3908.at"
            url = httpx.URL("https://www.3908.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde-saas-balen.at")
        assert result["3908.at"] >= 1
        assert redirect == "3908.at"

    async def test_www_redirect_not_flagged(self):
        """Redirect from mygemeinde.at to www.mygemeinde.at is NOT a cross-domain redirect."""

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@mygemeinde.at"
            url = httpx.URL("https://www.mygemeinde.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "mygemeinde.at")
        assert result["mygemeinde.at"] >= 1
        assert redirect is None


# ── resolve_municipality_domain() ────────────────────────────────────


class TestResolveMunicipalityDomain:
    async def test_override_takes_priority(self):
        m = {
            "gkz": "10101",
            "name": "Eisenstadt",
            "federal_state": "Burgenland",
        }
        overrides = {"10101": {"override_domain": "https://www.eisenstadt.at"}}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mail.protection.outlook.com"],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "eisenstadt.at"
        assert result["source"] == "override"
        assert result["confidence"] == "high"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_override_website_scraped_for_email_domain(self):
        """When override has a website but no direct MX, its pages are scraped."""
        m = {
            "gkz": "10101",
            "name": "Eisenstadt",
            "federal_state": "Burgenland",
        }
        overrides = {"10101": {"override_website": "https://www.eisenstadt.at"}}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@stadt-eisenstadt.at"
            url = httpx.URL("https://www.eisenstadt.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "eisenstadt.at":
                return []
            if domain == "stadt-eisenstadt.at":
                return ["mx.stadt-eisenstadt.at"]
            return []

        with (
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
            ),
            patch("mail_sovereignty.resolve_domains.guess_domains", return_value=[]),
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "stadt-eisenstadt.at"
        assert result["source"] == "override_scrape"
        assert result["confidence"] == "medium"
        assert result["sources_detail"]["override_scrape"] == ["stadt-eisenstadt.at"]

    async def test_staedtebund_wikidata_agree_high_confidence(self):
        """When Städtebund scrape and Wikidata scrape find the same domain, confidence is high."""
        m = {
            "gkz": "999",
            "name": "Test",
            "federal_state": "",
            "website_sb": "https://www.test.at",
            "website_wd": "https://test.at",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@mail-test.at"
            url = httpx.URL("https://www.test.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "mail-test.at":
                return ["mx.mail-test.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "mail-test.at"
        assert result["confidence"] == "high"
        assert "mail-test.at" in result["sources_detail"]["staedtebund_scrape"]
        assert "mail-test.at" in result["sources_detail"]["wikidata_scrape"]

    async def test_wikidata_scrape_only_low_confidence(self):
        """When only Wikidata scraping finds a domain (single trusted family), confidence is low."""
        m = {
            "gkz": "999",
            "name": "Test",
            "federal_state": "",
            "website_wd": "https://www.test.at",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@email-test.at"
            url = httpx.URL("https://www.test.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "email-test.at":
                return ["mail.email-test.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "email-test.at"
        assert result["source"] == "wikidata_scrape"
        assert "email-test.at" in result["sources_detail"]["wikidata_scrape"]

    async def test_scrape_finds_different_domain_than_website(self):
        """Municipality website has MX, but scraping finds regional mail domain."""

        m = {
            "gkz": "20806",
            "name": "Gallizien",
            "federal_state": "Kärnten",
            "website_wd": "https://www.gallizien.at",
        }

        overrides = {}

        class FakeResponse:
            status_code = 200
            text = '<a href="mailto:gemeinde@ktn.gde.at">Email</a>'
            url = httpx.URL("https://www.gallizien.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "gallizien.at":
                return ["mail.gallizien.at"]
            if domain == "ktn.gde.at":
                return ["mx.ktn.gde.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx",
            side_effect=fake_lookup_mx,
        ):
            result = await resolve_municipality_domain(
                m,
                overrides,
                client,
            )

        # Website domain discovered via wikidata
        assert "gallizien.at" in result["sources_detail"]["wikidata"]

        # Scraped mail domain discovered
        assert "ktn.gde.at" in result["sources_detail"]["wikidata_scrape"]

    async def test_same_website_host_scraped_once_for_staedtebund_and_wikidata(self):
        m = {
            "gkz": "999",
            "name": "Test",
            "federal_state": "",
            "website_sb": "https://www.test.at",
            "website_wd": "https://test.at",
        }
        overrides = {}
        client = AsyncMock()

        # sb_domain "test.at" has no MX so scraping kicks in; mail-test.at has MX
        shared_result = ("test.at", Counter({"mail-test.at": 2}), Counter())

        async def fake_lookup_mx(domain):
            if domain in {"mail-test.at"}:
                return ["mx.example.invalid"]
            return []

        with (
            patch(
                "mail_sovereignty.resolve_domains._collect_website_source_candidates",
                new_callable=AsyncMock,
                return_value=shared_result,
            ) as mock_collect,
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
            ),
            patch("mail_sovereignty.resolve_domains.guess_domains", return_value=[]),
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        mock_collect.assert_awaited_once()
        assert result["domain"] == "mail-test.at"
        assert result["sources_detail"]["staedtebund_scrape"] == ["mail-test.at"]
        assert result["sources_detail"]["wikidata_scrape"] == ["mail-test.at"]

    async def test_none_when_no_domain_found(self):
        m = {"gkz": "999", "name": "Zzz", "federal_state": ""}
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == ""
        assert result["source"] == "none"
        assert result["confidence"] == "none"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_single_source_guess_low_confidence(self):
        """When only guess finds a domain, confidence is low with guess_only flag."""
        m = {
            "gkz": "999",
            "name": "Testingen",
            "federal_state": "Wien",
        }
        overrides = {}
        client = AsyncMock()

        async def fake_lookup_mx(domain):
            if domain == "testingen.at":
                return ["mail.testingen.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "testingen.at"
        assert result["source"] == "guess"
        assert result["confidence"] == "low"
        assert "guess_only" in result["flags"]

    async def test_guess_skip_domain_filtered(self):
        m = {
            "gkz": "999",
            "name": "Example",
            "federal_state": "Wien",
        }
        overrides = {}
        client = AsyncMock()

        async def fake_lookup_mx(domain):
            if domain == "example.at":
                return ["mail.example.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == ""
        assert result["source"] == "none"
        assert result["sources_detail"]["guess"] == []

    async def test_staedtebund_skip_domain_is_allowed_but_wikidata_skip_domain_is_filtered(
        self,
    ):
        m = {
            "gkz": "999",
            "name": "Example",
            "federal_state": "",
            "website_sb": "https://www.example.at",
            "website_wd": "https://www.domain.com",
        }
        overrides = {}

        class FakeResponse:
            status_code = 404
            text = ""
            url = httpx.URL("https://www.example.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain in {"example.at", "domain.com"}:
                return ["mail.test.invalid"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "example.at"
        assert result["source"] == "staedtebund"
        assert result["sources_detail"]["staedtebund"] == ["example.at"]
        assert result["sources_detail"]["wikidata"] == []

    async def test_redirect_skip_domain_filtered(self):
        m = {
            "gkz": "999",
            "name": "Example",
            "federal_state": "",
            "website_wd": "https://www.municipality.at",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "No contact here"
            url = httpx.URL("https://www.example.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "example.at":
                return ["mail.example.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == ""
        assert result["source"] == "none"
        assert result["sources_detail"]["wikidata_redirect"] == []

    async def test_redirect_domain_used_as_source(self):
        """Website redirects to a name-matching domain, which is accepted as source."""
        m = {
            "gkz": "999",
            "name": "Saas-Balen",
            "federal_state": "",
            "website_wd": "https://www.saas-balen.at",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at gemeinde@saas-balen-gemeinde.at"
            url = httpx.URL("https://www.saas-balen-gemeinde.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "saas-balen-gemeinde.at":
                return ["mx.saas-balen-gemeinde.at"]
            return []

        with patch(
            "mail_sovereignty.resolve_domains.lookup_mx", side_effect=fake_lookup_mx
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "saas-balen-gemeinde.at"
        assert "saas-balen-gemeinde.at" in result["sources_detail"]["wikidata_scrape"]
        assert "saas-balen-gemeinde.at" in result["sources_detail"]["wikidata_redirect"]


# ── run() ────────────────────────────────────────────────────────────


MUNICIPALITIES_CSV_HEADER = "municipality_name,bundesland,gkz,domain"
SAMPLE_MUNICIPALITIES_CSV = f"""{MUNICIPALITIES_CSV_HEADER}
Eisenstadt,Burgenland,10101,eisenstadt.gv.at
Graz,Steiermark,60101,graz.at
Linz,Oberoesterreich,40101,linz.at
"""
EMPTY_MUNICIPALITIES_CSV = MUNICIPALITIES_CSV_HEADER + "\n"

_MAP_MUNICIPALITIES = {
    "10101": {"gkz": "10101", "name": "Eisenstadt", "federal_state": "Burgenland"},
    "60101": {"gkz": "60101", "name": "Graz", "federal_state": "Steiermark"},
    "40101": {"gkz": "40101", "name": "Linz", "federal_state": "Oberösterreich"},
}


class TestResolveRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(SAMPLE_MUNICIPALITIES_CSV, encoding="utf-8")

        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "eisenstadt"},
                                "website": {"value": "https://www.eisenstadt.at"},
                            },
                        ]
                    }
                },
            )
        )

        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value=dict(_MAP_MUNICIPALITIES),
            ),
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx.eisenstadt.at"],
            ),
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 3
        assert "10101" in data["municipalities"]

    @respx.mock
    async def test_gkz_wikidata_merge(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(SAMPLE_MUNICIPALITIES_CSV, encoding="utf-8")

        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "Eisenstadt"},
                                "website": {"value": "https://www.eisenstadt.at"},
                            },
                        ]
                    }
                },
            )
        )

        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value=dict(_MAP_MUNICIPALITIES),
            ),
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx.eisenstadt.at"],
            ),
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv)

        data = json.loads(output.read_text())
        entry = data["municipalities"]["10101"]
        assert entry["name"] == "Eisenstadt"
        assert "sources_detail" in entry


# ── Wikidata retry ────────────────────────────────────────────────

WIKIDATA_JSON = {
    "results": {
        "bindings": [
            {
                "gkz": {"value": "10101"},
                "itemLabel": {"value": "eisenstadt"},
                "website": {"value": "https://www.eisenstadt.at"},
                "federal_stateLabel": {"value": "eisenstadt"},
            },
        ]
    }
}


class TestFetchWikidataRetry:
    @respx.mock
    async def test_retries_on_503_then_succeeds(self):
        stamina.set_testing(False)
        route = respx.post("https://query.wikidata.org/sparql").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(200, json=WIKIDATA_JSON),
            ]
        )
        result = await fetch_wikidata()
        assert "10101" in result
        assert route.call_count == 2

    @respx.mock
    async def test_raises_after_all_retries_exhausted(self):
        stamina.set_testing(False)
        route = respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(503)
        )
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_wikidata()
        assert route.call_count == 3


# ── Scrape error logging ─────────────────────────────────────────


class TestScrapeErrorLogging:
    async def test_logs_debug_on_exception(self, caplog):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=ConnectionError("refused"))

        result, redirect = await scrape_email_domains(client, "fail.at")

        assert result == Counter()
        assert redirect is None
        assert any("Scrape" in msg and "refused" in msg for msg in caplog.messages)


# ── Error isolation in resolve run() ─────────────────────────────


class TestResolveRunErrorIsolation:
    @respx.mock
    async def test_skips_failing_municipality(self, tmp_path):
        """One failing resolution should not crash the whole run."""
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(
            """municipality_name,bundesland,gkz,domain
Linz,Oberoesterreich,40101,linz.at
Graz,Steiermark,60101,graz.at
""",
            encoding="utf-8",
        )

        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )

        call_count = 0

        async def _flaky_resolve(m, overrides, client):
            nonlocal call_count
            call_count += 1
            if m["gkz"] == "60101":
                raise RuntimeError("boom")
            return {
                "gkz": m["gkz"],
                "name": m["name"],
                "federal_state": m.get("federal_state", ""),
                "domain": "test.at",
                "source": "guess",
                "confidence": "low",
                "sources_detail": {},
                "flags": [],
            }

        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value={
                    "40101": {
                        "gkz": "40101",
                        "name": "Linz",
                        "federal_state": "Oberösterreich",
                    },
                    "60101": {
                        "gkz": "60101",
                        "name": "Graz",
                        "federal_state": "Steiermark",
                    },
                },
            ),
            patch(
                "mail_sovereignty.run_resolve.resolve_municipality_domain",
                side_effect=_flaky_resolve,
            ),
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv)

        data = json.loads(output.read_text())
        assert "40101" in data["municipalities"]
        assert "60101" not in data["municipalities"]


class TestResolveRunLogging:
    pass


# ── _process_scrape_response() ────────────────────────────────────────


class TestProcessScrapeResponse:
    def test_non_200_returns_unchanged(self):
        r = httpx.Response(404, request=httpx.Request("GET", "https://example.at"))
        domains, redirect = _process_scrape_response(r, "example.at", Counter(), None)
        assert not domains
        assert redirect is None

    def test_200_extracts_email_and_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@3908.at",
            request=httpx.Request("GET", "https://www.3908.at/"),
        )
        domains, redirect = _process_scrape_response(
            r, "gemeinde-saas-balen.at", Counter(), None
        )
        assert "3908.at" in domains
        assert redirect == "3908.at"

    def test_200_same_domain_no_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@mygemeinde.at",
            request=httpx.Request("GET", "https://www.mygemeinde.at/"),
        )
        domains, redirect = _process_scrape_response(
            r, "mygemeinde.at", Counter(), None
        )
        assert "mygemeinde.at" in domains
        assert redirect is None

    def test_preserves_existing_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@other.at",
            request=httpx.Request("GET", "https://www.other.at/"),
        )
        domains, redirect = _process_scrape_response(
            r, "example.at", Counter(), "already.at"
        )
        assert "other.at" in domains
        assert redirect == "already.at"


# ── _is_ssl_error() ─────────────────────────────────────────────────


class TestIsSslError:
    def test_direct_ssl_error(self):
        import ssl

        exc = ssl.SSLCertVerificationError("certificate verify failed")
        assert _is_ssl_error(exc) is True

    def test_nested_ssl_error(self):
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL error")
        connect_exc.__cause__ = ssl_exc
        assert _is_ssl_error(connect_exc) is True

    def test_non_ssl_error(self):
        exc = ConnectionRefusedError("Connection refused")
        assert _is_ssl_error(exc) is False

    def test_string_fallback(self):
        exc = Exception("CERTIFICATE_VERIFY_FAILED in handshake")
        assert _is_ssl_error(exc) is True


# ── SSL retry in scrape_email_domains() ──────────────────────────────


class TestSslRetry:
    @pytest.mark.asyncio
    async def test_ssl_error_triggers_insecure_retry(self):
        """SSL error should trigger an insecure retry that recovers."""
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL handshake failed")
        connect_exc.__cause__ = ssl_exc

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        fake_response = AsyncMock()
        fake_response.status_code = 200
        fake_response.text = "Contact: gemeinde@3908.at"
        fake_response.url = httpx.URL("https://www.3908.at/")

        with patch(
            "mail_sovereignty.resolve_domains._fetch_insecure",
            new_callable=AsyncMock,
            return_value=fake_response,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(
                client, "gemeinde-saas-balen.at"
            )

        assert "3908.at" in domains
        assert redirect == "3908.at"
        mock_fetch.assert_called()

    @pytest.mark.asyncio
    async def test_non_ssl_connect_error_no_retry(self):
        """Non-SSL ConnectError should not trigger insecure retry."""
        connect_exc = httpx.ConnectError("Connection refused")

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        with patch(
            "mail_sovereignty.resolve_domains._fetch_insecure",
            new_callable=AsyncMock,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(client, "example.at")

        assert domains == Counter()
        assert redirect is None
        mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_ssl_retry_failure_continues(self):
        """If insecure retry also fails, scrape should continue gracefully."""
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL handshake failed")
        connect_exc.__cause__ = ssl_exc

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        with patch(
            "mail_sovereignty.resolve_domains._fetch_insecure",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("still broken"),
        ):
            domains, redirect = await scrape_email_domains(client, "example.at")

        assert domains == Counter()
        assert redirect is None


# ── run_resolve helpers ───────────────────────────────────────────────


class TestNormaliseGkz:
    def test_plain_integer(self):
        assert _normalise_gkz("10101") == "10101"

    def test_float_string(self):
        assert _normalise_gkz("10101.0") == "10101"

    def test_non_digit_prefix(self):
        assert _normalise_gkz("AT10101") == "10101"

    def test_empty(self):
        assert _normalise_gkz("") == ""

    def test_none(self):
        assert _normalise_gkz(None) == ""


class TestCleanString:
    def test_none_returns_empty(self):
        assert _clean_string(None) == ""

    def test_list_triggers_type_error_branch(self):
        result = _clean_string([1, 2])
        assert result == "[1, 2]"

    def test_nan_returns_empty(self):
        assert _clean_string(float("nan")) == ""

    def test_strips_whitespace(self):
        assert _clean_string("  hello  ") == "hello"


class TestMunicipalityNamesMatch:
    def test_exact_match(self):
        assert municipality_names_match("Eisenstadt", "Eisenstadt") is True

    def test_empty_left(self):
        assert municipality_names_match("", "Eisenstadt") is True

    def test_empty_right(self):
        assert municipality_names_match("Eisenstadt", "") is True

    def test_umlaut_normalised(self):
        assert municipality_names_match("Gföhl", "Gfoehl") is True

    def test_mismatch(self):
        assert municipality_names_match("Eisenstadt", "Graz") is False


class TestMunicipalityIdentityMatches:
    def test_gkz_mismatch_returns_false(self):
        base = {"gkz": "10101", "name": "Eisenstadt", "federal_state": "Burgenland"}
        source = {"gkz": "60101", "name": "Graz", "federal_state": "Steiermark"}
        assert municipality_identity_matches(base, source, "test") is False

    def test_state_mismatch_still_returns_true(self):
        base = {"gkz": "10101", "name": "Eisenstadt", "federal_state": "Burgenland"}
        source = {"gkz": "10101", "name": "Eisenstadt", "federal_state": "Wien"}
        assert municipality_identity_matches(base, source, "test") is True

    def test_name_mismatch_still_returns_true(self):
        base = {"gkz": "10101", "name": "Eisenstadt", "federal_state": "Burgenland"}
        source = {"gkz": "10101", "name": "Graz", "federal_state": "Burgenland"}
        assert municipality_identity_matches(base, source, "test") is True

    def test_no_source_gkz_still_matches(self):
        base = {"gkz": "10101", "name": "Eisenstadt", "federal_state": "Burgenland"}
        source = {"name": "Eisenstadt", "federal_state": "Burgenland"}
        assert municipality_identity_matches(base, source, "test") is True


class TestIterMapFeatureProperties:
    def test_feature_collection(self):
        data = {
            "type": "FeatureCollection",
            "features": [
                {"properties": {"iso": "10101", "name": "Eisenstadt"}},
                {"properties": {"iso": "60101", "name": "Graz"}},
            ],
        }
        result = _iter_map_feature_properties(data)
        assert len(result) == 2
        assert result[0]["iso"] == "10101"

    def test_topojson_gemeinden_object(self):
        data = {
            "type": "Topology",
            "objects": {
                "gemeinden": {
                    "geometries": [
                        {"properties": {"iso": "10101", "name": "Eisenstadt"}},
                    ]
                }
            },
        }
        result = _iter_map_feature_properties(data)
        assert len(result) == 1
        assert result[0]["iso"] == "10101"

    def test_topojson_first_object_with_geometries(self):
        data = {
            "type": "Topology",
            "objects": {
                "municipalities": {
                    "geometries": [
                        {"properties": {"iso": "10101", "name": "Eisenstadt"}},
                    ]
                }
            },
        }
        result = _iter_map_feature_properties(data)
        assert len(result) == 1

    def test_empty_map_returns_empty_list(self):
        assert _iter_map_feature_properties({}) == []


class TestLoadMapMunicipalities:
    async def test_loads_topojson(self, tmp_path):
        topo = {
            "type": "Topology",
            "objects": {
                "gemeinden": {
                    "geometries": [
                        {"properties": {"iso": "10101", "name": "Eisenstadt"}},
                        {"properties": {"iso": "60101", "name": "Graz"}},
                    ]
                }
            },
        }
        p = tmp_path / "topo.json"
        p.write_text(json.dumps(topo), encoding="utf-8")
        result = await load_map_municipalities(p)
        assert "10101" in result
        assert result["10101"]["name"] == "Eisenstadt"
        assert result["60101"]["federal_state"] == "Steiermark"

    async def test_loads_geojson(self, tmp_path):
        geojson = {
            "type": "FeatureCollection",
            "features": [
                {"properties": {"iso": "10101", "name": "Eisenstadt"}},
            ],
        }
        p = tmp_path / "geo.json"
        p.write_text(json.dumps(geojson), encoding="utf-8")
        result = await load_map_municipalities(p)
        assert "10101" in result

    async def test_skips_feature_without_gkz_or_name(self, tmp_path):
        topo = {
            "type": "Topology",
            "objects": {
                "gemeinden": {
                    "geometries": [
                        {"properties": {}},
                        {"properties": {"iso": "10101", "name": "Eisenstadt"}},
                    ]
                }
            },
        }
        p = tmp_path / "topo.json"
        p.write_text(json.dumps(topo), encoding="utf-8")
        result = await load_map_municipalities(p)
        assert len(result) == 1

    async def test_warns_on_duplicate_gkz(self, tmp_path):
        topo = {
            "type": "Topology",
            "objects": {
                "gemeinden": {
                    "geometries": [
                        {"properties": {"iso": "10101", "name": "Eisenstadt"}},
                        {"properties": {"iso": "10101", "name": "Eisenstadt Dup"}},
                    ]
                }
            },
        }
        p = tmp_path / "topo.json"
        p.write_text(json.dumps(topo), encoding="utf-8")
        result = await load_map_municipalities(p)
        assert len(result) == 1
        assert result["10101"]["name"] == "Eisenstadt"

    async def test_raises_on_empty_map(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"type": "Topology", "objects": {}}), encoding="utf-8")
        with pytest.raises(ValueError, match="No municipalities found"):
            await load_map_municipalities(p)


class TestLoadOverridesErrors:
    def test_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "overrides.json"
        p.write_text("not valid json", encoding="utf-8")
        assert load_overrides(p) == {}

    def test_whitespace_only_returns_empty(self, tmp_path):
        p = tmp_path / "overrides.json"
        p.write_text("   ", encoding="utf-8")
        assert load_overrides(p) == {}


class TestLoadStaedtebund:
    def test_load_existing(self, tmp_path):
        p = tmp_path / "sb.csv"
        p.write_text(
            "municipality_name,bundesland,gkz,domain\nEisenstadt,Burgenland,10101,eisenstadt.gv.at\n",
            encoding="utf-8",
        )
        df = load_staedtebund(p)
        assert not df.empty
        assert "gkz" in df.columns

    def test_load_nonexistent(self, tmp_path):
        df = load_staedtebund(tmp_path / "nonexistent.csv")
        assert df.empty

    def test_load_empty_csv(self, tmp_path):
        p = tmp_path / "empty.csv"
        p.write_text("", encoding="utf-8")
        df = load_staedtebund(p)
        assert df.empty


class TestMergeOverridesIntoMunicipalities:
    def test_merges_domain(self):
        municipalities = {
            "10101": {
                "gkz": "10101",
                "name": "Eisenstadt",
                "federal_state": "Burgenland",
            }
        }
        result = merge_overrides_into_municipalities(
            municipalities, {"10101": {"domain": "eisenstadt-test.at"}}
        )
        assert municipalities["10101"]["override_domain"] == "eisenstadt-test.at"
        assert "10101" in result

    def test_merges_website(self):
        municipalities = {
            "10101": {
                "gkz": "10101",
                "name": "Eisenstadt",
                "federal_state": "Burgenland",
            }
        }
        merge_overrides_into_municipalities(
            municipalities, {"10101": {"website": "https://www.eisenstadt.at"}}
        )
        assert (
            municipalities["10101"]["override_website"] == "https://www.eisenstadt.at"
        )

    def test_skips_gkz_not_in_map(self):
        municipalities = {}
        result = merge_overrides_into_municipalities(
            municipalities, {"99999": {"domain": "test.at"}}
        )
        assert result == {}

    def test_skips_override_without_gkz(self):
        municipalities = {}
        result = merge_overrides_into_municipalities(
            municipalities, {"": {"domain": "test.at"}}
        )
        assert result == {}


class TestMergeStaedtebundIntoMunicipalities:
    def test_merges_website_sb(self):
        municipalities = {
            "10101": {
                "gkz": "10101",
                "name": "Eisenstadt",
                "federal_state": "Burgenland",
            }
        }
        df = pd.DataFrame(
            [
                {
                    "municipality_name": "Eisenstadt",
                    "bundesland": "Burgenland",
                    "gkz": "10101",
                    "domain": "eisenstadt.gv.at",
                }
            ]
        )
        merge_staedtebund_into_municipalities(municipalities, df)
        assert municipalities["10101"]["website_sb"] == "eisenstadt.gv.at"

    def test_empty_df_is_noop(self):
        municipalities = {"10101": {"gkz": "10101", "name": "Eisenstadt"}}
        merge_staedtebund_into_municipalities(municipalities, pd.DataFrame())
        assert "website_sb" not in municipalities["10101"]

    def test_skips_gkz_not_in_map(self):
        municipalities = {}
        df = pd.DataFrame(
            [
                {
                    "municipality_name": "Graz",
                    "bundesland": "Steiermark",
                    "gkz": "60101",
                    "domain": "graz.at",
                }
            ]
        )
        merge_staedtebund_into_municipalities(municipalities, df)

    def test_skips_row_without_gkz(self):
        municipalities = {"10101": {"gkz": "10101", "name": "Eisenstadt"}}
        df = pd.DataFrame(
            [
                {
                    "municipality_name": "Eisenstadt",
                    "bundesland": "Burgenland",
                    "domain": "x.at",
                }
            ]
        )
        merge_staedtebund_into_municipalities(municipalities, df)
        assert "website_sb" not in municipalities["10101"]


class TestMergeWikidataIntoMunicipalities:
    def test_merges_website_wd(self):
        municipalities = {
            "10101": {
                "gkz": "10101",
                "name": "Eisenstadt",
                "federal_state": "Burgenland",
            }
        }
        wikidata = {
            "10101": {
                "gkz": "10101",
                "name": "Eisenstadt",
                "website": "https://www.eisenstadt.at",
                "federal_state": "Burgenland",
            }
        }
        merge_wikidata_into_municipalities(municipalities, wikidata)
        assert municipalities["10101"]["website_wd"] == "https://www.eisenstadt.at"

    def test_skips_gkz_not_in_map(self):
        municipalities = {}
        merge_wikidata_into_municipalities(
            municipalities,
            {
                "99999": {
                    "gkz": "99999",
                    "name": "Missing",
                    "website": "x.at",
                    "federal_state": "",
                }
            },
        )

    def test_skips_entry_without_gkz(self):
        municipalities = {}
        merge_wikidata_into_municipalities(
            municipalities,
            {"": {"gkz": "", "name": "Bad", "website": "x.at", "federal_state": ""}},
        )


class TestAddSharedDomainFlags:
    def test_flags_shared_domains(self):
        results = {
            "10101": {"domain": "shared.at", "flags": []},
            "10102": {"domain": "shared.at", "flags": []},
            "10103": {"domain": "unique.at", "flags": []},
        }
        _add_shared_domain_flags(results)
        assert "shared_domain" in results["10101"]["flags"]
        assert "shared_domain" in results["10102"]["flags"]
        assert "shared_domain" not in results["10103"]["flags"]

    def test_no_flag_for_unique_domain(self):
        results = {"10101": {"domain": "unique.at", "flags": []}}
        _add_shared_domain_flags(results)
        assert "shared_domain" not in results["10101"]["flags"]

    def test_skips_entries_without_domain(self):
        results = {"10101": {"domain": "", "flags": []}}
        _add_shared_domain_flags(results)
        assert "shared_domain" not in results["10101"]["flags"]

    def test_does_not_duplicate_flag(self):
        results = {
            "10101": {"domain": "shared.at", "flags": ["shared_domain"]},
            "10102": {"domain": "shared.at", "flags": []},
        }
        _add_shared_domain_flags(results)
        assert results["10101"]["flags"].count("shared_domain") == 1


class TestFetchWikidataDeduplication:
    @respx.mock
    async def test_second_entry_with_website_fills_empty(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "Eisenstadt"},
                                "website": {"value": ""},
                            },
                            {
                                "gkz": {"value": "10101"},
                                "itemLabel": {"value": "Eisenstadt"},
                                "website": {"value": "https://www.eisenstadt.at"},
                            },
                        ]
                    }
                },
            )
        )
        result = await fetch_wikidata()
        assert result["10101"]["website"] == "https://www.eisenstadt.at"

    @respx.mock
    async def test_entry_without_gkz_is_skipped(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "itemLabel": {"value": "Unnamed"},
                                "website": {"value": "x.at"},
                            },
                        ]
                    }
                },
            )
        )
        result = await fetch_wikidata()
        assert len(result) == 0


class TestResolveRunWarningBranches:
    @respx.mock
    async def test_staedtebund_without_gkz_column(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(
            "municipality_name,bundesland,domain\nEisenstadt,Burgenland,eisenstadt.gv.at\n",
            encoding="utf-8",
        )
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )
        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value=dict(_MAP_MUNICIPALITIES),
            ),
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            output = tmp_path / "out.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv)
        assert output.exists()

    @respx.mock
    async def test_wikidata_only_gkz_logs_warning(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(EMPTY_MUNICIPALITIES_CSV, encoding="utf-8")
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "gkz": {"value": "99999"},
                                "itemLabel": {"value": "Nonexistent"},
                                "website": {"value": "https://www.nonexistent.at"},
                            }
                        ]
                    }
                },
            )
        )
        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value=dict(_MAP_MUNICIPALITIES),
            ),
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            output = tmp_path / "out.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv)
        assert output.exists()

    @respx.mock
    async def test_override_only_gkz_logs_warning(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(EMPTY_MUNICIPALITIES_CSV, encoding="utf-8")
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )
        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value=dict(_MAP_MUNICIPALITIES),
            ),
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            output = tmp_path / "out.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text(
                '{"99999": {"domain": "nonexistent.at", "name": "Nonexistent", "federal_state": ""}}'
            )
            await run(output, overrides, municipalities_csv)
        assert output.exists()

    @respx.mock
    async def test_staedtebund_only_gkz_logs_warning(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"
        municipalities_csv.write_text(
            "municipality_name,bundesland,gkz,domain\nNonexistent,Burgenland,99999,nonexistent.at\n",
            encoding="utf-8",
        )
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )
        with (
            patch(
                "mail_sovereignty.run_resolve.load_map_municipalities",
                new_callable=AsyncMock,
                return_value=dict(_MAP_MUNICIPALITIES),
            ),
            patch(
                "mail_sovereignty.resolve_domains.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            output = tmp_path / "out.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv)
        assert output.exists()
