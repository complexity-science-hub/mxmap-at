import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
import stamina

from mail_sovereignty.resolve import (
    _is_ssl_error,
    _process_scrape_response,
    build_urls,
    decrypt_typo3,
    detect_website_mismatch,
    extract_email_domains,
    fetch_wikidata,
    guess_domains,
    load_overrides,
    resolve_municipality_domain,
    run,
    score_domain_sources,
    scrape_email_domains,
    url_to_domain,
)


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
        assert "town.burgenland.at" in domains

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


# ── score_domain_sources() ──────────────────────────────────────────


class TestScoreDomainSources:
    def test_two_sources_agree_high(self):
        sources = {
            "scrape": {"example.at"},
            "wikidata": {"example.at"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Example", "example.at")
        assert result["domain"] == "example.at"
        assert result["confidence"] == "high"
        assert result["source"] == "scrape"

    def test_single_source_medium(self):
        sources = {
            "scrape": {"example.at"},
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Example", "example.at")
        assert result["domain"] == "example.at"
        assert result["confidence"] == "medium"

    def test_guess_only_low(self):
        sources = {
            "scrape": set(),
            "wikidata": set(),
            "guess": {"example.at"},
        }
        result = score_domain_sources(sources, "Example", "example.at")
        assert result["domain"] == "example.at"
        assert result["confidence"] == "low"
        assert "guess_only" in result["flags"]

    def test_no_domain_none(self):
        sources = {
            "scrape": set(),
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Example", "example.at")
        assert result["domain"] == ""
        assert result["confidence"] == "none"

    def test_sources_disagree(self):
        """Flag when scrape found domains but none match the best domain."""
        sources = {
            "scrape": {"email-provider.at"},
            "wikidata": {"website.at"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "website.at")
        assert "sources_disagree" in result["flags"]

    def test_extra_scrape_domains_not_disagreement(self):
        """Extra junk domains in scrape shouldn't trigger disagree when best domain matches."""
        sources = {
            "scrape": {"junk.at", "correct.at"},
            "wikidata": {"correct.at"},
            "guess": {"correct.at", "gemeinde-correct.at"},
        }
        result = score_domain_sources(sources, "Correct", "correct.at")
        assert result["domain"] == "correct.at"
        assert result["confidence"] == "high"
        assert "sources_disagree" not in result["flags"]

    def test_real_disagreement_scrape_vs_wikidata(self):
        """Flag when scrape found domains but none match the wikidata-preferred best."""
        sources = {
            "scrape": {"email-provider.at"},
            "wikidata": {"website.at"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "website.at")
        assert "sources_disagree" in result["flags"]

    def test_guess_extra_domains_no_disagreement(self):
        """Extra guess domains should never trigger disagreement."""
        sources = {
            "scrape": {"correct.at"},
            "wikidata": {"correct.at"},
            "guess": {"correct.at", "gemeinde-correct.at", "correct.zh.at"},
        }
        result = score_domain_sources(sources, "Correct", "correct.at")
        assert result["confidence"] == "high"
        assert "sources_disagree" not in result["flags"]

    def test_website_mismatch_flag(self):
        sources = {
            "scrape": {"example.at"},
            "wikidata": {"example.at"},
            "guess": set(),
        }
        # Name doesn't match the website domain
        result = score_domain_sources(sources, "Totally Different", "unrelated-site.at")
        assert "website_mismatch" in result["flags"]
        assert result["confidence"] == "medium"

    def test_sources_detail_populated(self):
        sources = {
            "scrape": {"a.at", "b.at"},
            "wikidata": {"a.at"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "a.at")
        assert result["sources_detail"]["scrape"] == ["a.at", "b.at"]
        assert result["sources_detail"]["wikidata"] == ["a.at"]
        assert result["sources_detail"]["guess"] == []

    def test_scrape_preferred_over_wikidata(self):
        """When both scrape and wikidata find the same domain, source is scrape."""
        sources = {
            "scrape": {"example.at"},
            "wikidata": {"example.at"},
            "guess": {"example.at"},
        }
        result = score_domain_sources(sources, "Example", "example.at")
        assert result["source"] == "scrape"

    def test_tiebreaker_scrape_preferred(self):
        """When tied on source count, the domain found by scrape wins."""
        sources = {
            "scrape": {"email.at"},
            "wikidata": {"website.at"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "website.at")
        assert result["domain"] == "email.at"

    def test_no_tie_unaffected(self):
        """When one domain clearly wins on source count, tiebreaker doesn't change result."""
        sources = {
            "scrape": {"winner.at"},
            "wikidata": {"winner.at"},
            "guess": {"loser.at"},
        }
        result = score_domain_sources(sources, "Test", "winner.at")
        assert result["domain"] == "winner.at"

    def test_redirect_source_counted(self):
        """Redirect source counts toward agreement."""
        sources = {
            "scrape": {"3908.at"},
            "redirect": {"3908.at"},
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Saas-Balen", "gemeinde-saas-balen.at")
        assert result["domain"] == "3908.at"
        assert result["confidence"] == "high"  # 2 sources agree

    def test_redirect_only_medium_confidence(self):
        """Redirect as sole source gives medium confidence."""
        sources = {
            "scrape": set(),
            "redirect": {"3908.at"},
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Saas-Balen", "gemeinde-saas-balen.at")
        assert result["domain"] == "3908.at"
        assert result["confidence"] == "medium"
        assert result["source"] == "redirect"

    def test_redirect_priority_between_scrape_and_wikidata(self):
        """When redirect and wikidata both find the same domain, source is redirect."""
        sources = {
            "scrape": set(),
            "redirect": {"3908.at"},
            "wikidata": {"3908.at"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Saas-Balen", "gemeinde-saas-balen.at")
        assert result["source"] == "redirect"


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
        assert result == set()
        assert redirect is None

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeinde.at"
            url = httpx.URL("https://www.gemeinde.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde.at")
        assert "gemeinde.at" in result
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
        assert "3908.at" in result
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
        assert "mygemeinde.at" in result
        assert redirect is None


# ── resolve_municipality_domain() ────────────────────────────────────


class TestResolveMunicipalityDomain:
    async def test_override_takes_priority(self):
        m = {
            "gkz": "10101",
            "name": "Eisenstadt",
            "federal_state": "Burgenland",
            "website": "https://www.eisenstadt.gv.at",
        }
        overrides = {"10101": {"website": "https://www.eisenstadt.at", "reason": "test"}}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mail.protection.outlook.com"],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "eisenstadt.at"
        assert result["source"] == "override"
        assert result["confidence"] == "high"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_multi_source_scrape_and_wikidata(self):
        """When scrape and wikidata agree, confidence is high."""
        m = {
            "gkz": "999",
            "name": "Test",
            "federal_state": "",
            "website": "https://www.test.at",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@test.at"
            url = httpx.URL("https://www.test.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "test.at":
                return ["mail.test.at"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "test.at"
        assert result["confidence"] == "high"
        assert "test.at" in result["sources_detail"]["scrape"]
        assert "test.at" in result["sources_detail"]["wikidata"]

    async def test_scrape_only_medium(self):
        """When only scrape finds a domain, confidence is medium."""
        m = {
            "gkz": "999",
            "name": "Test",
            "federal_state": "",
            "website": "https://www.test.at",
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

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "email-test.at"
        assert result["source"] == "scrape"

    async def test_scrape_finds_different_domain_than_website(self):
        """Municipality website has MX, but scraping finds regional mail domain."""

        m = {
            "gkz": "20806",
            "name": "Gallizien",
            "bundesland": "Kärnten",
            "website": "https://www.gallizien.at",
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
            "mail_sovereignty.resolve.lookup_mx",
            side_effect=fake_lookup_mx,
        ):
            result = await resolve_municipality_domain(
                m,
                overrides,
                client,
            )

        # Website domain discovered
        assert "gallizien.at" in result["sources_detail"]["wikidata"]

        # Scraped mail domain discovered
        assert "ktn.gde.at" in result["sources_detail"]["scrape"]

    async def test_none_when_no_domain_found(self):
        m = {"gkz": "999", "name": "Zzz", "federal_state": "", "website": ""}
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == ""
        assert result["source"] == "none"
        assert result["confidence"] == "none"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_guess_only_low_confidence(self):
        """When only guess finds a domain, confidence is low."""
        m = {
            "gkz": "999",
            "name": "Testingen",
            "federal_state": "Wien",
            "website": "",
        }
        overrides = {}
        client = AsyncMock()

        async def fake_lookup_mx(domain):
            if domain == "testingen.at":
                return ["mail.testingen.at"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "testingen.at"
        assert result["source"] == "guess"
        assert result["confidence"] == "low"
        assert "guess_only" in result["flags"]

    """
    async def test_gkz_only_flag(self):
        #Municipalities only in gkz get the gkz_only flag.
        m = {
            "gkz": "999",
            "name": "NewTown",
            "federal_state": "",
            "website": "",
            "gkz_only": True,
        }
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert "gkz_only" in result["flags"]
    """

    async def test_redirect_domain_used_as_source(self):
        """Saas-Balen case: website redirects to postal code domain."""
        m = {
            "gkz": "6289",
            "name": "Saas-Balen",
            "federal_state": "Kanton Wallis",
            "website": "https://www.gemeinde-saas-balen.at",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at gemeinde@3908.at"
            url = httpx.URL("https://www.3908.at/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "3908.at":
                return ["mail.3908.at"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "3908.at"
        assert "3908.at" in result["sources_detail"]["scrape"]
        assert "3908.at" in result["sources_detail"]["redirect"]
        assert result["confidence"] == "high"  # scrape + redirect agree


# ── run() ────────────────────────────────────────────────────────────


# Sample Austrian municipalities CSV
MUNICIPALITIES_CSV_HEADER = "municipality_name,bundesland,gkz,domain"
SAMPLE_MUNICIPALITIES_CSV = f"""{MUNICIPALITIES_CSV_HEADER}
Eisenstadt,Burgenland,10101,eisenstadt.gv.at
Graz,Steiermark,60101,graz.at
Linz,Oberoesterreich,40101,linz.at
"""
EMPTY_MUNICIPALITIES_CSV = MUNICIPALITIES_CSV_HEADER + "\n"


class TestResolveRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"

        municipalities_csv.write_text(
            SAMPLE_MUNICIPALITIES_CSV,
            encoding="utf-8",
        )

        # Mock Wikidata
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

        # Scraping runs first now; mock scrape to return no emails (404)
        respx.get(url__regex=r"https://.*eisenstadt\.at.*").mock(
            return_value=httpx.Response(404)
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.eisenstadt.at"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv, date="01-01-2026")

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 3
        assert "10101" in data["municipalities"]

    @respx.mock
    async def test_adds_override_only_municipalities(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"

        municipalities_csv.write_text(
            EMPTY_MUNICIPALITIES_CSV,
            encoding="utf-8",
        )

        # Mock Wikidata (empty)
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={"results": {"bindings": []}},
            )
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.test.at"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text(
                '{"2056": {"website": "https://www.linz.at", "name": "Linz", "federal_state": "Oberoesterreich", "reason": "Missing from Wikidata"}}'
            )
            await run(output, overrides, municipalities_csv, date="01-01-2026")

        data = json.loads(output.read_text())
        assert "2056" in data["municipalities"]
        assert data["municipalities"]["2056"]["source"] == "override"

    @respx.mock
    async def test_gkz_wikidata_merge(self, tmp_path):
        municipalities_csv = tmp_path / "municipalities.csv"

        municipalities_csv.write_text(
            SAMPLE_MUNICIPALITIES_CSV,
            encoding="utf-8",
        )

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

        respx.get(url__regex=r"https://.*eisenstadt\.at.*").mock(
            return_value=httpx.Response(404)
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.eisenstadt.at"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv, date="01-01-2026")

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

        assert result == set()
        assert redirect is None
        assert any("Scrape" in msg and "refused" in msg for msg in caplog.messages)


# ── Error isolation in resolve run() ─────────────────────────────


class TestResolveRunErrorIsolation:
    @respx.mock
    async def test_skips_failing_municipality(self, tmp_path):
        """One failing resolution should not crash the whole run."""
        # Two municipalities in gkz
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

        with patch(
            "mail_sovereignty.resolve.resolve_municipality_domain",
            side_effect=_flaky_resolve,
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv, date="01-01-2026")

        data = json.loads(output.read_text())
        # Linz succeeded, Graz failed/skipped
        assert "40101" in data["municipalities"]
        assert "60101" not in data["municipalities"]


class TestResolveRunLogging:
    """
    @respx.mock
    async def test_logs_bfs_only_warning(self, tmp_path, caplog):
        #BFS-only municipalities should produce a warning log.
        # BFS has Bern, Wikidata is empty -> Bern is BFS-only
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=httpx.Response(200, text=SAMPLE_BFS_CSV)
        )
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, municipalities_csv, date="01-01-2026")

        assert any(
            "municipalities in gkz but missing from Wikidata" in msg
            for msg in caplog.messages
        )
    """


# ── _process_scrape_response() ────────────────────────────────────────


class TestProcessScrapeResponse:
    def test_non_200_returns_unchanged(self):
        r = httpx.Response(404, request=httpx.Request("GET", "https://example.at"))
        domains, redirect = _process_scrape_response(r, "example.at", set(), None)
        assert domains == set()
        assert redirect is None

    def test_200_extracts_email_and_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@3908.at",
            request=httpx.Request("GET", "https://www.3908.at/"),
        )
        domains, redirect = _process_scrape_response(
            r, "gemeinde-saas-balen.at", set(), None
        )
        assert "3908.at" in domains
        assert redirect == "3908.at"

    def test_200_same_domain_no_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@mygemeinde.at",
            request=httpx.Request("GET", "https://www.mygemeinde.at/"),
        )
        domains, redirect = _process_scrape_response(r, "mygemeinde.at", set(), None)
        assert "mygemeinde.at" in domains
        assert redirect is None

    def test_preserves_existing_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@other.at",
            request=httpx.Request("GET", "https://www.other.at/"),
        )
        domains, redirect = _process_scrape_response(
            r, "example.at", set(), "already.at"
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
            "mail_sovereignty.resolve._fetch_insecure",
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
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(client, "example.at")

        assert domains == set()
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
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("still broken"),
        ):
            domains, redirect = await scrape_email_domains(client, "example.at")

        assert domains == set()
        assert redirect is None
