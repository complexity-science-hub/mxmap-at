"""Tests for the classification pipeline."""

import json
from unittest.mock import patch

import pytest

from mail_sovereignty.pipeline import (
    PROVIDER_OUTPUT_NAMES,
    _apply_resolve_caps,
    _detect_domain_flags,
    _is_reject_all_spf,
    _minify_for_frontend,
    _output_provider,
    _serialize_result,
    run,
)
from mail_sovereignty.models import ClassificationResult, Evidence, Provider, SignalKind
from mail_sovereignty.probes import WEIGHTS


class TestIsRejectAllSpf:
    def test_bare_reject_all(self):
        assert _is_reject_all_spf("v=spf1 -all")

    def test_softfail_all(self):
        assert _is_reject_all_spf("v=spf1 ~all")

    def test_with_include_not_flagged(self):
        assert not _is_reject_all_spf("v=spf1 include:a1.net -all")

    def test_with_ip4_not_flagged(self):
        assert not _is_reject_all_spf("v=spf1 ip4:1.2.3.4 -all")

    def test_with_mx_not_flagged(self):
        assert not _is_reject_all_spf("v=spf1 mx -all")

    def test_empty_string(self):
        assert not _is_reject_all_spf("")


class TestApplyResolveCaps:
    def test_sources_disagree_caps_at_90(self):
        assert _apply_resolve_caps(95.0, ["sources_disagree"]) == 90.0

    def test_single_source_caps_at_80(self):
        assert _apply_resolve_caps(100.0, ["single_source"]) == 80.0

    def test_domain_mismatch_caps_at_70(self):
        assert _apply_resolve_caps(90.0, ["domain_mismatch"]) == 70.0

    def test_lowest_cap_wins(self):
        assert (
            _apply_resolve_caps(100.0, ["sources_disagree", "domain_mismatch"]) == 70.0
        )

    def test_no_flags_no_cap(self):
        assert _apply_resolve_caps(100.0, []) == 100.0

    def test_confidence_already_below_cap_unchanged(self):
        assert _apply_resolve_caps(60.0, ["sources_disagree"]) == 60.0

    def test_unknown_flag_ignored(self):
        assert _apply_resolve_caps(100.0, ["some_other_flag"]) == 100.0

    def test_cap_applied_in_serialize_result(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=1.0,
            evidence=[],
            mx_hosts=["mx.example.com"],
        )
        entry = {
            "gkz": "1",
            "name": "Test",
            "domain": "test.at",
            "flags": ["sources_disagree"],
        }
        out = _serialize_result(entry, result)
        assert out["classification_confidence"] == 90.0

    def test_single_source_cap_in_serialize_result(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=1.0,
            evidence=[],
            mx_hosts=["mx.example.com"],
        )
        entry = {
            "gkz": "1",
            "name": "Test",
            "domain": "test.at",
            "flags": ["single_source"],
        }
        out = _serialize_result(entry, result)
        assert out["classification_confidence"] == 80.0


class TestDetectDomainFlags:
    def test_localhost_mx(self):
        assert _detect_domain_flags(["localhost"], "") == ["invalid_mx"]

    def test_empty_string_mx(self):
        assert _detect_domain_flags([""], "") == ["invalid_mx"]

    def test_mixed_mx_not_flagged(self):
        assert _detect_domain_flags(["localhost", "mx.real.at"], "") == []

    def test_no_mx_not_flagged(self):
        assert _detect_domain_flags([], "") == []

    def test_reject_all_spf(self):
        assert _detect_domain_flags([], "v=spf1 -all") == ["reject_all_spf"]

    def test_both_flags(self):
        assert _detect_domain_flags(["localhost"], "v=spf1 -all") == [
            "invalid_mx",
            "reject_all_spf",
        ]

    def test_clean_domain_no_flags(self):
        assert _detect_domain_flags(["mx.a1.net"], "v=spf1 include:a1.net -all") == []


class TestProviderOutputNames:
    def test_ms365_mapped(self):
        assert PROVIDER_OUTPUT_NAMES["ms365"] == "microsoft"

    def test_output_provider_ms365(self):
        assert _output_provider(Provider.MS365) == "microsoft"

    def test_output_provider_google(self):
        assert _output_provider(Provider.GOOGLE) == "google"

    def test_output_provider_independent(self):
        assert _output_provider(Provider.INDEPENDENT) == "independent"


class TestSerializeResult:
    def test_basic_serialization(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="example.mail.protection.outlook.com",
                ),
                Evidence(
                    kind=SignalKind.SPF,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.SPF],
                    detail="SPF match",
                    raw="v=spf1 include:spf.protection.outlook.com -all",
                ),
            ],
            mx_hosts=["example.mail.protection.outlook.com"],
            spf_raw="v=spf1 include:spf.protection.outlook.com -all",
        )
        entry = {
            "gkz": "351",
            "name": "Eisenstadt",
            "federal_state": "Burgenland",
            "domain": "eisenstadt.at",
        }
        out = _serialize_result(entry, result)

        assert out["gkz"] == "351"
        assert out["provider"] == "microsoft"
        assert out["category"] == "us-cloud"
        assert out["classification_confidence"] == 40.0
        assert out["mx"] == ["example.mail.protection.outlook.com"]
        assert out["spf"] == "v=spf1 include:spf.protection.outlook.com -all"
        assert len(out["classification_signals"]) == 2
        assert out["classification_signals"][0]["kind"] == "mx"
        assert out["classification_signals"][0]["provider"] == "microsoft"

    def test_gateway_included(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            gateway="seppmail",
            mx_hosts=[],
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert out["gateway"] == "seppmail"

    def test_no_gateway_omitted(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.0,
            evidence=[],
            mx_hosts=[],
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert "gateway" not in out

    def test_domain_inactive_localhost_mx(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.92,
            evidence=[],
            mx_hosts=["localhost"],
            spf_raw="",
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert out["provider"] == "unknown"
        assert out["category"] == "unknown"
        assert out["classification_confidence"] == 0.0
        assert out["classification_signals"] == []
        assert out["domain_flags"] == ["domain_inactive"]

    def test_domain_inactive_empty_mx(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.6,
            evidence=[],
            mx_hosts=[""],
            spf_raw="",
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert out["domain_flags"] == ["domain_inactive"]
        assert out["provider"] == "unknown"

    def test_domain_inactive_reject_all_spf(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.9,
            evidence=[],
            mx_hosts=[],
            spf_raw="v=spf1 -all",
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert out["provider"] == "unknown"
        assert out["category"] == "unknown"
        assert out["classification_confidence"] == 0.0
        assert out["domain_flags"] == ["domain_inactive"]

    def test_domain_inactive_both_conditions(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.92,
            evidence=[],
            mx_hosts=["localhost"],
            spf_raw="v=spf1 -all",
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert out["provider"] == "unknown"
        assert out["domain_flags"] == ["domain_inactive"]

    def test_domain_flags_omitted_when_clean(self):
        result = ClassificationResult(
            provider=Provider.A1,
            confidence=0.9,
            evidence=[],
            mx_hosts=["mx.a1.net"],
            spf_raw="v=spf1 include:a1.net -all",
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert "domain_flags" not in out

    def test_resolve_fields_passthrough(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.0,
            evidence=[],
            mx_hosts=[],
        )
        entry = {
            "gkz": "1",
            "name": "Test",
            "domain": "test.at",
            "sources_detail": {"scrape": ["test.at"]},
            "flags": ["gkz_only"],
        }
        out = _serialize_result(entry, result)
        assert out["sources_detail"] == {"scrape": ["test.at"]}
        assert out["resolve_flags"] == ["gkz_only"]

    def test_same_provider_signals_count(self):
        """Signals whose provider matches the winner are marked counts_toward_confidence=True."""
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.9,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="mail.protection.outlook.com",
                ),
                Evidence(
                    kind=SignalKind.SPF,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.SPF],
                    detail="SPF match",
                    raw="",
                ),
            ],
            mx_hosts=["mail.protection.outlook.com"],
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert all(s["counts_toward_confidence"] for s in out["classification_signals"])

    def test_cross_provider_signals_do_not_count(self):
        """ASN/TXT signals from a different provider are marked counts_toward_confidence=False."""
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.9,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="mail.protection.outlook.com",
                ),
                Evidence(
                    kind=SignalKind.ASN,
                    provider=Provider.AWS,
                    weight=WEIGHTS[SignalKind.ASN],
                    detail="ASN 16509 on mx2.example.com",
                    raw="16509",
                ),
                Evidence(
                    kind=SignalKind.TXT_VERIFICATION,
                    provider=Provider.GOOGLE,
                    weight=WEIGHTS[SignalKind.TXT_VERIFICATION],
                    detail="google-site-verification token",
                    raw="",
                ),
            ],
            mx_hosts=["mail.protection.outlook.com"],
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        by_kind = {s["kind"]: s for s in out["classification_signals"]}
        assert by_kind["mx"]["counts_toward_confidence"] is True
        assert by_kind["asn"]["counts_toward_confidence"] is False
        assert by_kind["txt_verification"]["counts_toward_confidence"] is False

    def test_independent_all_signals_count(self):
        """For INDEPENDENT all signals feed _independent_confidence, so all are marked True."""
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.5,
            evidence=[
                Evidence(
                    kind=SignalKind.ASN,
                    provider=Provider.AUSTRIA_ISP,
                    weight=WEIGHTS[SignalKind.ASN],
                    detail="ASN 8447 (A1 Telekom Austria)",
                    raw="8447",
                ),
            ],
            mx_hosts=["mx.custom.at"],
        )
        entry = {"gkz": "1", "name": "Test", "domain": "test.at"}
        out = _serialize_result(entry, result)
        assert all(s["counts_toward_confidence"] for s in out["classification_signals"])


class TestPipelineRun:
    @pytest.fixture
    def domains_json(self, tmp_path):
        data = {
            "municipalities": {
                "351": {
                    "gkz": "351",
                    "name": "Eisenstadt",
                    "federal_state": "Burgenland",
                    "domain": "eisenstadt.at",
                },
                "9999": {
                    "gkz": "9999",
                    "name": "Testingen",
                    "federal_state": "Testland",
                    "domain": "",
                },
            }
        }
        path = tmp_path / "municipality_domains.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    async def test_run_writes_output(self, domains_json, tmp_path):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="eisenstadt-at.mail.protection.outlook.com",
                ),
            ],
            mx_hosts=["eisenstadt-at.mail.protection.outlook.com"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["total"] == 2
        assert "351" in data["municipalities"]
        assert "9999" in data["municipalities"]
        assert data["municipalities"]["351"]["provider"] == "microsoft"
        assert data["municipalities"]["351"]["category"] == "us-cloud"
        assert data["municipalities"]["9999"]["provider"] == "unknown"
        assert data["municipalities"]["9999"]["category"] == "unknown"
        assert data["municipalities"]["9999"]["classification_confidence"] == 0.0

    async def test_run_no_domain_entry(self, domains_json, tmp_path):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            mx_hosts=[],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        data = json.loads(output_path.read_text())
        no_domain = data["municipalities"]["9999"]
        assert no_domain["domain"] == ""
        assert no_domain["mx"] == []

    async def test_run_passthrough_fields(self, tmp_path):
        data = {
            "municipalities": {
                "100": {
                    "gkz": "100",
                    "name": "Town",
                    "federal_state": "Burgenland",
                    "domain": "town.at",
                    "sources_detail": {"scrape": ["town.at"]},
                    "flags": ["gkz_only"],
                },
            }
        }
        path = tmp_path / "domains.json"
        path.write_text(json.dumps(data), encoding="utf-8")

        result = ClassificationResult(
            provider=Provider.GOOGLE,
            confidence=0.4,
            evidence=[],
            mx_hosts=["mx.google.com"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(path, output_path)

        out = json.loads(output_path.read_text())
        entry = out["municipalities"]["100"]
        assert entry["sources_detail"] == {"scrape": ["town.at"]}
        assert entry["resolve_flags"] == ["gkz_only"]

    async def test_run_counts_in_output(self, domains_json, tmp_path):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            mx_hosts=[],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        data = json.loads(output_path.read_text())
        assert "counts" in data
        assert data["counts"]["microsoft"] == 1
        assert data["counts"]["unknown"] == 1

    async def test_run_writes_minified_output(self, domains_json, tmp_path):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="eisenstadt-at.mail.protection.outlook.com",
                ),
            ],
            mx_hosts=["eisenstadt-at.mail.protection.outlook.com"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        mini_path = tmp_path / "data.min.json"
        assert mini_path.exists()

        raw = mini_path.read_text(encoding="utf-8")
        # Compact: no newlines
        assert "\n" not in raw

        mini = json.loads(raw)
        assert "generated" in mini
        assert "municipalities" in mini
        # Top-level fields stripped
        assert "total" not in mini
        assert "counts" not in mini


class TestMinifyForFrontend:
    def _make_full_output(self):
        return {
            "generated": "2026-01-01T00:00:00Z",
            "total": 1,
            "counts": {"microsoft": 1},
            "municipalities": {
                "351": {
                    "gkz": "351",
                    "name": "Eisenstadt",
                    "federal_state": "Burgenland",
                    "domain": "eisenstadt.at",
                    "mx": ["eisenstadt-at.mail.protection.outlook.com"],
                    "spf": "v=spf1 include:spf.protection.outlook.com -all",
                    "provider": "microsoft",
                    "category": "us-cloud",
                    "classification_confidence": 40.0,
                    "classification_signals": [
                        {
                            "kind": "mx",
                            "provider": "microsoft",
                            "weight": 0.4,
                            "detail": "MX match",
                            "counts_toward_confidence": True,
                        },
                    ],
                    "gateway": "seppmail",
                    "sources_detail": {"scrape": ["eisenstadt.at"]},
                    "resolve_flags": ["gkz_only"],
                }
            },
        }

    def test_minify_strips_unused_fields(self):
        full = self._make_full_output()
        mini = _minify_for_frontend(full)

        entry = mini["municipalities"]["351"]
        assert "gkz" not in entry
        assert "sources_detail" not in entry
        assert "resolve_flags" not in entry

        # Signal entries keep kind, detail, counts_toward_confidence; strip provider/weight
        sig = entry["classification_signals"][0]
        assert "provider" not in sig
        assert "weight" not in sig
        assert sig["counts_toward_confidence"] is True

        # Top-level
        assert "total" not in mini
        assert "counts" not in mini

    def test_minify_preserves_frontend_fields(self):
        full = self._make_full_output()
        mini = _minify_for_frontend(full)

        assert mini["generated"] == "2026-01-01T00:00:00Z"
        entry = mini["municipalities"]["351"]
        assert entry["name"] == "Eisenstadt"
        assert entry["domain"] == "eisenstadt.at"
        assert entry["mx"] == ["eisenstadt-at.mail.protection.outlook.com"]
        assert entry["spf"] == "v=spf1 include:spf.protection.outlook.com -all"
        assert entry["provider"] == "microsoft"
        assert entry["category"] == "us-cloud"
        assert entry["classification_confidence"] == 40.0
        assert entry["gateway"] == "seppmail"

        sig = entry["classification_signals"][0]
        assert sig["kind"] == "mx"
        assert sig["detail"] == "MX match"


class TestPipelineLogging:
    @pytest.fixture
    def domains_json(self, tmp_path):
        data = {
            "municipalities": {
                "351": {
                    "gkz": "351",
                    "name": "Eisenstadt",
                    "federal_state": "Burgenland",
                    "domain": "eisenstadt.at",
                },
            }
        }
        path = tmp_path / "municipality_domains.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    async def test_logs_progress_messages(self, domains_json, tmp_path, caplog):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            mx_hosts=[],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many",
            side_effect=fake_classify_many,
        ):
            await run(domains_json, output_path)

        assert any("Classifying" in msg for msg in caplog.messages)
        assert any("Wrote" in msg for msg in caplog.messages)

    async def test_logs_independent_pattern_summary(
        self, domains_json, tmp_path, caplog
    ):
        independent_result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.94,
            evidence=[
                Evidence(
                    kind=SignalKind.TENANT,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.TENANT],
                    detail="MS365 tenant detected",
                    raw="Managed",
                ),
                Evidence(
                    kind=SignalKind.ASN,
                    provider=Provider.AUSTRIA_ISP,
                    weight=WEIGHTS[SignalKind.ASN],
                    detail="ASN is Austrian ISP",
                    raw="AS8447",
                ),
            ],
            mx_hosts=["mail.cnv.at"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, independent_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many",
            side_effect=fake_classify_many,
        ):
            await run(domains_json, output_path)

        summary_msg = next(
            msg for msg in caplog.messages if "Independent pattern summary" in msg
        )
        assert "microsoft:tenant" in summary_msg
        assert "austria_isp:asn" in summary_msg
        assert "asn+tenant" in summary_msg
        assert "mail.cnv.at" in summary_msg
