import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from mail_sovereignty.cli import (
    analyze,
    classify_providers,
    extract_austria_municipalities,
    resolve_domains,
)
from mail_sovereignty.log import setup as setup_logging


class TestSetupLogging:
    def test_default_suppresses_noisy_loggers(self):
        setup_logging(verbose=False)
        for name in ("httpx", "httpcore", "dns", "stamina"):
            assert logging.getLogger(name).level == logging.WARNING

    def test_verbose_suppresses_noisy_loggers(self):
        setup_logging(verbose=True)
        for name in ("httpx", "httpcore", "dns", "stamina"):
            assert logging.getLogger(name).level == logging.WARNING


class TestCli:
    def test_resolve_domains(self):
        with (
            patch(
                "mail_sovereignty.run_resolve.run", new_callable=AsyncMock
            ) as mock_run,
            patch("sys.argv", ["resolve-domains"]),
        ):
            resolve_domains()
            mock_run.assert_called_once_with(
                Path("data/municipality_domains.json"),
                Path("data/overrides.json"),
                Path("data/municipalities_gv_at.csv"),
            )

    """ # date was used for bfs api -> not used anymore
    def test_resolve_domains_with_date(self):
        with (
            patch("mail_sovereignty.resolve.run", new_callable=AsyncMock) as mock_run,
            patch("sys.argv", ["resolve-domains", "--date", "15-03-2026"]),
        ):
            resolve_domains()
            mock_run.assert_called_once_with(
                Path("municipality_domains.json"),
                Path("overrides.json"),
                date="15-03-2026",
            )
    """

    def test_resolve_domains_verbose(self):
        with (
            patch("mail_sovereignty.run_resolve.run", new_callable=AsyncMock),
            patch("sys.argv", ["resolve-domains", "-v"]),
        ):
            resolve_domains()

    def test_classify_providers(self):
        with (
            patch("mail_sovereignty.pipeline.run", new_callable=AsyncMock) as mock_run,
            patch("sys.argv", ["classify-providers"]),
        ):
            classify_providers()
            mock_run.assert_called_once_with(
                Path("data/municipality_domains.json"), Path("data/data.json")
            )

    def test_classify_providers_verbose(self):
        with (
            patch("mail_sovereignty.pipeline.run", new_callable=AsyncMock),
            patch("sys.argv", ["classify-providers", "--verbose"]),
        ):
            classify_providers()

    def test_extract_austria_municipalities(self):
        with (
            patch("sys.argv", ["extract-austria-municipalities"]),
            patch(
                "mail_sovereignty.extract_austria_municipalities.main",
                return_value=None,
            ),
            patch("asyncio.run"),
        ):
            extract_austria_municipalities()

    def test_analyze(self):
        with patch(
            "mail_sovereignty.analyze.main", new_callable=MagicMock
        ) as mock_main:
            analyze()
            mock_main.assert_called_once()
