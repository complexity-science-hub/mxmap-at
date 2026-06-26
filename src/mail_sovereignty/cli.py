import argparse
import asyncio
from pathlib import Path

from mail_sovereignty.log import setup as setup_logging


def extract_austria_municipalities() -> None:
    from mail_sovereignty.extract_austria_municipalities import main

    parser = argparse.ArgumentParser(description="Extract Austria municipality data")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(main())


def resolve_domains() -> None:
    from mail_sovereignty.run_resolve import run

    parser = argparse.ArgumentParser(description="Resolve municipality email domains")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(
        run(
            Path("data/municipality_domains.json"),
            Path("data/overrides.json"),
            Path("data/municipalities_gv_at.csv"),
        )
    )


def classify_providers() -> None:
    from mail_sovereignty.pipeline import run

    parser = argparse.ArgumentParser(
        description="Classify municipality email providers"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(run(Path("data/municipality_domains.json"), Path("data/data.json")))


def analyze() -> None:
    from mail_sovereignty.analyze import main

    main()
