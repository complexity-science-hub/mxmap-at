"""Provider DNS fingerprint signatures and pattern matching."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .models import Provider


class ProviderSignature(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    mx_patterns: tuple[str, ...] = ()
    spf_includes: tuple[str, ...] = ()
    dkim_selectors: tuple[str, ...] = ()
    dkim_cname_patterns: tuple[str, ...] = ()
    autodiscover_patterns: tuple[str, ...] = ()
    cname_patterns: tuple[str, ...] = ()
    dmarc_patterns: tuple[str, ...] = ()
    smtp_banner_patterns: tuple[str, ...] = ()
    txt_verification_patterns: tuple[str, ...] = ()
    asns: tuple[int, ...] = ()


SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        provider=Provider.MS365,
        mx_patterns=("mail.protection.outlook.com", "mx.microsoft"),
        spf_includes=("spf.protection.outlook.com",),
        dkim_selectors=("selector1", "selector2"),
        dkim_cname_patterns=("onmicrosoft.com",),
        autodiscover_patterns=("autodiscover.outlook.com",),
        cname_patterns=("mail.protection.outlook.com", "mx.microsoft"),
        dmarc_patterns=("rua.agari.com",),
        smtp_banner_patterns=(
            "microsoft esmtp mail service",
            "protection.outlook.com",
            "mx.microsoft",
        ),
        txt_verification_patterns=("ms=ms",),
        asns=(8075,),
    ),
    ProviderSignature(
        provider=Provider.GOOGLE,
        mx_patterns=("aspmx.l.google.com", "googlemail.com", "smtp.google.com"),
        spf_includes=("_spf.google.com",),
        dkim_selectors=("google", "google2048"),
        dkim_cname_patterns=("domainkey.google.com",),
        autodiscover_patterns=("google.com",),
        cname_patterns=("google.com", "googlemail.com"),
        dmarc_patterns=(),
        smtp_banner_patterns=("mx.google.com", "google esmtp"),
        txt_verification_patterns=("google-site-verification=",),
        asns=(15169, 396982),
    ),
    ProviderSignature(
        provider=Provider.AWS,
        mx_patterns=("amazonaws.com", "awsapps.com"),
        spf_includes=("amazonses.com",),
        dkim_selectors=(),
        dkim_cname_patterns=("dkim.amazonses.com",),
        autodiscover_patterns=("awsapps.com",),
        cname_patterns=("amazonaws.com", "awsapps.com"),
        dmarc_patterns=(),
        smtp_banner_patterns=("amazonaws", "amazonses"),
        txt_verification_patterns=("amazonses",),
        asns=(16509, 14618),
    ),
    # Austria-specific providers
    ProviderSignature(
        provider=Provider.A1,
        spf_includes=("a1.net",),
        mx_patterns=("a1.net",),
        asns=(8447,),
    ),
    ProviderSignature(
        provider=Provider.GEMDAT,
        mx_patterns=(
            "gemdatnoe.at",
            "gemserver.at",
        ),
    ),
    ProviderSignature(
        provider=Provider.RIS,
        mx_patterns=("ris.at",),
    ),
    ProviderSignature(
        provider=Provider.EASYNAME,
        mx_patterns=("easyname.eu",),
    ),
    # TODO: add more providers? extend current ones
]


GATEWAY_KEYWORDS: dict[str, list[str]] = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "cleanmail": ["cleanmail.ch", "cleanmail.safecenter.ch"],
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com", "hornetsecurity.ch"],
    "proofpoint": ["ppe-hosted.com", "pphosted.com"],
    "sophos": ["hydra.sophos.com"],
    "cisco": ["iphmx.com"],
    "mimecast": ["mimecast.com"],
    "spamvor": ["spamvor.com"],
    "abxsec": ["abxsec.com"],
    "messagelabs": ["messagelabs.com"],
}


AUSTRIA_ISP_ASNS: dict[int, str] = {
    8447: "A1 Telekom Austria",
    8412: "T-Mobile Austria",
    25255: "TELE2 AUSTRIA",
    8437: "Hutchison Drei Austria",
    8339: "kabelplus",
    12605: "LIWEST",
    1853: "ACOnet",
    42473: "Anexia Cloud Solutions",
    1764: "Next Layer",
    5403: "APA-IT",
    8245: "Video-Broadcast",
    25447: "JM-DATA",
    40980: "ANEXIA",
}


def match_patterns(value: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Case-insensitive substring match of value against any pattern."""
    if not value or not patterns:
        return False
    lower = value.lower()
    return any(p.lower() in lower for p in patterns)
