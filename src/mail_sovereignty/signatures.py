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
        mx_patterns=(
            "mail.protection.outlook.com",
            "mx.microsoft",
            "mail.protection.outlook.de",
        ),
        spf_includes=("spf.protection.outlook.com", "spf.protection.outlook.de"),
        dkim_selectors=("selector1", "selector2"),
        dkim_cname_patterns=("onmicrosoft.com",),
        autodiscover_patterns=("autodiscover.outlook.com",),
        cname_patterns=(
            "mail.protection.outlook.com",
            "mx.microsoft",
            "mail.protection.outlook.de",
        ),
        dmarc_patterns=("rua.agari.com",),
        smtp_banner_patterns=(
            "microsoft esmtp mail service",
            "protection.outlook.com",
            "mx.microsoft",
            "protection.outlook.de",
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
        mx_patterns=("a1.net", "aon.at", "aon.cc"),
        smtp_banner_patterns=("a1",),
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
    ProviderSignature(
        provider=Provider.POST,
        mx_patterns=("mxs.post.at",),
        spf_includes=("mxs.post.at", "spf-pp.post.at"),
    ),
    ProviderSignature(
        provider=Provider.ASP_BGLD,
        mx_patterns=("smtp.asp-bgld.at",),
    ),
    ProviderSignature(
        provider=Provider.W4YMAIL,
        spf_includes=("spf.w4ymail.at",),
    ),
    ProviderSignature(
        provider=Provider.BON,
        mx_patterns=("mx1.bon.at", "mx2.bon.at"),
        spf_includes=("spf.bon.at",),
    ),
    ProviderSignature(
        provider=Provider.WIEN,
        mx_patterns=("mx01.wien.gv.at", "mx02.wien.gv.at"),
    ),
    ProviderSignature(
        provider=Provider.CNV,
        mx_patterns=("mail.cnv.at",),
        spf_includes=("_spf.cnv.at",),
    ),
    ProviderSignature(
        provider=Provider.SALZBURG,
        mx_patterns=("smtp.salzburg.at",),
        spf_includes=("_spf.salzburg.at",),
    ),
    ProviderSignature(
        provider=Provider.WVNET,
        mx_patterns=("smtpgate.wvnet.at", "esg.wvnet.eu"),
        spf_includes=("_netblocks.wvnet.eu", "_mxblocks.wvnet.eu"),
    ),
    ProviderSignature(
        provider=Provider.MAGENTA,
        mx_patterns=("mx.mymagenta.business",),
        spf_includes=("_spf.mymagenta.business",),
    ),
    ProviderSignature(
        provider=Provider.NET4YOU,
        mx_patterns=("mx1.net4you.net", "mx2.net4you.net"),
        spf_includes=("net4you.net",),
    ),
    ProviderSignature(
        provider=Provider.KAS,
        mx_patterns=("kasserver.com",),
        spf_includes=("spf.kasserver.com",),
    ),
    ProviderSignature(
        provider=Provider.MYMAILWALL,
        mx_patterns=("mymailwall.com", "mymailwall.at", "scanlab01.mymailwall.at"),
        spf_includes=("mymailwall.com",),
    ),
    ProviderSignature(
        provider=Provider.SECURE_SHIELD,
        mx_patterns=("secure-shield.at",),
        spf_includes=("secure-shield.at",),
    ),
    ProviderSignature(
        provider=Provider.KABELPLUS,
        mx_patterns=("kabelplus.at",),
        asns=(8339,),
    ),
    ProviderSignature(
        provider=Provider.CABLELINK,
        mx_patterns=("cablelink.at", "mx-in.cablelink.at"),
        spf_includes=("_spf.cablelink.at",),
    ),
    ProviderSignature(
        provider=Provider.NODE4WEB,
        mx_patterns=("node4web.at",),
        spf_includes=("spf.node4web.at",),
    ),
    ProviderSignature(
        provider=Provider.HIWAY,
        mx_patterns=("hiway.at",),
        spf_includes=("hiway.at",),
    ),
    ProviderSignature(
        provider=Provider.MYNET,
        mx_patterns=("mynet.at",),
        spf_includes=("_spf.mynet.at",),
    ),
    ProviderSignature(
        provider=Provider.LGBS,
        mx_patterns=("lgbs.at",),
        spf_includes=("lgbs.at",),
    ),
    ProviderSignature(
        provider=Provider.FLASHNET,
        mx_patterns=("flashnet.at",),
        spf_includes=("flashnet.at",),
    ),
    ProviderSignature(
        provider=Provider.STYRION,
        mx_patterns=("styrion.net",),
        spf_includes=("_spf.styrion.net",),
    ),
    ProviderSignature(
        provider=Provider.VIENNAWEB,
        mx_patterns=("viennaweb.at",),
        spf_includes=("spf.viennaweb.at",),
    ),
    ProviderSignature(
        provider=Provider.RIEPERT,
        mx_patterns=("riepert.at",),
    ),
    ProviderSignature(
        provider=Provider.HALLO_CLOUD,
        mx_patterns=("hallo.cloud",),
        spf_includes=("_spf.r29.hallo.cloud",),
    ),
    ProviderSignature(
        provider=Provider.AGENTURSERVER,
        mx_patterns=("agenturserver.de",),
        spf_includes=("agenturserver.de",),
    ),
    ProviderSignature(
        provider=Provider.IONOS,
        mx_patterns=("ionos.de",),
        spf_includes=("_spf-eu.ionos.com", "_spf.ionos.com"),
    ),
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
