"""Pydantic models for the mail sovereignty classifier."""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class Provider(str, enum.Enum):
    # Global cloud providers
    MS365        = "ms365"
    GOOGLE       = "google"
    AWS          = "aws"
    # Austrian regional / state providers
    A1           = "a1"
    GEMDAT       = "gemdat"
    RIS          = "ris"
    EASYNAME     = "easyname"
    AUSTRIA_ISP  = "austria_isp"
    POST         = "post"
    ASP_BGLD     = "asp_bgld"
    W4YMAIL      = "w4ymail"
    BON          = "bon"
    WIEN         = "wien"
    CNV          = "cnv"
    SALZBURG     = "salzburg"
    WVNET        = "wvnet"
    MAGENTA      = "magenta"
    NET4YOU      = "net4you"
    MYMAILWALL   = "mymailwall"    # mymailwall.com / mymailwall.at — Austrian mail gateway
    SECURE_SHIELD = "secure_shield" # secure-shield.at — Austrian anti-spam / mail service
    KABELPLUS    = "kabelplus"     # kabelplus.at — Austrian cable ISP
    CABLELINK    = "cablelink"     # cablelink.at — Austrian cable ISP
    NODE4WEB     = "node4web"      # node4web.at — Austrian web/mail host
    HIWAY        = "hiway"         # hiway.at — Austrian ISP (Styria)
    MYNET        = "mynet"         # mynet.at — Tyrolean ISP
    LGBS         = "lgbs"          # lgbs.at — Lower Austrian government IT service
    FLASHNET     = "flashnet"      # flashnet.at — Austrian ISP (Upper Austria)
    STYRION      = "styrion"       # styrion.net — Austrian hosting
    VIENNAWEB    = "viennaweb"     # viennaweb.at — Austrian hosting
    RIEPERT      = "riepert"       # riepert.at — Austrian managed mail (Upper Austria)
    # European
    HALLO_CLOUD  = "hallo_cloud"   # hallo.cloud — Dutch cloud mail service
    KAS          = "kas"           # kasserver.com — German host, widely used in AT municipalities
    AGENTURSERVER = "agenturserver" # agenturserver.de — German host used by some AT municipalities
    IONOS        = "ionos"         # ionos.de — German/European host (IONOS / 1&1)
    # Self-hosted Austrian infrastructure (positive Austrian signal, no named provider match)
    INDEPENDENT  = "independent"
    # Cannot determine provider but domain is known to exist
    UNRESOLVED   = "unresolved"
    # No usable signals at all (no MX, dead domain, ind_none rule)
    UNKNOWN      = "unknown"


class SignalKind(str, enum.Enum):
    MX = "mx"
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    AUTODISCOVER = "autodiscover"
    CNAME_CHAIN = "cname_chain"
    SMTP = "smtp"
    TENANT = "tenant"
    ASN = "asn"
    TXT_VERIFICATION = "txt_verification"
    SPF_IP = "spf_ip"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: SignalKind
    provider: Provider
    weight: float = Field(ge=0.0, le=1.0)
    detail: str
    raw: str = ""


class ClassificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = []
    gateway: str | None = None
    mx_hosts: list[str] = []
    spf_raw: str = ""
