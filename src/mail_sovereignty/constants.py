import re

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?gkz ?website WHERE {
  ?item wdt:P31 wd:Q667509 .          # instance of: municipality of Austria
  ?item wdt:P964 ?gkz .              # Austrian municipality key (Gemeindekennziffer)
  FILTER NOT EXISTS {                  # exclude dissolved municipalities
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {                  # exclude municipalities with ended P31 statement
    ?item p:P31 ?stmt .
    ?stmt ps:P31 wd:Q667509 .
    ?stmt pq:P582 ?endTime .
    FILTER(?endTime <= NOW())
  }
  FILTER NOT EXISTS {                  # exclude municipalities replaced by a successor
    ?item wdt:P1366 ?successor .
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "de,en" . }
}
ORDER BY xsd:integer(?gkz)
"""

DEFAULT_MAP_TOPOJSON_URL = (
    "https://raw.githubusercontent.com/ginseng666/GeoJSON-TopoJSON-Austria/"
    "refs/heads/master/2021/simplified-99.9/gemeinden_999_topo.json"
)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(
    r"linkTo_UnCryptMailto\((?:['\"]|%27|%22)([^'\"]+?)(?:['\"]|%27|%22)"
)

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

FEDERAL_STATES = {
    "Burgenland": "bgld",
    "Kärnten": "ktn",
    "Niederösterreich": "noe",
    "Oberösterreich": "ooe",
    "Salzburg": "sbg",
    "Steiermark": "stmk",
    "Tirol": "tirol",
    "Vorarlberg": "vbg",
    "Wien": "wien",
}

SUBPAGES = [
    "/kontakt",
    "/contact",
    "/impressum",
    "/kontakt/",
    "/contact/",
    "/impressum/",
    "/de/kontakt",
    "/verwaltung",
    "/administration",
    "/gemeinde",
]


# Substrings that identify clearly non-municipal organisations; a domain
# containing any of these is rejected outright by detect_domain_mismatch.
NON_MUNICIPAL_DOMAIN_PATTERNS: tuple[str, ...] = (
    "ff-",
    "feuerwehr",
    "apotheke",
    "bestattung",
    "musikverein",
    "sportverein",
    "sv-",
    "usv-",
    "hotel",
    "gasthof",
    "restaurant",
    "wirt",
    ".ksn.at",
    "vs-",
)

# Generic Austrian place-name components excluded from the word-level fallback
# in detect_domain_mismatch — they appear in too many unrelated domains.
MISMATCH_WORD_STOPLIST: frozenset[str] = frozenset({
    "bach",
    "berg",
    "dorf",
    "feld",
    "kirche",
    "markt",
    "stein",
    "stadt",
    "wald",
})

SKIP_DOMAINS = {
    # Examples / placeholders
    "example.com",
    "example.at",
    "beispiel.at",

    # Web standards / schemas / framework noise
    "w3.org",
    "schema.org",
    "wordpress.org",

    # Google / analytics / calendar noise
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "group.calendar.google.com",

    # Error monitoring / security / SaaS noise
    "sentry.io",
    "defiant.com",
    "schedulista.com",

    # Generic mail providers / personal mailbox providers
    "gmail.com",
    "gmx.at",
    "gmx.com",
    "gmx.net",
    "gmx.info",
    "hotmail.com",
    "hotmail.de",
    "outlook.com",
    "outlook.de",
    "outlook.at",
    "outlook.co",
    "icloud.com",
    "yahoo.com",
    "yahoo.de",
    "web.de",
    "t-online.de",
    "live.de",
    "mail.com",
    "aon.at",
    "aon.cc",
    "chello.at",
    "utanet.at",

    # Generic telecom / ISP / hosting
    "a1.net",
    "domain.com",

    # Shared app / CMS / municipal-service platforms
    "citiesapps.com",
    "citiesapp.com",  # keep typo defensively
    "gem2go.info",
    "gemeinde24.at",
    "riskommunal.at",
    "oberoesterreich.at",

    # Federal/state/public bodies, not municipal domains
    "polizei.gv.at",
    "dsb.gv.at",
    "usp.gv.at",
    "brz.gv.at",
    "bev.gv.at",
    "sozialministerium.gv.at",
    "gesundheitsministerium.gv.at",
    "volksanw.gv.at",

    # Education / school domains seen as false scrape candidates
    "bildungsserver.com",
    "noeschule.at",
    "musikschule.at",

    # Other recurring unrelated domains from scrape noise
    "dp-wired.de",
    "bzsv.at",
    "appmea.com",
    "cs4web.at",
    "vhs-burgenland.at",
    "tagesmuetter.co.at",
}

SOURCE_PRIORITY = [
    "override",
    "override_scrape",
    "override_redirect",
    "staedtebund",
    "staedtebund_scrape",
    "staedtebund_redirect",
    "source_agreement",
    "wikidata",
    "wikidata_scrape",
    "wikidata_redirect",
    "guess",
    "guess_scrape",
    "guess_redirect",
]

SOURCE_KEYS = [
    source
    for source in SOURCE_PRIORITY
    if source != "source_agreement"
]

CONCURRENCY_POSTPROCESS = 10
