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

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(
    r"linkTo_UnCryptMailto\((?:['\"]|%27|%22)([^'\"]+?)(?:['\"]|%27|%22)"
)

# TODO: Review for Austria
SKIP_DOMAINS = {
    "example.com",
    "example.at",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
    # Generic email providers (not municipality-specific)
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "gmx.at",
    "gmx.com",
    "yahoo.com",
    # Shared hosting / CMS / web agencies
    "domain.com",
    # Web framework / analytics
    "google.com",
    "group.calendar.google.com",
    # Generic / unrelated services
    "mail.com",
    "wordpress.org",
    "defiant.com",
    "schedulista.com",
}

# TODO: Review for Austria
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

FEDERAL_STATES = {
    "Burgenland": "burgenland",
    "Kärnten": "kaernten",
    "Niederösterreich": "niederoesterreich",
    "Oberösterreich": "oberoesterreich",
    "Salzburg": "salzburg",
    "Steiermark": "steiermark",
    "Tirol": "tirol",
    "Vorarlberg": "vorarlberg",
    "Wien": "wien",
}

CONCURRENCY_POSTPROCESS = 10
