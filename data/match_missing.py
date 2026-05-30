import json

with open("data.json", encoding="utf-8") as f:
    data = json.load(f)

municipalities = data["municipalities"]

# copy from browser console
missing = [
  {
    "iso": "40835",
    "name": "Peuerbach"
  },
  {
    "iso": "41345",
    "name": "Helfenberg"
  },
  {
    "iso": "41628",
    "name": "Vorderweißenbach"
  },
  {
    "iso": "61060",
    "name": "Sankt Veit in der Südsteiermark"
  },
  {
    "iso": "61120",
    "name": "Trofaiach"
  },
  {
    "iso": "62007",
    "name": "Fohnsdorf"
  },
  {
    "iso": "62008",
    "name": "Gaal"
  },
  {
    "iso": "62014",
    "name": "Kobenz"
  },
  {
    "iso": "62021",
    "name": "Pusterwald"
  },
  {
    "iso": "62026",
    "name": "Sankt Georgen ob Judenburg"
  },
  {
    "iso": "62032",
    "name": "Sankt Peter ob Judenburg"
  },
  {
    "iso": "62034",
    "name": "Seckau"
  },
  {
    "iso": "62036",
    "name": "Unzmarkt-Frauenburg"
  },
  {
    "iso": "62038",
    "name": "Zeltweg"
  },
  {
    "iso": "62105",
    "name": "Breitenau am Hochlantsch"
  },
  {
    "iso": "62115",
    "name": "Krieglach"
  },
  {
    "iso": "62116",
    "name": "Langenwang"
  },
  {
    "iso": "62125",
    "name": "Pernegg an der Mur"
  },
  {
    "iso": "62128",
    "name": "Sankt Lorenzen im Mürztal"
  },
  {
    "iso": "62131",
    "name": "Spital am Semmering"
  },
  {
    "iso": "62132",
    "name": "Stanz im Mürztal"
  },
  {
    "iso": "62135",
    "name": "Turnau"
  },
  {
    "iso": "62202",
    "name": "Bad Blumau"
  },
  {
    "iso": "62206",
    "name": "Burgau"
  },
  {
    "iso": "62209",
    "name": "Ebersdorf"
  },
  {
    "iso": "62211",
    "name": "Friedberg"
  },
  {
    "iso": "62214",
    "name": "Greinbach"
  },
  {
    "iso": "62216",
    "name": "Großsteinbach"
  },
  {
    "iso": "62219",
    "name": "Hartberg"
  },
  {
    "iso": "62220",
    "name": "Hartberg Umgebung"
  },
  {
    "iso": "62226",
    "name": "Lafnitz"
  },
  {
    "iso": "62232",
    "name": "Ottendorf an der Rittschein"
  },
  {
    "iso": "62233",
    "name": "Pinggau"
  },
  {
    "iso": "62235",
    "name": "Pöllauberg"
  },
  {
    "iso": "62242",
    "name": "Sankt Jakob im Walde"
  },
  {
    "iso": "62244",
    "name": "Sankt Johann in der Haide"
  },
  {
    "iso": "62245",
    "name": "Sankt Lorenzen am Wechsel"
  },
  {
    "iso": "62247",
    "name": "Schäffern"
  },
  {
    "iso": "62252",
    "name": "Söchau"
  },
  {
    "iso": "62256",
    "name": "Stubenberg"
  },
  {
    "iso": "62262",
    "name": "Wenigzell"
  },
  {
    "iso": "62311",
    "name": "Edelsbach bei Feldbach"
  },
  {
    "iso": "62314",
    "name": "Eichkögl"
  },
  {
    "iso": "62326",
    "name": "Halbenrain"
  },
  {
    "iso": "62330",
    "name": "Jagerberg"
  },
  {
    "iso": "62332",
    "name": "Kapfenstein"
  },
  {
    "iso": "62335",
    "name": "Klöch"
  },
  {
    "iso": "62343",
    "name": "Mettersdorf am Saßbach"
  },
  {
    "iso": "62368",
    "name": "Tieschen"
  },
  {
    "iso": "62372",
    "name": "Unterlamm"
  },
  {
    "iso": "90101",
    "name": "Wien-Innere Stadt"
  },
  {
    "iso": "90201",
    "name": "Wien-Leopoldstadt"
  },
  {
    "iso": "90301",
    "name": "Wien-Landstraße"
  },
  {
    "iso": "90401",
    "name": "Wien-Wieden"
  },
  {
    "iso": "90501",
    "name": "Wien-Margareten"
  },
  {
    "iso": "90601",
    "name": "Wien-Mariahilf"
  },
  {
    "iso": "90701",
    "name": "Wien-Neubau"
  },
  {
    "iso": "90801",
    "name": "Wien-Josefstadt"
  },
  {
    "iso": "90901",
    "name": "Wien-Alsergrund"
  },
  {
    "iso": "91001",
    "name": "Wien-Favoriten"
  },
  {
    "iso": "91101",
    "name": "Wien-Simmering"
  },
  {
    "iso": "91201",
    "name": "Wien-Meidling"
  },
  {
    "iso": "91301",
    "name": "Wien-Hietzing"
  },
  {
    "iso": "91401",
    "name": "Wien-Penzing"
  },
  {
    "iso": "91501",
    "name": "Wien-Rudolfsheim-Fünfhaus"
  },
  {
    "iso": "91601",
    "name": "Wien-Ottakring"
  },
  {
    "iso": "91701",
    "name": "Wien-Hernals"
  },
  {
    "iso": "91801",
    "name": "Wien-Währing"
  },
  {
    "iso": "91901",
    "name": "Wien-Döbling"
  },
  {
    "iso": "92001",
    "name": "Wien-Brigittenau"
  },
  {
    "iso": "92101",
    "name": "Wien-Floridsdorf"
  },
  {
    "iso": "92201",
    "name": "Wien-Donaustadt"
  },
  {
    "iso": "92301",
    "name": "Wien-Liesing"
  }
]

# Build lookup by normalized name
by_name = {}

for gkz, muni in municipalities.items():
    name = muni.get("name", "").strip().lower()

    by_name[name] = {
        "gkz": gkz,
        "name": muni.get("name"),
        "federal_state": muni.get("federal_state", ""),
        "domain": muni.get("domain"),
        "provider": muni.get("provider"),
    }


matches = {}
unmatched = []

for entry in missing:

    name = entry["name"].strip().lower()
    
    # Vienna districts
    normalized = name.lower()
    if normalized.startswith("wien-") and entry["iso"].startswith("9"):

        matches[entry["iso"]] = {
            "name": name,
            "federal_state": "Wien",
            "website": "https://wien.gv.at",
            "gkz": entry["iso"],
        }

        print(
            f'{entry["iso"]} -> WIEN  '
            f'{name}  '
            f'domain=wien.gv.at'
        )

        continue

    if name in by_name:

        matched = by_name[name]

        matches[entry["iso"]] = {
            "name": entry["name"],
            "federal_state": matched["federal_state"],
            "website": f'https://{matched["domain"]}',
            "gkz": entry["iso"],
        }

        print(
            f'{entry["iso"]} -> {matched["gkz"]}  '
            f'{entry["name"]}  '
            f'state={matched["federal_state"]}  '
            f'domain={matched["domain"]}'
        )

    else:
        unmatched.append(entry)


with open("matched_missing.json", "w", encoding="utf-8") as f:
    json.dump(matches, f, indent=2, ensure_ascii=False)


print(f"\nGenerated matched_missing.json with {len(matches)} entries")

if unmatched:

    print("\n=== UNMATCHED ===\n")
    print(f"\nTotal unmatched: {len(unmatched)}")

    for u in unmatched:
        print(f'{u["iso"]}  {u["name"]}')

   