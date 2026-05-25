#!/usr/bin/env python3
"""
Extraction of Austrian municipality data from the Staedtebund website.
Generates municipalities_gv_at.csv with bundesland, GKZ, name, domain information.
"""

import asyncio
import pdfplumber
import sys
from pathlib import Path
from typing import List
import httpx
import pandas as pd
from bs4 import BeautifulSoup

BUNDESLAND_NAMES = [
    "Burgenland",
    "Niederoesterreich",
    "Oberoesterreich",
    "Kaernten",
    "Salzburg",
    "Tirol",
    "Vorarlberg",
    "Wien",
    "Steiermark"
]

BASE_URL = "https://www.staedtebund.gv.at/organisation/oesterr-staedtebund/gvat-gemeindenamen"

STM_PDF_URL = "https://www.staedtebund.gv.at/fileadmin/USERDATA/Service/Dokumente/gv-at-domains_Steiermark_ab2016-01-01.pdf"

class AustriaMunicipalityExtractor:
    def __init__(self, output_dir: Path = Path("data")):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.client = httpx.AsyncClient(timeout=30.0)

    async def extract_html_tables(self) -> List[pd.DataFrame]:
        """Extract municipality data from HTML tables for all states except Steiermark (PDF only)."""
        dataframes = []
        
        for state in BUNDESLAND_NAMES:
            url = f"{BASE_URL}/{state.lower()}/"
            
            try:
                df = await self._extract_state_table(url)
                dataframes.append(df)
                print(f"Extracted {len(df)} municipalities from {url}")
            except Exception as e:
                print(f"Failed to extract {state}: {e}")
                
        return dataframes

    async def _extract_state_table(self, url: str) -> pd.DataFrame:
        """Extract and parse HTML table from a state page."""
        response = await self.client.get(url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find the main table containing municipality data
        table = soup.find('table')
        if not table:
            raise ValueError(f"No table found on {url}")
            
        # Extract table data
        rows = []
        
        # Extract data rows
        for row in table.find_all('tr')[1:]:  # Skip header row
            cells = row.find_all(['td', 'th'])
            if len(cells) >= 4:  # name, bundesland, gkz, domain
                # Take first 4 columns to match expected order
                row_data = [cell.get_text(strip=True) for cell in cells[:4]]
                rows.append(row_data)
        
        # Convert to DataFrame with correct column order
        df = pd.DataFrame(rows, columns=['municipality_name', 'bundesland', 'gkz', 'domain'])
        
        return df

    async def download_steiermark(self) -> pd.DataFrame:
        """Download and Parse Steiermark municipality data PDF."""
        pdf_file = self.output_dir / "steiermark.pdf"
 
        response = await self.client.get(STM_PDF_URL)
        response.raise_for_status()
 
        with open(pdf_file, 'wb') as f:
            f.write(response.content)
        
        rows = []

        with pdfplumber.open(pdf_file) as pdf:
            for page in pdf.pages:
                text = page.extract_text()

                if not text:
                    continue

                for line in text.split("\n"):

                    parts = line.split()

                    # skip garbage/footer rows
                    if len(parts) < 3:
                        continue

                    # detect valid municipality row
                    if not parts[0].startswith("GGA-"):
                        continue

                    # remove duplicated rows in same line
                    half = len(parts) // 2

                    if parts[:half] == parts[half:]:
                        parts = parts[:half]

                    gkz = parts[0].replace("GGA-", "")  # Remove GGA- prefix
                    domain = parts[-1]
                    municipality = " ".join(parts[1:-1])

                    rows.append({
                        "municipality_name": municipality,
                        "bundesland": "Steiermark",
                        "gkz": gkz,
                        "domain": domain
                    })
                    
        return pd.DataFrame(rows)

    async def merge_all_tables(self, dataframes: List[pd.DataFrame]) -> Path:
        """Merge all DataFrames into final municipalities_gv_at.csv."""
        print("Merging all data...")
        
        if not dataframes:
            raise ValueError("No data to merge")
        
        # Combine all data
        merged_df = pd.concat(dataframes, ignore_index=True)
        
        # Drop entries with empty gkz
        merged_df = merged_df[merged_df['gkz'] != '']
        
        # Drop duplicates and sort
        merged_df = merged_df.drop_duplicates(subset=['gkz'], keep='first')
        merged_df = merged_df.sort_values('gkz')
        
        print(f"Merged dataframe contains {len(merged_df)} municipalities")
        return merged_df

    async def run(self):
        """Complete extraction pipeline."""
        
        # Extract HTML tables
        dataframes = await self.extract_html_tables()
        
        # Handle Steiermark file
        try:
            steiermark_df = await self.download_steiermark()
            print(f"Extracted {len(steiermark_df)} municipalities from Steiermark file")
            dataframes.append(steiermark_df)
        except Exception as e:
            print(f"Steiermark file processing failed: {e}")
        
        # Merge all data
        merged_df = await self.merge_all_tables(dataframes)

        # Save final output
        output_file = self.output_dir / "municipalities_gv_at.csv"
        merged_df.to_csv(output_file, index=False)
        
        print(f"Extraction complete, file saved at: {output_file}")
        return merged_df

    async def close(self):
        """Clean up resources."""
        await self.client.aclose()


async def main():
    extractor = AustriaMunicipalityExtractor()
    
    try:
        merged_df = await extractor.run()
        print(f"Total municipalities: {len(merged_df)}")
    except Exception as e:
        print(f"Extraction failed: {e}")
        sys.exit(1)
    finally:
        await extractor.close()


if __name__ == "__main__":
    
    asyncio.run(main())


    