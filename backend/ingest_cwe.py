import pandas as pd
import requests
import zipfile
import io
import json
import os

CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
PROCESSED_PATH = "data/processed/cwe_kb.json"

def fetch_and_parse_cwe():
    print("Downloading CWE database...")
    response = requests.get(CWE_URL)
    
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        csv_filename = z.namelist()[0]
        with z.open(csv_filename) as f:
            lines = [line.decode('utf-8', errors='ignore') for line in f.readlines()]

    # Bulletproof header detection
    header_idx = 0
    for i, line in enumerate(lines):
        if "CWE-ID" in line and "Name" in line:
            header_idx = i
            break

    print(f"Dynamically found header at line {header_idx + 1}")
    
    csv_data = io.StringIO(''.join(lines[header_idx:]))
    df = pd.read_csv(csv_data)

    kb_entries = []
    for _, row in df.iterrows():
        try:
            row.index = row.index.str.strip()
            
            cwe_id = str(row.get('CWE-ID', '')).strip()
            name = str(row.get('Name', '')).strip()
            desc = str(row.get('Description', '')).strip()
            ext_desc = str(row.get('Extended Description', '')).strip()
            
            # Clean up pandas missing values ('nan')
            if desc.lower() == 'nan': desc = ''
            if ext_desc.lower() == 'nan': ext_desc = ''
            
            # Skip invalid rows
            if not cwe_id or cwe_id.lower() == 'nan':
                continue
                
            entry = {
                "source": "CWE",
                "id": f"CWE-{cwe_id}",
                "name": name,
                "description": desc,
                "extended_description": ext_desc
            }
            entry["search_text"] = f"{entry['name']} {entry['description']} {entry['extended_description']}".strip()
            kb_entries.append(entry)
        except Exception:
            continue

    os.makedirs(os.path.dirname(PROCESSED_PATH), exist_ok=True)
    with open(PROCESSED_PATH, "w", encoding="utf-8") as out_file:
        json.dump(kb_entries, out_file, indent=2, ensure_ascii=False)

    print(f"Successfully processed {len(kb_entries)} CWE entries.")
    print(f"Saved to {PROCESSED_PATH}")
    
    if kb_entries:
        print("\nSample Entry:")
        print(json.dumps(kb_entries[0], indent=2))
    else:
        print("\nError: 0 entries found.")

if __name__ == "__main__":
    fetch_and_parse_cwe()
