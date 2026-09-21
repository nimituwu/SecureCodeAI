import requests
import zipfile
import io
import json
import os

OWASP_ZIP_URL = "https://github.com/OWASP/CheatSheetSeries/archive/refs/heads/master.zip"
PROCESSED_PATH = "data/processed/owasp_kb.json"

def fetch_and_parse_owasp():
    print("Downloading OWASP Cheat Sheet Series from GitHub...")
    response = requests.get(OWASP_ZIP_URL)
    
    kb_entries = []
    
    # Extract the zip file in memory
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        for filepath in z.namelist():
            # We only care about the actual markdown cheat sheets
            if "cheatsheets/" in filepath and filepath.endswith(".md"):
                # Clean up the filename to use as the title
                filename = os.path.basename(filepath)
                name = filename.replace(".md", "").replace("_", " ")
                
                if name.lower() == "index":  # Skip the index file
                    continue
                
                # Read the markdown content
                with z.open(filepath) as f:
                    content = f.read().decode('utf-8', errors='ignore')
                
                entry = {
                    "source": "OWASP",
                    "id": f"OWASP-{name.replace(' ', '-')}",
                    "name": f"OWASP {name}",
                    "description": f"Official OWASP Cheat Sheet for {name}",
                    "extended_description": content[:5000], # Cap at 5000 chars to keep JSON lightweight
                    "search_text": f"{name} {content}".strip()
                }
                kb_entries.append(entry)

    os.makedirs(os.path.dirname(PROCESSED_PATH), exist_ok=True)
    with open(PROCESSED_PATH, "w", encoding="utf-8") as out_file:
        json.dump(kb_entries, out_file, indent=2, ensure_ascii=False)

    print(f"Successfully processed {len(kb_entries)} OWASP Cheat Sheets.")
    print(f"Saved to {PROCESSED_PATH}")
    
    # Print a truncated sample to verify
    if kb_entries:
        print("\nSample Entry (Truncated):")
        sample = kb_entries[0].copy()
        sample["extended_description"] = sample["extended_description"][:100] + "..."
        sample["search_text"] = sample["search_text"][:100] + "..."
        print(json.dumps(sample, indent=2))

if __name__ == "__main__":
    fetch_and_parse_owasp()
