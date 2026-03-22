import io
import pefile
import pandas as pd
from capstone import *
import pyzipper
import time
import requests
from typing import List, Dict

from family_to_type import FAMILY_TO_TYPE_MAPPING, TYPE_LIST

# --- Configuration ---
API_URL = "https://mb-api.abuse.ch/api/v1/"
API_KEY = "ce04109870b5c936962a6973e6015ca930d14ffc112803c6"
ZIP_PASSWORD = b"infected"
SHA1_TXT = "full_sha1.txt"
OUTPUT_DIR = "data"

session = requests.Session()
session.headers.update({"Auth-Key": API_KEY})

# --- Functions with Exception Handling ---

def get_info(sha1: str) -> Dict:
    data = {"query": "get_info", "hash": sha1}
    response = session.post(API_URL, data=data, timeout=30)
    response.raise_for_status()
    
    result = response.json()
    if result.get("query_status") != "ok":
        raise ValueError(f"MalwareBazaar API returned status: {result.get('query_status')}")
    
    entry = result['data'][0]
    return {
        "sha256": entry['sha256_hash'],
        "file_format": entry['file_format'],
        "family": entry.get('signature')
    }

def get_file_content(sha256: str) -> bytes:
    data = {"query": "get_file", "sha256_hash": sha256}
    response = session.post(API_URL, data=data, timeout=60)
    response.raise_for_status()
    # MalwareBazaar returns the zip file directly in the content
    return response.content

def extract_from_zip(zip_content: bytes) -> bytes:
    try:
        with pyzipper.AESZipFile(io.BytesIO(zip_content)) as zf:
            zf.setpassword(ZIP_PASSWORD)
            names = zf.namelist()
            if not names:
                raise RuntimeError("ZIP file is empty.")
            return zf.read(names[0])
    except Exception as e:
        raise RuntimeError(f"Extraction failed: {str(e)}")

def extract_opcode(file_content: bytes, output_path: str):
    try:
        pe = pefile.PE(data=file_content)
    except Exception as e:
        raise ValueError(f"PE parsing error: {e}")

    if pe.OPTIONAL_HEADER.Magic == 0x10b:
        arch_mode = CS_MODE_32
    elif pe.OPTIONAL_HEADER.Magic == 0x20b:
        arch_mode = CS_MODE_64
    else:
        raise TypeError("Unknown PE architecture.")

    # We collect executable sections
    executable_data = bytearray()
    for section in pe.sections:
        # 0x20000000 = IMAGE_SCN_MEM_EXECUTE
        if section.Characteristics & 0x20000000:
            executable_data.extend(section.get_data())
    
    if not executable_data:
        raise ValueError("No executable sections found.")

    with open(output_path, "wb") as f:
        f.write(executable_data)

# --- Main Logic ---

results_data = []

try:
    with open(SHA1_TXT, 'r') as file:
        lines = file.readlines()
except FileNotFoundError:
    print(f"Error: {SHA1_TXT} not found.")
    lines = []

LIMIT = 100_000
processed_count = 0
for line_num, line in enumerate(lines, 1):
    if processed_count >  LIMIT:
        break

    sha1 = line.strip()         
    if not sha1 or sha1.startswith("#") or len(sha1) != 40:
        continue
    
    print(f"[{line_num}] Processing: {sha1[:16]}...")
    
    try:
        # 1. Get Info
        info = get_info(sha1)
        if info['file_format'] != 'PE': 
            print(f"Skipping: {sha1[:8]} is not a PE file.")
            continue
        
        # 2. Map Family to Type
        file_type = "unknown"
        family_name = info['family']
        if family_name:
            family_lower = family_name.lower()
            for t_type in TYPE_LIST:
                if family_lower in [f.lower() for f in FAMILY_TO_TYPE_MAPPING.get(t_type, [])]:
                    file_type = t_type
                    break

        # 3. Download and Extract
        zip_payload = get_file_content(info['sha256'])
        extracted_binary = extract_from_zip(zip_payload)

        # 4. Save Executable Sections
        output_name = f"{OUTPUT_DIR}/{sha1}.rtc"
        extract_opcode(extracted_binary, output_name)

        # 5. Store Metadata for DataFrame
        results_data.append({
            "sha1": sha1,
            "file_type": file_type,
            "family": family_name,
            "output_dir": output_name
        })

        if processed_count % 10 == 0: 
            df = pd.DataFrame(results_data)
            df.to_csv("output.csv", index=False)

        print(f"Successfully processed {sha1[:8]}")
        processed_count += 1
        

            
    except Exception as e:
        print(f"[-] Failed to process {sha1[:8]}: {e}")
        
    time.sleep(0.1)

# --- Final DataFrame ---
df = pd.DataFrame(results_data)
df.to_csv("output.csv", index=False)

print("\n--- Processing Complete ---")
print(df)