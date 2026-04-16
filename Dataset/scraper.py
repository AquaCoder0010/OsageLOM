"""
Scraper for ran-ds.com/benigns — benign PE files for malware research.

Flow per page:
  1. GET /benigns?page=N  → parse CSRF token, Livewire component snapshot,
                            and the 10 table rows (record DB-id + SHA256).
  2. For each row call the Livewire update endpoint to "mount" the view action,
     which returns a pre-signed S3 download URL (expires ~60 s).
  3. Stream-download the .zip, then extract with password b'infected'.

Run:  python scraper.py [--pages N]          (default: 1  = test mode)
      python scraper.py --pages all           (all ~11 079 pages — takes a while)
"""
import os
import pefile

import argparse
import json
import re
import time
import pyzipper
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# ──────────────────────────────────────────────────────────────────────────────
BASE_URL    = "https://ran-ds.com/benigns"
LW_UPDATE   = "https://ran-ds.com/livewire/update"
ZIP_PASS    = b"infected"
OUTPUT_DIR  = Path(__file__).parent / "class_0"
DELAY_S     = 0.5          # polite delay between Livewire calls on the same page
PAGE_DELAY  = 1.0          # delay between pages
MAX_PAGES   = 11079        # exclusive upper bound given by the site
# ──────────────────────────────────────────────────────────────────────────────



def extract_opcode(file_path: bytes, output_path: str):
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"PE parsing error: {e}")
        return

    # We collect executable sections
    executable_data = bytearray()
    for section in pe.sections:
        # 0x20000000 = IMAGE_SCN_MEM_EXECUTE
        if section.Characteristics & 0x20000000:
            executable_data.extend(section.get_data())
    

    with open(output_path, "wb") as f:
        f.write(executable_data)



def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        )
    })
    return s


# ── Page parsing ──────────────────────────────────────────────────────────────

def fetch_page(session: requests.Session, page: int) -> requests.Response:
    url = BASE_URL if page == 1 else f"{BASE_URL}?page={page}"
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return resp


def parse_csrf(html: str) -> str:
    m = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
    if not m:
        raise ValueError("CSRF token not found in page HTML")
    return m.group(1)


def parse_snapshot(html: str) -> str:
    """Return the raw (HTML-decoded) snapshot JSON string for the list component."""
    m = re.search(
        r'wire:snapshot="(\{[^"]+list-benigns[^"]+\})"', html
    )
    if not m:
        raise ValueError("Livewire snapshot not found for list-benigns component")
    return m.group(1).replace("&quot;", '"')


def parse_records(html: str) -> list[dict]:
    """Return list of {sha256, record_key} dicts for the 10 rows on the page."""
    soup = BeautifulSoup(html, "html.parser")
    rows = soup.find_all("tr", class_="fi-ta-row")
    records = []
    for row in rows:
        cells = row.find_all("td")
        if not cells:
            continue
        sha256 = cells[0].get_text(strip=True)
        # wire:click="mountAction('view', {}, JSON.parse('{"recordKey":"N","table":true}'))"
        # is on a child element of the row
        click_el = row.find(attrs={"wire:click": re.compile(r"mountAction|mountTableAction")})
        if not click_el:
            continue
        # wire:click may encode quotes as \u0022 (unicode escape) or literal "
        click_val = click_el["wire:click"].encode().decode("unicode_escape")
        key_m = re.search(r'"recordKey"\s*:\s*"(\d+)"', click_val)
        if key_m:
            records.append({"sha256": sha256, "key": key_m.group(1)})
    return records


# ── Livewire download-URL resolution ──────────────────────────────────────────

def get_download_url(
    session: requests.Session,
    snapshot_json: str,
    csrf: str,
    record_key: str,
) -> str | None:
    """
    Call the Livewire update endpoint to open the view action for a record,
    which causes the server to render the modal with a signed S3 download link.
    Returns the URL string, or None on failure.
    """
    payload = {
        "components": [
            {
                "calls": [
                    {
                        "path": "",
                        "method": "mountTableAction",
                        "params": ["view", record_key],
                    }
                ],
                "updates": {},
                "snapshot": snapshot_json,
            }
        ]
    }
    headers = {
        "X-Livewire": "true",
        "X-CSRF-TOKEN": csrf,
        "Content-Type": "application/json",
        "Accept": "text/html, application/xhtml+xml",
        "Referer": BASE_URL,
    }

    try:
        r = session.post(LW_UPDATE, json=payload, headers=headers, timeout=30)
        r.raise_for_status()
    except requests.RequestException as exc:
        print(f"    [!] Livewire request failed for key={record_key}: {exc}")
        return None

    # The signed URL is embedded inside the returned HTML partial.
    # Pattern: https://malware-dataset.s3....amazonaws.com/...sha256...zip?...
    raw = json.dumps(r.json())
    matches = re.findall(
        r"https://malware-dataset\.s3\.[^\\\"]+\.zip[^\\\"]*", raw
    )
    if not matches:
        return None
    # HTML-unescape ampersands (&amp; → &)
    return matches[0].replace("&amp;", "&")


# ── Download + extraction ──────────────────────────────────────────────────────

def download_and_extract(
    session: requests.Session,
    url: str,
    sha256: str,
    output_dir: Path,
) -> bool:
    """
    Stream-download the zip, extract with password 'infected', delete the zip.
    Returns True on success.
    """
    zip_path = output_dir / f"{sha256}.zip"

    # Download
    try:
        with session.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(zip_path, "wb") as fh:
                for chunk in r.iter_content(chunk_size=65536):
                    fh.write(chunk)
    except requests.RequestException as exc:
        print(f"    [!] Download failed for {sha256[:16]}…: {exc}")
        zip_path.unlink(missing_ok=True)
        return False

    # Extract (pyzipper supports AES-256 encrypted zips)
    try:
        with pyzipper.AESZipFile(zip_path, "r") as zf:
            zf.extractall(path=output_dir, pwd=ZIP_PASS)
        extracted_path = os.path.join(output_dir, sha256)
        extract_opcode(extracted_path, extracted_path + ".rtc")
    except pyzipper.BadZipFile as exc:
        print(f"    [!] Bad zip for {sha256[:16]}…: {exc}")
        zip_path.unlink(missing_ok=True)
        return False
    except RuntimeError as exc:
        # Wrong password or other extraction error
        print(f"    [!] Extraction error for {sha256[:16]}…: {exc}")
        zip_path.unlink(missing_ok=True)
        return False

    zip_path.unlink(missing_ok=True)
    return True


# ── Per-page orchestration ─────────────────────────────────────────────────────

def process_page(session: requests.Session, page: int, output_dir: Path) -> int:
    """Process one page. Returns number of successfully extracted files."""
    print(f"\n── Page {page} ──────────────────────────────")
    resp = fetch_page(session, page)
    csrf = parse_csrf(resp.text)
    snapshot = parse_snapshot(resp.text)
    records = parse_records(resp.text)

    if not records:
        print("  No records found — page may be beyond the last page.")
        return 0

    print(f"  {len(records)} records on this page.")
    success = 0

    for i, rec in enumerate(records, 1):
        sha256 = rec["sha256"]
        key    = rec["key"]

        # Skip already-extracted files (resume support)
        # The extracted PE file will be named by its sha256 (without extension known upfront)
        # We check for any file starting with the sha256 hash.
        existing = list(output_dir.glob(f"{sha256}*"))
        if existing:
            print(f"  [{i:2d}/10] {sha256[:20]}… — already exists, skipping")
            success += 1
            continue

        print(f"  [{i:2d}/10] {sha256[:20]}…", end=" ", flush=True)

        url = get_download_url(session, snapshot, csrf, key)
        if not url:
            print("no download URL found")
            continue

        ok = download_and_extract(session, url, sha256, output_dir)
        print("OK" if ok else "FAILED")
        if ok:
            success += 1

        time.sleep(DELAY_S)

    return success


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scrape benign PE files from ran-ds.com")
    parser.add_argument(
        "--pages",
        default="1",
        help=(
            "Number of pages to scrape (default: 1 for test mode), "
            "or 'all' to scrape all pages (2 ≤ N ≤ 11078, exclusive)."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(OUTPUT_DIR),
        help="Directory to save extracted PE files.",
    )
    parser.add_argument(
        "--start-page",
        type=int,
        default=1,
        help="Page to start from (default: 1).",
    )
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.pages == "all":
        page_range = range(args.start_page, MAX_PAGES)
    else:
        n = int(args.pages)
        page_range = range(args.start_page, args.start_page + n)

    session = build_session()
    total_ok = 0

    for page in page_range:
        try:
            ok = process_page(session, page, output_dir)
            total_ok += ok
        except Exception as exc:
            print(f"\n[!] Unhandled error on page {page}: {exc}")
        time.sleep(PAGE_DELAY)

    print(f"\nDone. {total_ok} files extracted to {output_dir}/")


if __name__ == "__main__":
    main()
