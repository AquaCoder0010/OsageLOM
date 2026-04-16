import os
import io
import sys
import time
import argparse
import threading
import pandas as pd
import requests
import pyzipper
from typing import List, Dict
import pefile

from family_to_type import FAMILY_TO_TYPE_MAPPING, TYPE_LIST

# ── Constants ─────────────────────────────────────────────────────────────────
API_URL      = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"

# ── Shared state ──────────────────────────────────────────────────────────────
csv_lock = threading.Lock()   # guards all writes to the output CSV


# ── File Helpers uwu  ───────────────────────────────────────────────────────────────
def extract_opcode(file_content: bytes, output_path: str):
    try:
        pe = pefile.PE(data=file_content)
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

# ── API helpers ───────────────────────────────────────────────────────────────

def get_info(session: requests.Session, sha1: str) -> Dict:
    """Return sha256, file_format, and malware family for *sha1*."""
    resp = session.post(API_URL, data={"query": "get_info", "hash": sha1}, timeout=30)
    resp.raise_for_status()
    result = resp.json()
    if result.get("query_status") != "ok":
        raise ValueError(f"MalwareBazaar: {result.get('query_status')}")
    entry = result["data"][0]
    return {
        "sha256":      entry["sha256_hash"],
        "file_format": entry.get("file_type") or entry.get("file_format", ""),
        "family":      entry.get("signature"),
    }


def get_file_content(session: requests.Session, sha256: str) -> bytes:
    """Download the password-protected zip for *sha256* and return raw bytes."""
    resp = session.post(API_URL, data={"query": "get_file", "sha256_hash": sha256}, timeout=120)
    resp.raise_for_status()
    return resp.content


def extract_from_zip(zip_content: bytes) -> bytes:
    """Unzip the AES-encrypted MalwareBazaar archive and return the first file."""
    with pyzipper.AESZipFile(io.BytesIO(zip_content)) as zf:
        zf.setpassword(ZIP_PASSWORD)
        names = zf.namelist()
        if not names:
            raise RuntimeError("ZIP archive is empty.")
        return zf.read(names[0])


# ── Family → type mapping ─────────────────────────────────────────────────────

def map_family_to_type(family: str | None) -> str:
    if not family:
        return "unknown"
    family_lower = family.lower()
    for t_type in TYPE_LIST:
        if family_lower in [f.lower() for f in FAMILY_TO_TYPE_MAPPING.get(t_type, [])]:
            return t_type
    return "unknown"


# ── CSV helpers ───────────────────────────────────────────────────────────────

def flush_to_csv(rows: list, csv_path: str) -> None:
    """Append *rows* to *csv_path* under the shared lock; write header iff the
    file does not yet exist.  Clears *rows* in-place after writing."""
    if not rows:
        return
    df = pd.DataFrame(rows)
    with csv_lock:
        write_header = not os.path.isfile(csv_path)
        df.to_csv(csv_path, mode="a", index=False, header=write_header)
    rows.clear()


# ── Worker ────────────────────────────────────────────────────────────────────

def worker(
    thread_id:       int,
    api_key:         str,
    sha1_chunk:      List[str],
    already_done:    frozenset,
    csv_path:        str,
    output_dir:      str,
    flush_every:     int,
    request_delay:   float,
) -> None:
    """Process one chunk of SHA1 hashes using a dedicated API key / session."""
    session = requests.Session()
    session.headers.update({"Auth-Key": api_key})

    local_rows: list = []
    tag = f"[T{thread_id}]"

    for sha1 in sha1_chunk:
        if sha1 in already_done:
            print(f"{tag} Skip (already done): {sha1[:12]}…")
            continue

        print(f"{tag} Processing: {sha1[:16]}…")

        try:
            # ── 1. Query metadata ──────────────────────────────────────────
            info = get_info(session, sha1)

            print(f"sha1 : {sha1 [:16]} .. file format : {info['file_format']}")
            if info["file_format"].upper() != "EXE":
                print(f"{tag} Skip (not PE, format={info['file_format']}): {sha1[:8]}")
                continue

            # ── 2. Resolve malware type ────────────────────────────────────
            file_type = map_family_to_type(info["family"])

            # ── 3. Download & unpack ───────────────────────────────────────
            zip_bytes  = get_file_content(session, info["sha256"])
            pe_bytes   = extract_from_zip(zip_bytes)

            # Release the zip bytes immediately after extraction
            del zip_bytes

            # ── 4. Extract opcodes ─────────────────────────────────────────
            output_path = os.path.join(output_dir, f"{sha1}.rtc")
            extract_opcode(pe_bytes, output_path)
            del pe_bytes

            # ── 5. Accumulate metadata ─────────────────────────────────────
            local_rows.append({
                "sha1":       sha1,
                "sha256":     info["sha256"],
                "file_type":  file_type,
                "family":     info["family"],
                "output_dir": output_path,
            })

            print(f"{tag} OK: {sha1[:12]}")

        except Exception as exc:
            print(f"{tag} FAIL {sha1[:12]}: {exc}")

        # ── Periodic flush ─────────────────────────────────────────────────
        if len(local_rows) >= flush_every:
            flush_to_csv(local_rows, csv_path)   # clears local_rows in-place

        time.sleep(request_delay)

    # ── Final flush for this thread ────────────────────────────────────────
    flush_to_csv(local_rows, csv_path)
    print(f"{tag} Chunk finished.")


# ── List partitioning ─────────────────────────────────────────────────────────

def split_into_chunks(lst: list, n: int) -> List[list]:
    """Partition *lst* into *n* roughly equal, disjoint sub-lists."""
    size = (len(lst) + n - 1) // n   # ceiling division
    return [lst[i : i + size] for i in range(0, len(lst), size)]



# ── Entry point ───────────────────────────────────────────────────────────────



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-threaded MalwareBazaar PE opcode curator."
    )
    parser.add_argument(
        "--keys", "-k",
        nargs="+", required=True, metavar="API_KEY",
        help="One or more MalwareBazaar API keys.  One thread is created per key.",
    )
    parser.add_argument(
        "--sha1-file", "-s",
        default="full_sha1.txt", metavar="FILE",
        help="Path to the newline-delimited SHA1 hash list (default: full_sha1.txt).",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="class_1", metavar="DIR",
        help="Directory for extracted .rtc opcode files (default: data).",
    )
    parser.add_argument(
        "--csv", "-c",
        default="output.csv", metavar="FILE",
        help="Output CSV path (default: output.csv).  Appended to if it exists.",
    )
    parser.add_argument(
        "--flush-every", "-f",
        type=int, default=10, metavar="N",
        help="Flush accumulated rows to CSV every N successful samples per thread (default: 10).",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float, default=0.5, metavar="SECONDS",
        help="Per-request sleep in seconds to respect rate limits (default: 0.5).",
    )
    args = parser.parse_args()

    # ── Validate / prepare directories ────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)

    # ── Load SHA1 list ─────────────────────────────────────────────────────
    try:
        with open(args.sha1_file, "r") as fh:
            raw_lines = fh.readlines()
    except FileNotFoundError:
        sys.exit(f"Error: SHA1 file not found: {args.sha1_file}")

    sha1_list = [
        line.strip()
        for line in raw_lines
        if line.strip() and not line.startswith("#") and len(line.strip()) == 40
    ]
    print(f"Loaded {len(sha1_list):,} valid SHA1 hashes from {args.sha1_file}.")

    if not sha1_list:
        sys.exit("No valid SHA1 hashes found — nothing to do.")

    # ── Build resume set from existing CSV ────────────────────────────────
    already_done: frozenset = frozenset()
    if os.path.isfile(args.csv):
        try:
            existing_df = pd.read_csv(args.csv, usecols=["sha1"])
            already_done = frozenset(existing_df["sha1"].dropna().astype(str))
            print(f"Resuming: {len(already_done):,} SHA1s already in {args.csv}.")
            del existing_df
        except Exception as exc:
            print(f"Warning: could not read existing CSV for resume ({exc}); starting fresh.")

    # ── Partition work across API keys ────────────────────────────────────
    n_threads = len(args.keys)
    chunks    = split_into_chunks(sha1_list, n_threads)
    del sha1_list   # free the master list; each thread owns its chunk

    print(f"Spawning {n_threads} thread(s), ~{len(chunks[0]):,} SHA1s each.")

    # ── Launch threads ─────────────────────────────────────────────────────
    threads = []
    for i, (api_key, chunk) in enumerate(zip(args.keys, chunks)):
        t = threading.Thread(
            target=worker,
            name=f"worker-{i}",
            kwargs=dict(
                thread_id=i,
                api_key=api_key,
                sha1_chunk=chunk,
                already_done=already_done,
                csv_path=args.csv,
                output_dir=args.output_dir,
                flush_every=args.flush_every,
                request_delay=args.delay,
            ),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n--- All threads finished ---")


if __name__ == "__main__":
    main()
