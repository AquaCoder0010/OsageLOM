# Malware Dataset Curation

Query MalwareBazaar API to collect 64-bit Windows PE malware samples and extract opcode sequences.

## Setup

```bash
source v/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python main.py -i hashes.txt -k YOUR_API_KEY --category rat
```

## Options

- `-i, --input`     Input file with SHA1 hashes (one per line)
- `-k, --api-key`   MalwareBazaar API key
- `-d, --database` SQLite database path (default: malware_samples.db)
- `--delay`        Seconds between API requests (default: 1.0)
- `--category`      Target category: rat, infostealer, dropper, ransomware, wiper, worm, virus, rootkit, all (default: all)
- `--stats`        Show database statistics

## Categories

- `rat` - Remote Access Trojans
- `infostealer` - Information Stealers
- `dropper` - Droppers & Loaders
- `ransomware` - Ransomware
- `wiper` - Wipers
- `worm` - Worms
- `virus` - Viruses
- `rootkit` - Rootkits & Bootkits
- `all` - All categories (default)

## Examples

```bash
# Check current stats
python main.py --stats

# Process all categories
python main.py -i sha1_hashes.txt -k YOUR_API_KEY

# Process specific category (e.g., RATs)
python main.py -i sha1_hashes.txt -k YOUR_API_KEY --category rat

# Faster processing (0.5s delay)
python main.py -i sha1_hashes.txt -k YOUR_API_KEY --delay 0.5 --category ransomware
```

## Output

Samples are stored in SQLite with:
- sha256, sha1, md5
- file_name, file_type, file_arch, file_size
- signature, first_seen, last_seen
- category (rat, infostealer, dropper, ransomware, wiper, worm, virus, rootkit)
- opcode_text (full disassembly using Capstone)
