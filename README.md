# Malware Opcode Dataset Builder

A toolkit for curating malware opcode datasets from MalwareBazaar through the extraction of metadata from the EMBER2024 Dataset. 

## Overview

- **9 Categories**: RATs, Infostealers, Droppers, Ransomware, Wipers, Worms, Viruses, Rootkits, Benign
- **Extraction**: Raw opcode bytes from PE `.text` section using Capstone

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Edit config.yaml with your API keys
nano config/config.yaml

# Step 1: Import EMBER2024 hashes (gets hashes + family labels)
python main.py --import-ember --split challenge --file-type PE

# Step 2: Download PE files from MalwareBazaar using imported hashes
python main.py --download

# Step 3: Extract opcodes
python main.py --extract

# View stats
python main.py --stats
```

## EMBER2024 Import

The `--import-ember` command downloads EMBER2024 metadata (hashes + labels) and imports them to the database. It maps EMBER family names to malware types (RAT, ransomware, etc.).

```bash
# Import challenge set (6K evasive samples)
python main.py --import-ember --split challenge --file-type PE

# Import train set (millions of samples)
python main.py --import-ember --split train --file-type PE

# Import test set
python main.py --import-ember --split test --file-type PE

# Import all PE types
python main.py --import-ember --split all --file-type PE
```

## Configuration

Edit `config/config.yaml`:

```yaml
MALWAREBAZAAR_API_KEY: "your-api-key"
TELEGRAM_BOT_TOKEN: "your-bot-token"
TELEGRAM_CHAT_ID: "your-chat-id"
SAMPLES_PER_FAMILY: 10000
```

## Usage

| Command | Description |
|---------|-------------|
| `python main.py --import-ember` | Import EMBER2024 hashes to database |
| `python main.py --download` | Download all malware families |
| `python main.py --download --family rat` | Download specific family |
| `python main.py --extract` | Extract opcodes from pending samples |
| `python main.py --collect-benign` | Collect benign PE files |
| `python main.py --stats` | Show dataset statistics |
| `python main.py --telegram` | Enable Telegram notifications |

## Project Structure

```
dataset-curation/
├── config/
│   └── config.yaml           # Configuration
├── src/
│   ├── config_loader.py      # Config manager
│   ├── database.py           # SQLite database
│   ├── malware_downloader.py # MalwareBazaar API client
│   ├── opcode_extractor.py  # PE + Capstone extraction
│   ├── benign_collector.py  # Benign file collection
│   ├── ember_downloader.py  # EMBER2024 hash importer
│   └── telegram_notifier.py # Telegram bot notifications
├── data/
│   ├── malware/             # Downloaded PE files
│   ├── benign/              # Benign PE files
│   ├── ember/               # EMBER2024 metadata
│   ├── opcodes/             # Extracted opcode JSONs
│   └── dataset.db           # SQLite database
├── main.py                  # Main orchestration script
└── requirements.txt         # Dependencies
```

## Database Schema

```sql
samples (
    id, sha256, family, source, file_path, arch,
    file_size, first_seen, last_seen, vt_detections,
    is_packed, extraction_status, opcode_path
)

extraction_logs (
    id, sample_id, extraction_time, opcode_count,
    text_section_size, error_message
)

collection_stats (
    id, family, target_count, current_count, status
)
```

## Requirements

- Python 3.10+
- MalwareBazaar API key (free at https://auth.abuse.ch/)
- Telegram bot for notifications (optional)

## License

Licensed under MIT.
