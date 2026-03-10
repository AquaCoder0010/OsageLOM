#!/usr/bin/env python3
"""
Malware Opcode Dataset Builder
================================
Main orchestration script for building a curated malware opcode dataset.

Usage:
    python main.py --download           # Download malware samples
    python main.py --extract            # Extract opcodes from samples
    python main.py --collect-benign     # Collect benign files
    python main.py --full               # Run full pipeline
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.config_loader import config
from src.database import Database
from src.malware_downloader import MalwareDownloader
from src.opcode_extractor import OpcodeExtractor
from src.benign_collector import BenignCollector
from src.ember_downloader import EmberDownloader


def setup_logging():
    log_dir = Path(config.get('LOG_DIR'))
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / f"dataset_builder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)


def download_malware(args):
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("Starting malware download phase")
    logger.info("="*60)
    
    if not config.get('MALWAREBAZAAR_API_KEY'):
        logger.error("Please set MALWAREBAZAAR_API_KEY in config.yaml")
        return
    
    downloader = MalwareDownloader(telegram_enabled=args.telegram)
    
    if args.family:
        target = args.limit or config.samples_per_family
        count = downloader.download_from_database(family=args.family, limit=target)
        logger.info(f"Downloaded {count} samples for {args.family}")
    else:
        count = downloader.download_all(target_per_type=args.limit)
        logger.info(f"Downloaded {count} samples total")
    
    stats = downloader.db.get_family_counts()
    logger.info("\nMalware Collection Summary:")
    for family, count in stats.items():
        logger.info(f"  {family}: {count}")
    
    total = downloader.db.get_total_samples()
    logger.info(f"Total malware samples: {total}")


def extract_opcodes(args):
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("Starting opcode extraction phase")
    logger.info("="*60)
    
    extractor = OpcodeExtractor()
    
    if args.family:
        db = Database()
        samples = db.get_samples_by_family(args.family, limit=args.limit)
        
        logger.info(f"Processing {len(samples)} samples for family: {args.family}")
        
        for sample in samples:
            if sample['extraction_status'] != 'pending':
                continue
            
            extractor.extract_and_save(sample['id'], sample['file_path'])
    else:
        extractor.extract_all_pending()
    
    db = Database()
    pending = db.get_pending_extractions(limit=1)
    logger.info(f"\nExtraction complete. Remaining pending: {len(pending)}")


def collect_benign(args):
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("Starting benign file collection")
    logger.info("="*60)
    
    collector = BenignCollector()
    
    if args.source == 'system':
        count = collector.collect_from_system_files(args.windows_dir)
        logger.info(f"Collected {count} benign files from system")
    else:
        logger.info("VirusShare benign collection requires VT API integration")


def import_ember(args):
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("Importing EMBER2024 dataset hashes")
    logger.info("="*60)
    
    downloader = EmberDownloader(data_dir=args.ember_dir)
    count = downloader.run(split=args.split, file_type=args.file_type)
    
    logger.info(f"EMBER import complete: {count} samples added to database")


def run_full_pipeline(args):
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("Running FULL pipeline")
    logger.info("="*60)
    
    logger.info("\n[1/4] Importing EMBER2024 hashes...")
    import_ember(args)
    
    logger.info("\n[2/4] Downloading malware samples...")
    download_malware(args)
    
    logger.info("\n[3/4] Extracting opcodes...")
    extract_opcodes(args)
    
    logger.info("\n[4/4] Collecting benign files...")
    collect_benign(args)
    
    logger.info("\n" + "="*60)
    logger.info("Pipeline complete!")
    logger.info("="*60)
    
    db = Database()
    stats = db.get_family_counts()
    
    logger.info("\nFinal Dataset Statistics:")
    logger.info(f"  Total samples: {db.get_total_samples()}")
    for family, count in stats.items():
        logger.info(f"  {family}: {count}")


def show_stats(args):
    db = Database()
    
    print("\n" + "="*50)
    print("DATASET STATISTICS")
    print("="*50)
    
    print(f"\nTotal samples: {db.get_total_samples()}")
    
    print("\nBy Family:")
    family_counts = db.get_family_counts()
    for family, count in sorted(family_counts.items()):
        print(f"  {family}: {count}")
    
    print("\nCollection Status:")
    collection_stats = db.get_collection_stats()
    for stat in collection_stats:
        print(f"  {stat['family']}: {stat['current_count']}/{stat['target_count']} ({stat['status']})")


def main():
    parser = argparse.ArgumentParser(
        description='Malware Opcode Dataset Builder',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --import-ember                 Import EMBER2024 hashes
  %(prog)s --import-ember --split challenge --file-type PE
  %(prog)s --download                    Download all malware families
  %(prog)s --download --family rat        Download only RAT family
  %(prog)s --extract                      Extract opcodes from pending samples
  %(prog)s --extract --family ransomware # Extract from specific family
  %(prog)s --collect-benign              Collect benign files from system
  %(prog)s --full                         Run complete pipeline
  %(prog)s --stats                        Show dataset statistics
        """
    )
    
    parser.add_argument('--download', action='store_true',
                       help='Download malware samples')
    parser.add_argument('--extract', action='store_true',
                       help='Extract opcodes from samples')
    parser.add_argument('--collect-benign', action='store_true',
                       help='Collect benign PE files')
    parser.add_argument('--full', action='store_true',
                       help='Run full pipeline')
    parser.add_argument('--stats', action='store_true',
                       help='Show dataset statistics')
    
    parser.add_argument('--family', type=str,
                       help='Specific family to process')
    parser.add_argument('--source', type=str, choices=['system', 'virusshare'],
                       default='system', help='Benign file source')
    parser.add_argument('--limit', type=int,
                       help='Limit number of samples')
    parser.add_argument('--windows-dir', type=str,
                       help='Windows directory for system files')
    parser.add_argument('--telegram', action='store_true',
                       help='Enable Telegram progress notifications')
    parser.add_argument('--import-ember', action='store_true',
                       help='Import EMBER2024 hashes to database')
    parser.add_argument('--split', type=str, default='challenge',
                       choices=['all', 'train', 'test', 'challenge'],
                       help='EMBER dataset split to import')
    parser.add_argument('--file-type', type=str, default='PE',
                       choices=['all', 'PE', 'Win32', 'Win64', 'Dot_Net'],
                       help='EMBER file type to import')
    parser.add_argument('--ember-dir', type=str,
                       help='EMBER data directory')
    
    args = parser.parse_args()
    
    if args.stats:
        show_stats(args)
        return
    
    if args.import_ember:
        setup_logging()
        import_ember(args)
        return
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    if args.full:
        run_full_pipeline(args)
    elif args.download:
        download_malware(args)
    elif args.extract:
        extract_opcodes(args)
    elif args.collect_benign:
        collect_benign(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
