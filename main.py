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
        families = {args.family: config.families.get(args.family)}
        alternatives = {args.family: config.family_alternatives.get(args.family, [])}
        target = args.limit or config.samples_per_family
        
        sigs = [families[args.family]] + alternatives[args.family]
        downloader.collect_family_samples(args.family, sigs, target)
    else:
        downloader.collect_all_families()
    
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


def run_full_pipeline(args):
    logger = logging.getLogger(__name__)
    logger.info("="*60)
    logger.info("Running FULL pipeline")
    logger.info("="*60)
    
    logger.info("\n[1/3] Downloading malware samples...")
    download_malware(args)
    
    logger.info("\n[2/3] Extracting opcodes...")
    extract_opcodes(args)
    
    logger.info("\n[3/3] Collecting benign files...")
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
    
    args = parser.parse_args()
    
    if args.stats:
        show_stats(args)
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
