#!/usr/bin/env python3
import argparse
import os
import sys
from database import MalwareDatabase
from malware_collector import MalwareCollector


def main():
    parser = argparse.ArgumentParser(
        description="Malware Dataset Curation Tool - Query Ma`lwareBazaar for PE64 samples"
    )
    parser.add_argument(
        "-i", "--input",
        help="Input file containing SHA1 hashes (one per line)"
    )
    parser.add_argument(
        "-k", "--api-key",
        help="MalwareBazaar API key"
    )
    parser.add_argument(
        "-d", "--database",
        default="malware_samples.db",
        help="SQLite database path (default: malware_samples.db)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between API requests in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--category",
        type=str,
        default="all",
        help="Target category: rat, infostealer, dropper, ransomware, wiper, worm, virus, rootkit, all (default: all)"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show database statistics"
    )
    
    args = parser.parse_args()
    
    db = MalwareDatabase(args.database)
    
    if args.stats:
        stats = db.get_stats()
        print("=" * 50)
        print("Database Statistics")
        print("=" * 50)
        print(f"Total samples in DB:    {stats['total_samples']}")
        print(f"Total hashes processed: {stats['total_processed']}")
        print(f"  - Downloaded:        {stats['downloaded']}")
        print(f"  - Skipped (not PE64): {stats['skipped_not_pe64']}")
        print(f"  - Not found:         {stats['not_found']}")
        print("=" * 50)
        sys.exit(0)
    
    if not args.input or not args.api_key:
        print("Error: -i/--input and -k/--api-key are required")
        parser.print_help()
        sys.exit(1)
    
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)
    
    print("=" * 50)
    print("Malware Dataset Curation Tool")
    print("=" * 50)
    print(f"Input file:  {args.input}")
    print(f"Database:    {args.database}")
    print(f"Delay:       {args.delay}s")
    print(f"Category:    {args.category}")
    print("=" * 50)
    
    collector = MalwareCollector(args.api_key, db, args.delay, args.category)
    results = collector.process_file(args.input)
    
    print("=" * 50)
    print("Processing Complete")
    print("=" * 50)
    print(f"Downloaded: {results['downloaded']}")
    print(f"Skipped:     {results['skipped']}")
    
    stats = db.get_stats()
    print(f"\nTotal in database: {stats['total_samples']}")
    print("=" * 50)


if __name__ == "__main__":
    main()
