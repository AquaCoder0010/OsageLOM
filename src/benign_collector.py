import os
import sys
import time
import json
import logging
import hashlib
import requests
from pathlib import Path
from typing import List, Dict, Optional
from tqdm import tqdm

from .config_loader import config
from .database import Database

logger = logging.getLogger(__name__)


class BenignCollector:
    def __init__(self):
        self.db = Database()
        self.benign_dir = Path(config.get('BENIGN_DIR'))
        self.benign_dir.mkdir(parents=True, exist_ok=True)
        
        self.vt_threshold = config.get('VIRUSSHARE_BENIGN_THRESHOLD', 3)
    
    def download_from_virusshare(self, hashes: List[str], api_key: str) -> int:
        downloaded = 0
        
        for sha256 in tqdm(hashes, desc="Downloading benign"):
            try:
                url = f"https://virusshare.com/apiv2/file?hash={sha256}"
                response = requests.get(url, timeout=60)
                
                if response.status_code == 200:
                    file_path = self.benign_dir / f"{sha256[:2]}" / f"{sha256}.exe"
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(file_path, 'wb') as f:
                        f.write(response.content)
                    
                    self.db.add_sample(
                        sha256=sha256,
                        family='benign',
                        source='virusshare',
                        file_path=str(file_path),
                        file_size=file_path.stat().st_size,
                        vt_detections=0
                    )
                    
                    downloaded += 1
                    
            except Exception as e:
                logger.error(f"Error downloading {sha256}: {e}")
                continue
            
            time.sleep(1)
        
        return downloaded
    
    def collect_from_system_files(self, windows_dir: str = None) -> int:
        if windows_dir is None:
            windows_dir = "C:\\Windows\\System32"
        
        collected = 0
        
        system_dirs = [
            windows_dir,
            os.path.join(windows_dir, "SysWOW64"),
            "C:\\Program Files",
            "C:\\Program Files (x86)"
        ]
        
        extensions = ['.exe', '.dll']
        
        for directory in system_dirs:
            if not os.path.exists(directory):
                continue
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext not in extensions:
                        continue
                    
                    file_path = os.path.join(root, file)
                    
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size < 1024 or file_size > 50_000_000:
                            continue
                        
                        with open(file_path, 'rb') as f:
                            sha256 = hashlib.sha256(f.read()).hexdigest()
                        
                        if self.db.sample_exists(sha256):
                            continue
                        
                        dest_path = self.benign_dir / f"{sha256[:2]}" / f"{sha256}{ext}"
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        import shutil
                        shutil.copy2(file_path, dest_path)
                        
                        self.db.add_sample(
                            sha256=sha256,
                            family='benign',
                            source='system_files',
                            file_path=str(dest_path),
                            file_size=file_size,
                            vt_detections=0
                        )
                        
                        collected += 1
                        
                        if collected % 100 == 0:
                            logger.info(f"Collected {collected} benign files")
                        
                    except Exception as e:
                        continue
                
                if collected >= config.benign_samples:
                    break
            
            if collected >= config.benign_samples:
                break
        
        return collected
    
    def query_virustotal_for_clean_files(self, vt_api_key: str, 
                                          sample_hashes: List[str]) -> List[str]:
        clean_hashes = []
        
        headers = {
            'x-apikey': vt_api_key
        }
        
        for sha256 in tqdm(sample_hashes, desc="Checking VT"):
            try:
                url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    if malicious + suspicious < self.vt_threshold:
                        clean_hashes.append(sha256)
                
            except Exception as e:
                logger.error(f"VT check error for {sha256}: {e}")
                continue
            
            time.sleep(0.5)
        
        return clean_hashes


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Collect benign PE files')
    parser.add_argument('--source', type=str, choices=['system', 'virusshare'],
                       default='system', help='Source for benign files')
    parser.add_argument('--windows-dir', type=str, help='Windows directory for system files')
    parser.add_argument('--limit', type=int, default=10000, help='Number of samples')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    collector = BenignCollector()
    
    if args.source == 'system':
        print("Collecting from system files...")
        count = collector.collect_from_system_files(args.windows_dir)
        print(f"Collected {count} benign files from system")
    
    else:
        print("Benign collection from VirusShare requires VT API integration")
        print("Please provide sample hashes to check")


if __name__ == '__main__':
    main()
