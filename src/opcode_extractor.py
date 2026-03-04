import os
import sys
import time
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

import pefile
import capstone

from .config_loader import config
from .database import Database

logger = logging.getLogger(__name__)


class OpcodeExtractor:
    def __init__(self):
        self.db = Database()
        self.opcodes_dir = Path(config.get('OPCODES_DIR'))
        self.opcodes_dir.mkdir(parents=True, exist_ok=True)
        
        self.extraction_mode = config.get('EXTRACTION_MODE', 'raw_bytes')
        
        self.cs_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs_32.detail = False
        
        self.cs_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.cs_64.detail = False
    
    def _detect_architecture(self, pe: pefile.PE) -> str:
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return 'x86'
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return 'x64'
        return 'unknown'
    
    def _get_text_section(self, pe: pefile.PE) -> Optional[Tuple[bytes, int]]:
        for section in pe.sections:
            if section.Name.decode('utf-8', errors='ignore').strip('\x00') == '.text':
                return section.get_data(), section.Misc_VirtualSize
        return None
    
    def _extract_raw_bytes(self, pe: pefile.PE) -> bytes:
        text_section = self._get_text_section(pe)
        if text_section:
            return text_section[0]
        return b''
    
    def _extract_mnemonics(self, pe: pefile.PE, arch: str) -> List[str]:
        text_section = self._get_text_section(pe)
        if not text_section:
            return []
        
        code_bytes, size = text_section
        
        cs = self.cs_32 if arch == 'x86' else self.cs_64
        
        mnemonics = []
        for instruction in cs.disasm(code_bytes, 0x1000):
            mnemonics.append(instruction.mnemonic)
        
        return mnemonics
    
    def _extract_full_disasm(self, pe: pefile.PE, arch: str) -> List[str]:
        text_section = self._get_text_section(pe)
        if not text_section:
            return []
        
        code_bytes, size = text_section
        
        cs = self.cs_32 if arch == 'x86' else self.cs_64
        
        disasm = []
        for instruction in cs.disasm(code_bytes, 0x1000):
            disasm.append(f"{instruction.mnemonic} {instruction.op_str}")
        
        return disasm
    
    def extract(self, file_path: str) -> Optional[Dict]:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        start_time = time.time()
        
        try:
            pe = pefile.PE(file_path, fast_load=False)
            
            arch = self._detect_architecture(pe)
            
            if self.extraction_mode == 'raw_bytes':
                opcode_data = self._extract_raw_bytes(pe)
                opcode_list = None
            elif self.extraction_mode == 'mnemonics':
                opcode_list = self._extract_mnemonics(pe, arch)
                opcode_data = None
            elif self.extraction_mode == 'full_disasm':
                opcode_list = self._extract_full_disasm(pe, arch)
                opcode_data = None
            else:
                logger.error(f"Unknown extraction mode: {self.extraction_mode}")
                return None
            
            result = {
                'arch': arch,
                'extraction_time': time.time() - start_time,
                'text_section_size': len(opcode_data) if opcode_data else 0,
                'opcode_count': len(opcode_list) if opcode_list else 0
            }
            
            if opcode_data:
                result['raw_bytes'] = opcode_data.hex()
            
            if opcode_list:
                result['mnemonics'] = opcode_list
            
            return result
            
        except pefile.PEFormatError as e:
            logger.error(f"PE format error for {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error extracting opcodes from {file_path}: {e}")
            return None
    
    def extract_and_save(self, sample_id: int, file_path: str) -> bool:
        result = self.extract(file_path)
        
        if not result:
            self.db.update_extraction_status(
                sample_id, 'failed', 
                error='Extraction failed'
            )
            return False
        
        sha256 = os.path.basename(os.path.dirname(file_path))
        if '.' in os.path.basename(file_path):
            sha256 = os.path.basename(file_path).split('.')[0]
        
        opcode_file = self.opcodes_dir / f"{sha256[:8]}.json"
        
        try:
            with open(opcode_file, 'w') as f:
                json.dump({
                    'sample_id': sample_id,
                    'file_path': file_path,
                    'arch': result['arch'],
                    'extraction_time': result['extraction_time'],
                    'text_section_size': result['text_section_size'],
                    'raw_bytes': result.get('raw_bytes'),
                    'mnemonics': result.get('mnemonics'),
                    'opcode_count': result.get('opcode_count', 0),
                    'extracted_at': datetime.now().isoformat()
                }, f, indent=2)
            
            self.db.update_extraction_status(
                sample_id, 'completed', 
                opcode_path=str(opcode_file)
            )
            
            self.db.log_extraction(
                sample_id,
                result['extraction_time'],
                result.get('opcode_count', 0),
                result['text_section_size']
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving opcode data: {e}")
            self.db.update_extraction_status(
                sample_id, 'failed',
                error=str(e)
            )
            return False
    
    def process_pending(self, limit: int = 100) -> int:
        pending = self.db.get_pending_extractions(limit)
        
        if not pending:
            logger.info("No pending samples to process")
            return 0
        
        logger.info(f"Processing {len(pending)} pending samples")
        
        success_count = 0
        for sample in pending:
            sample_id = sample['id']
            file_path = sample['file_path']
            
            if not file_path or not os.path.exists(file_path):
                logger.warning(f"File not found for sample {sample_id}: {file_path}")
                self.db.update_extraction_status(
                    sample_id, 'failed',
                    error='File not found'
                )
                continue
            
            if self.extract_and_save(sample_id, file_path):
                success_count += 1
        
        logger.info(f"Successfully processed {success_count}/{len(pending)} samples")
        return success_count
    
    def extract_all_pending(self):
        total = 0
        while True:
            processed = self.process_pending(limit=50)
            if processed == 0:
                break
            total += processed
            logger.info(f"Total processed so far: {total}")
        
        return total


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Extract opcodes from PE files')
    parser.add_argument('--file', type=str, help='Single file to extract')
    parser.add_argument('--family', type=str, help='Process samples of specific family')
    parser.add_argument('--limit', type=int, default=100, help='Batch limit')
    parser.add_argument('--all', action='store_true', help='Process all pending')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    extractor = OpcodeExtractor()
    
    if args.file:
        result = extractor.extract(args.file)
        if result:
            print(json.dumps(result, indent=2, default=str))
    
    elif args.all:
        extractor.extract_all_pending()
    
    elif args.family:
        db = Database()
        samples = db.get_samples_by_family(args.family, limit=args.limit)
        
        for sample in samples:
            if sample['extraction_status'] == 'pending':
                extractor.extract_and_save(sample['id'], sample['file_path'])
    
    else:
        print("Processing pending extractions...")
        extractor.extract_all_pending()
    
    print("\nExtraction complete!")


if __name__ == '__main__':
    main()
