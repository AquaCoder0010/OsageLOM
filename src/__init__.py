"""
Malware Opcode Dataset Builder
================================
A toolkit for curating malware opcode datasets from MalwareBazaar.
"""

__version__ = '1.0.0'
__author__ = 'Dataset Builder'

from .config_loader import config
from .database import Database
from .malware_downloader import MalwareDownloader
from .opcode_extractor import OpcodeExtractor
from .benign_collector import BenignCollector

__all__ = [
    'config',
    'Database',
    'MalwareDownloader',
    'OpcodeExtractor',
    'BenignCollector'
]
