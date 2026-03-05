import os
import yaml
from pathlib import Path
from typing import Any, Dict

class Config:
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self.load()
    
    def load(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "config",
                "config.yaml"
            )
        
        with open(config_path, 'r') as f:
            self._config = yaml.safe_load(f)
        self._setup_directories()
    
    def _setup_directories(self):
        dirs = [
            self.get('MALWARE_DIR'),
            self.get('BENIGN_DIR'),
            self.get('OPCODES_DIR'),
            self.get('LOG_DIR')
        ]
        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)
    
    def get(self, key: str, default: Any = None) -> Any:
        if self._config is None:
            self.load()

        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value
    
    @property
    def families(self) -> Dict[str, str]:
        return self.get('FAMILIES', {})
    
    @property
    def family_alternatives(self) -> Dict[str, list]:
        return self.get('FAMILY_ALTERNATIVES', {})
    
    @property
    def samples_per_family(self) -> int:
        return self.get('SAMPLES_PER_FAMILY', 10000)
    
    @property
    def benign_samples(self) -> int:
        return self.get('BENIGN_SAMPLES', 10000)

config = Config()
