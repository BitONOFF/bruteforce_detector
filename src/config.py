import yaml
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        self.config_path = Path(Path(__file__).parent.parent / "config" / "settings.yaml")
        logger.info(f"Loading config from: {self.config_path}")
        if not self.config_path.exists():
            logger.error(f"Config file not found: {self.config_path}")
            self.config = self._create_default_config()
        else:
            self.config = self._load_config()
        self._validate_config()
        logger.debug(f"Config loaded: {self.config}")

    def _create_default_config(self):
        logger.warning("Creating default config")
        return {
            'app': {
                'name': 'Bruteforce Detector',
                'version': '1.0.0',
                'log_level': 'INFO'
            },
            'logs': {
                'ssh_log_path': '../logs/ssh_logs.csv',
                'ftp_log_path': '../logs/ftp_logs.csv',
                'batch_size': 100,
                'check_interval': 2
            },
            'detection': {
                'thresholds': {
                    'max_failed_attempts': 10,
                    'time_window_minutes': 5,
                    'min_unique_usernames': 3,
                    'max_attempts_per_second': 5
                }
            },
            'alerting': {
                'enabled': True,
                'channels': ['console'],
                'cooldown_minutes': 10
            }
        }

    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                logger.info(f"Config successfully loaded from {self.config_path}")
                return config if config else {}
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._create_default_config()

    def _validate_config(self):
        required_sections = ['logs', 'detection', 'alerting']
        for section in required_sections:
            if section not in self.config:
                logger.warning(f"Missing section in config: {section}")

    def get(self, key: str, default=None):
        try:
            keys = key.split('.')
            value = self.config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value if value is not None else default
        except Exception as e:
            logger.debug(f"Error getting key {key}: {e}")
            return default

    def save(self):
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)

    def __getitem__(self, key):
        return self.get(key)

config = Config()