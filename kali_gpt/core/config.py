"""Configuration Management Module"""

import json
import os
from pathlib import Path
from typing import Dict, Any

class ConfigManager:
    """Manages application configuration and persistence"""

    DEFAULT_CONFIG = {
        "model": "gpt-4o",
        "temperature": 0.7,
        "max_tokens": 2000,
        "require_confirmation": True,
        "auto_copy": True,
        "save_history": True,
        "max_history": 10,
        "default_timeout": 30,
        "custom_profiles": [],
        "metasploit": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 55553,
            "username": "msf",
            "password": ""
        },
        "vulnerability_db": {
            "enabled": True,
            "auto_update": True,
            "update_interval": 86400,  # 24 hours
            "sources": ["nvd", "cve", "exploitdb"]
        },
        "scanner": {
            "enabled": False,
            "default_scanner": "nmap",
            "concurrent_scans": 1
        },
        "collaboration": {
            "enabled": False,
            "server_url": "",
            "api_key": "",
            "share_logs": False
        },
        "plugins": {
            "enabled": True,
            "auto_load": True,
            "plugin_directory": "~/.kali-gpt/plugins"
        },
        "reports": {
            "default_format": "html",
            "output_directory": "~/.kali-gpt/reports",
            "include_screenshots": False,
            "auto_generate": False
        },
        "targets": {
            "save_targets": True,
            "max_targets": 50
        }
    }

    def __init__(self, config_dir: str = "~/.kali-gpt"):
        """Initialize configuration manager"""
        self.config_dir = Path(config_dir).expanduser()
        self.config_file = self.config_dir / "config.json"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_configs(self.DEFAULT_CONFIG, loaded_config)
            except json.JSONDecodeError:
                print("[Warning] Config file corrupted, using defaults")
                return self.DEFAULT_CONFIG.copy()
        else:
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()

    def _merge_configs(self, default: Dict, loaded: Dict) -> Dict:
        """Recursively merge loaded config with defaults"""
        result = default.copy()
        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def save_config(self, config: Dict[str, Any] = None):
        """Save configuration to file"""
        if config is None:
            config = self.config

        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

        self.config = config

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation support"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """Set configuration value with dot notation support"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self.save_config()

    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.save_config()
