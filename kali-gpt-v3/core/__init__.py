"""
Core Module - Main Application

The central application that ties all components together.
"""

from .app import (
    KaliGPTApp,
    AppConfig,
    get_app
)

__all__ = [
    "KaliGPTApp",
    "AppConfig",
    "get_app"
]
