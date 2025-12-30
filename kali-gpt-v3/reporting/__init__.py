"""
Reporting Module

Professional penetration testing report generation:
- HTML reports with charts
- Markdown documentation
- JSON for integrations
- PDF export (via HTML)
"""

from .generator import (
    ReportGenerator,
    ReportConfig
)

__all__ = [
    "ReportGenerator",
    "ReportConfig"
]
