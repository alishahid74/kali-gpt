"""Kali-GPT v5.0 - The World's Best AI Pentester"""
from .exploitation.engine import ExploitationEngine, Finding, ValidatedExploit
from .agents.parallel_agents import ParallelVulnHunter, ReconResult
from .analysis.source_analyzer import SourceCodeAnalyzer
from .workflow.orchestrator import PentestOrchestrator, PentestConfig, PentestReport
__version__ = "5.0.0"
__all__ = ["ExploitationEngine", "Finding", "ValidatedExploit", "ParallelVulnHunter",
           "ReconResult", "SourceCodeAnalyzer", "PentestOrchestrator", "PentestConfig", "PentestReport"]
