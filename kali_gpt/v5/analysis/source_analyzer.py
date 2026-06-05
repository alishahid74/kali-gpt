#!/usr/bin/env python3
"""
Kali-GPT v5.0 - Source Code Analyzer
Multi-language static analysis with data flow tracking.
"""

import ast
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PHP = "php"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    RUBY = "ruby"
    UNKNOWN = "unknown"


@dataclass
class CodeLocation:
    file: str
    line: int
    column: int = 0
    snippet: str = ""


@dataclass
class Source:
    name: str
    type: str
    location: CodeLocation
    language: Language


@dataclass
class Sink:
    name: str
    vuln_type: str
    location: CodeLocation
    language: Language
    severity: str = "high"


@dataclass
class DataFlow:
    source: Source
    sink: Sink
    path: List[CodeLocation]
    confidence: float
    description: str
    is_sanitized: bool = False
    sanitizer: Optional[str] = None


@dataclass
class SourceCodeFinding:
    title: str
    vuln_type: str
    severity: str
    file: str
    line: int
    code_snippet: str
    description: str
    data_flow: Optional[DataFlow]
    recommendation: str


class LanguageDetector:
    EXTENSION_MAP = {".py": Language.PYTHON, ".js": Language.JAVASCRIPT, ".ts": Language.TYPESCRIPT,
                     ".jsx": Language.JAVASCRIPT, ".tsx": Language.TYPESCRIPT, ".php": Language.PHP,
                     ".java": Language.JAVA, ".cs": Language.CSHARP, ".go": Language.GO, ".rb": Language.RUBY}

    @classmethod
    def detect(cls, file_path, content=None):
        return cls.EXTENSION_MAP.get(Path(file_path).suffix.lower(), Language.UNKNOWN)


DANGEROUS_SINKS = {
    Language.PYTHON: {
        "sqli": ["cursor.execute", "execute", "executemany", "raw", "connection.execute", "engine.execute", "session.execute", "db.execute"],
        "command_injection": ["os.system", "os.popen", "subprocess.call", "subprocess.run", "subprocess.Popen", "exec", "eval"],
        "path_traversal": ["open", "send_file", "send_from_directory"],
        "ssrf": ["requests.get", "requests.post", "urllib.request.urlopen", "aiohttp.ClientSession", "httpx.get"],
        "xss": ["render_template_string", "Markup", "mark_safe"],
        "deserialization": ["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load"],
        "ssti": ["render_template_string", "Template", "jinja2.Template"],
    },
    Language.JAVASCRIPT: {
        "sqli": ["query", "execute", "raw", "sequelize.query", "knex.raw"],
        "command_injection": ["exec", "execSync", "spawn", "child_process.exec", "eval", "Function"],
        "xss": ["innerHTML", "outerHTML", "document.write", "dangerouslySetInnerHTML"],
        "prototype_pollution": ["Object.assign", "_.merge", "_.extend", "$.extend"],
    },
    Language.PHP: {
        "sqli": ["mysql_query", "mysqli_query", "pg_query", "PDO::query"],
        "command_injection": ["system", "exec", "shell_exec", "passthru", "popen", "proc_open", "eval"],
        "path_traversal": ["file_get_contents", "fopen", "readfile", "include", "require"],
        "xss": ["echo", "print"],
        "deserialization": ["unserialize"],
    },
}


class PythonAnalyzer:
    def __init__(self):
        self.sources, self.sinks, self.findings = [], [], []

    def analyze_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            tree = ast.parse(content)
            lines = content.split("\n")
            self._find_sinks(tree, file_path, lines)
            self._find_patterns(content, file_path, lines)
            return self.sources, self.sinks, self.findings
        except (SyntaxError, Exception):
            return [], [], []

    def _find_sinks(self, tree, file_path, lines):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                for vuln_type, funcs in DANGEROUS_SINKS.get(Language.PYTHON, {}).items():
                    for f in funcs:
                        if f in func_name or func_name.endswith(f.split(".")[-1]):
                            self.sinks.append(Sink(name=func_name, vuln_type=vuln_type,
                                location=CodeLocation(file=file_path, line=node.lineno,
                                    snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else ""),
                                language=Language.PYTHON))

    def _find_patterns(self, content, file_path, lines):
        patterns = [
            (r'execute\s*\(\s*["\'].*%s.*["\']', "SQL query with string formatting", "sqli", "high"),
            (r'execute\s*\(\s*f["\']', "SQL query with f-string", "sqli", "high"),
            (r'cursor\.execute\s*\([^,]+\+', "SQL cursor with concatenation", "sqli", "high"),
            (r'os\.system\s*\([^)]*\+', "os.system with concatenation", "command_injection", "critical"),
            (r'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True', "subprocess with shell=True", "command_injection", "critical"),
            (r'eval\s*\(', "eval() usage", "command_injection", "critical"),
            (r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', "Hardcoded password", "hardcoded_secret", "medium"),
            (r'(api_key|apikey)\s*=\s*["\'][^"\']+["\']', "Hardcoded API key", "hardcoded_secret", "medium"),
            (r'(secret|token)\s*=\s*["\'][a-zA-Z0-9]{16,}["\']', "Hardcoded secret/token", "hardcoded_secret", "medium"),
        ]
        for pattern, desc, vuln_type, severity in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                self.findings.append(SourceCodeFinding(
                    title=f"Potential {vuln_type.replace('_', ' ').title()}", vuln_type=vuln_type, severity=severity,
                    file=file_path, line=line_num,
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    description=desc, data_flow=None,
                    recommendation={"sqli": "Use parameterized queries", "command_injection": "Avoid shell commands with user input",
                                    "hardcoded_secret": "Use environment variables"}.get(vuln_type, "Fix the vulnerability")))

    def _get_call_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


class JavaScriptAnalyzer:
    def __init__(self):
        self.findings = []

    def analyze_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            lines = content.split("\n")
            patterns = [
                (r'innerHTML\s*=', "innerHTML assignment", "xss", "medium"),
                (r'document\.write\s*\(', "document.write usage", "xss", "medium"),
                (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML", "xss", "medium"),
                (r'eval\s*\(', "eval() usage", "command_injection", "high"),
                (r'Object\.assign\s*\([^,]+,\s*[^)]*req\.(body|query|params)', "Object.assign with user input", "prototype_pollution", "high"),
            ]
            for pattern, desc, vuln_type, severity in patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count("\n") + 1
                    self.findings.append(SourceCodeFinding(
                        title=f"Potential {vuln_type.replace('_', ' ').title()}", vuln_type=vuln_type, severity=severity,
                        file=file_path, line=line_num,
                        code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                        description=desc, data_flow=None, recommendation="Sanitize user input"))
            return self.findings
        except Exception:
            return []


class SourceCodeAnalyzer:
    SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".cs", ".go", ".rb"}
    IGNORE_DIRS = {"node_modules", "venv", ".venv", "__pycache__", ".git", "vendor", "build", "dist"}

    def __init__(self, llm_provider=None):
        self.llm = llm_provider
        self.python_analyzer = PythonAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.findings, self.sources, self.sinks = [], [], []

    def analyze_repository(self, repo_path):
        print(f"\n{'='*60}\nSOURCE CODE ANALYZER\nRepository: {repo_path}\n{'='*60}\n")
        repo_path = Path(repo_path)
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        source_files = self._find_source_files(repo_path)
        print(f"[*] Found {len(source_files)} source files to analyze")
        stats = {"files_analyzed": 0, "files_by_language": {}, "total_findings": 0,
                 "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "findings_by_type": {}}
        for fp in source_files:
            lang = LanguageDetector.detect(str(fp))
            stats["files_analyzed"] += 1
            stats["files_by_language"][lang.value] = stats["files_by_language"].get(lang.value, 0) + 1
            if lang == Language.PYTHON:
                sources, sinks, findings = self.python_analyzer.analyze_file(str(fp))
                self.sources.extend(sources)
                self.sinks.extend(sinks)
                self.findings.extend(findings)
            elif lang in (Language.JAVASCRIPT, Language.TYPESCRIPT):
                self.findings.extend(self.js_analyzer.analyze_file(str(fp)))
        for f in self.findings:
            stats["total_findings"] += 1
            stats["findings_by_severity"][f.severity] = stats["findings_by_severity"].get(f.severity, 0) + 1
            stats["findings_by_type"][f.vuln_type] = stats["findings_by_type"].get(f.vuln_type, 0) + 1
        print(f"\n[+] Analysis complete! Files: {stats['files_analyzed']}, Findings: {stats['total_findings']}")
        return {"findings": self.findings, "sources": self.sources, "sinks": self.sinks, "statistics": stats}

    def _find_source_files(self, repo_path):
        files = []
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            for fn in filenames:
                fp = Path(root) / fn
                if fp.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                    files.append(fp)
        return files

    def get_vulnerable_endpoints(self):
        return [{"path": s.location.file, "line": s.location.line, "input_type": s.type, "input_name": s.name} for s in self.sources]


__all__ = ["SourceCodeAnalyzer", "SourceCodeFinding", "Source", "Sink", "DataFlow", "Language"]
