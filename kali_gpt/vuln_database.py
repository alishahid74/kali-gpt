#!/usr/bin/env python3
"""
Kali-GPT v4.1 - Vulnerability Database Module

Features:
- CVE/NVD database integration
- Vulnerability lookup and search
- Exploit database (ExploitDB) integration
- Vulnerability tracking and management
- Risk scoring and prioritization
- Remediation tracking
- CVSS calculations
- Vulnerability correlation

Usage:
    from vuln_database import VulnDatabase, CVE, Exploit
    
    db = VulnDatabase()
    cve = db.search_cve("CVE-2021-44228")
    exploits = db.find_exploits(cve_id="CVE-2021-44228")
"""

import os
import sys
import json
import uuid
import sqlite3
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not installed. API features disabled.")


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class VulnStatus(Enum):
    """Vulnerability status in tracking"""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"  # Risk accepted
    REOPENED = "reopened"


class ExploitType(Enum):
    """Types of exploits"""
    REMOTE = "remote"
    LOCAL = "local"
    WEBAPP = "webapp"
    DOS = "dos"
    SHELLCODE = "shellcode"
    PAPERS = "papers"


class AttackVector(Enum):
    """CVSS Attack Vector"""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    """CVSS Attack Complexity"""
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    """CVSS Privileges Required"""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    """CVSS User Interaction"""
    NONE = "N"
    REQUIRED = "R"


class Impact(Enum):
    """CVSS Impact levels"""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


# CVSS v3.1 Base Score weights
CVSS_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
CVSS_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
CVSS_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
CVSS_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
CVSS_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CVSS_IMPACT_WEIGHTS = {"N": 0, "L": 0.22, "H": 0.56}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CVSS:
    """CVSS v3.1 Score"""
    version: str = "3.1"
    vector_string: str = ""
    
    # Base metrics
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"  # Unchanged or Changed
    
    # Impact metrics
    confidentiality_impact: str = "N"
    integrity_impact: str = "N"
    availability_impact: str = "N"
    
    # Scores
    base_score: float = 0.0
    impact_score: float = 0.0
    exploitability_score: float = 0.0
    
    def calculate_score(self) -> float:
        """Calculate CVSS v3.1 base score"""
        # Exploitability sub-score
        av = CVSS_AV_WEIGHTS.get(self.attack_vector, 0.85)
        ac = CVSS_AC_WEIGHTS.get(self.attack_complexity, 0.77)
        
        if self.scope == "C":
            pr = CVSS_PR_WEIGHTS_CHANGED.get(self.privileges_required, 0.85)
        else:
            pr = CVSS_PR_WEIGHTS_UNCHANGED.get(self.privileges_required, 0.85)
        
        ui = CVSS_UI_WEIGHTS.get(self.user_interaction, 0.85)
        
        self.exploitability_score = 8.22 * av * ac * pr * ui
        
        # Impact sub-score
        c = CVSS_IMPACT_WEIGHTS.get(self.confidentiality_impact, 0)
        i = CVSS_IMPACT_WEIGHTS.get(self.integrity_impact, 0)
        a = CVSS_IMPACT_WEIGHTS.get(self.availability_impact, 0)
        
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if self.scope == "U":
            self.impact_score = 6.42 * isc_base
        else:
            self.impact_score = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        
        # Base score
        if self.impact_score <= 0:
            self.base_score = 0.0
        else:
            if self.scope == "U":
                score = min(self.exploitability_score + self.impact_score, 10)
            else:
                score = min(1.08 * (self.exploitability_score + self.impact_score), 10)
            
            # Round up to 1 decimal place
            self.base_score = round(score * 10) / 10
        
        return self.base_score
    
    def get_severity(self) -> Severity:
        """Get severity level from score"""
        if self.base_score >= 9.0:
            return Severity.CRITICAL
        elif self.base_score >= 7.0:
            return Severity.HIGH
        elif self.base_score >= 4.0:
            return Severity.MEDIUM
        elif self.base_score >= 0.1:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def to_vector_string(self) -> str:
        """Generate CVSS vector string"""
        self.vector_string = f"CVSS:{self.version}/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality_impact}/I:{self.integrity_impact}/A:{self.availability_impact}"
        return self.vector_string
    
    @classmethod
    def from_vector_string(cls, vector: str) -> 'CVSS':
        """Parse CVSS from vector string"""
        cvss = cls()
        
        if not vector:
            return cvss
        
        # Parse vector string
        parts = vector.split('/')
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                key = key.upper()
                value = value.upper()
                
                if key == 'AV':
                    cvss.attack_vector = value
                elif key == 'AC':
                    cvss.attack_complexity = value
                elif key == 'PR':
                    cvss.privileges_required = value
                elif key == 'UI':
                    cvss.user_interaction = value
                elif key == 'S':
                    cvss.scope = value
                elif key == 'C':
                    cvss.confidentiality_impact = value
                elif key == 'I':
                    cvss.integrity_impact = value
                elif key == 'A':
                    cvss.availability_impact = value
        
        cvss.calculate_score()
        cvss.vector_string = vector
        return cvss


@dataclass
class CVE:
    """Common Vulnerabilities and Exposures entry"""
    id: str  # CVE-YYYY-NNNNN
    
    # Description
    description: str = ""
    summary: str = ""
    
    # Scoring
    cvss: Optional[CVSS] = None
    severity: Severity = Severity.UNKNOWN
    
    # References
    references: List[str] = field(default_factory=list)
    
    # Affected products (CPE)
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    
    # Dates
    published_date: str = ""
    modified_date: str = ""
    
    # CWE (weakness)
    cwe_ids: List[str] = field(default_factory=list)
    
    # Exploit info
    has_exploit: bool = False
    exploit_ids: List[str] = field(default_factory=list)
    
    # Metadata
    source: str = "NVD"  # NVD, MITRE, etc.
    cached_at: str = ""
    
    def __post_init__(self):
        if not self.cached_at:
            self.cached_at = datetime.now().isoformat()
        
        # Calculate severity from CVSS if available
        if self.cvss and self.severity == Severity.UNKNOWN:
            self.severity = self.cvss.get_severity()


@dataclass
class Exploit:
    """Exploit database entry"""
    id: str
    
    # Basic info
    title: str = ""
    description: str = ""
    
    # Classification
    exploit_type: ExploitType = ExploitType.REMOTE
    platform: str = ""  # windows, linux, multiple, etc.
    
    # Code
    code: str = ""
    language: str = ""  # python, c, ruby, etc.
    
    # Related CVEs
    cve_ids: List[str] = field(default_factory=list)
    
    # Author and source
    author: str = ""
    source: str = "ExploitDB"  # ExploitDB, Metasploit, PacketStorm, etc.
    source_url: str = ""
    
    # Dates
    published_date: str = ""
    
    # Verification
    verified: bool = False
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    cached_at: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]
        if not self.cached_at:
            self.cached_at = datetime.now().isoformat()


@dataclass
class VulnInstance:
    """Instance of a vulnerability found in a scan"""
    id: str
    
    # Vulnerability reference
    cve_id: str = ""
    finding_id: str = ""  # Link to finding
    
    # Target info
    target_id: str = ""
    target_host: str = ""
    target_port: int = 0
    target_service: str = ""
    
    # Status tracking
    status: VulnStatus = VulnStatus.NEW
    severity: Severity = Severity.UNKNOWN
    
    # Risk assessment
    risk_score: float = 0.0
    exploitability: float = 0.0
    business_impact: str = "unknown"  # low, medium, high, critical
    
    # Evidence
    evidence: str = ""
    proof_of_concept: str = ""
    
    # Remediation
    remediation_notes: str = ""
    remediation_deadline: str = ""
    remediated_at: str = ""
    remediated_by: str = ""
    
    # Assignment
    assigned_to: str = ""
    assigned_at: str = ""
    
    # Metadata
    discovered_at: str = ""
    updated_at: str = ""
    comments: List[Dict] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]
        if not self.discovered_at:
            self.discovered_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()


@dataclass
class VulnStats:
    """Vulnerability statistics"""
    total: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_status: Dict[str, int] = field(default_factory=dict)
    by_cve: Dict[str, int] = field(default_factory=dict)
    
    new_last_7_days: int = 0
    new_last_30_days: int = 0
    remediated_last_7_days: int = 0
    remediated_last_30_days: int = 0
    
    avg_remediation_days: float = 0.0
    overdue_count: int = 0


# =============================================================================
# DATABASE
# =============================================================================

class VulnDatabaseStorage:
    """SQLite storage for vulnerability data"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            data_dir = Path.home() / ".kali-gpt"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "vulndb.db")
        
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # CVE cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                id TEXT PRIMARY KEY,
                description TEXT,
                summary TEXT,
                cvss_vector TEXT,
                cvss_score REAL,
                severity TEXT,
                references_json TEXT DEFAULT '[]',
                affected_products TEXT DEFAULT '[]',
                affected_versions TEXT DEFAULT '[]',
                published_date TEXT,
                modified_date TEXT,
                cwe_ids TEXT DEFAULT '[]',
                has_exploit INTEGER DEFAULT 0,
                exploit_ids TEXT DEFAULT '[]',
                source TEXT DEFAULT 'NVD',
                cached_at TEXT
            )
        ''')
        
        # Exploit cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploit_cache (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                exploit_type TEXT,
                platform TEXT,
                code TEXT,
                language TEXT,
                cve_ids TEXT DEFAULT '[]',
                author TEXT,
                source TEXT,
                source_url TEXT,
                published_date TEXT,
                verified INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                cached_at TEXT
            )
        ''')
        
        # Vulnerability instances table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vuln_instances (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                finding_id TEXT,
                target_id TEXT,
                target_host TEXT,
                target_port INTEGER,
                target_service TEXT,
                status TEXT DEFAULT 'new',
                severity TEXT,
                risk_score REAL DEFAULT 0,
                exploitability REAL DEFAULT 0,
                business_impact TEXT DEFAULT 'unknown',
                evidence TEXT,
                proof_of_concept TEXT,
                remediation_notes TEXT,
                remediation_deadline TEXT,
                remediated_at TEXT,
                remediated_by TEXT,
                assigned_to TEXT,
                assigned_at TEXT,
                discovered_at TEXT,
                updated_at TEXT,
                comments TEXT DEFAULT '[]'
            )
        ''')
        
        # Indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_cache(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_cached ON cve_cache(cached_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit_cache(cve_ids)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_status ON vuln_instances(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_target ON vuln_instances(target_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vuln_instances(cve_id)')
        
        conn.commit()
        conn.close()
    
    # CVE operations
    def save_cve(self, cve: CVE):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cve_cache (
                id, description, summary, cvss_vector, cvss_score, severity,
                references_json, affected_products, affected_versions,
                published_date, modified_date, cwe_ids, has_exploit,
                exploit_ids, source, cached_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cve.id, cve.description, cve.summary,
            cve.cvss.to_vector_string() if cve.cvss else "",
            cve.cvss.base_score if cve.cvss else 0,
            cve.severity.value,
            json.dumps(cve.references),
            json.dumps(cve.affected_products),
            json.dumps(cve.affected_versions),
            cve.published_date, cve.modified_date,
            json.dumps(cve.cwe_ids),
            1 if cve.has_exploit else 0,
            json.dumps(cve.exploit_ids),
            cve.source, cve.cached_at
        ))
        
        conn.commit()
        conn.close()
    
    def get_cve(self, cve_id: str) -> Optional[CVE]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cve_cache WHERE id = ?', (cve_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_cve(row)
        return None
    
    def search_cves(self, keyword: str = None, severity: str = None,
                    has_exploit: bool = None, limit: int = 100) -> List[CVE]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM cve_cache WHERE 1=1'
        params = []
        
        if keyword:
            query += ' AND (id LIKE ? OR description LIKE ?)'
            params.extend([f'%{keyword}%', f'%{keyword}%'])
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        
        if has_exploit is not None:
            query += ' AND has_exploit = ?'
            params.append(1 if has_exploit else 0)
        
        query += ' ORDER BY cvss_score DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_cve(row) for row in rows]
    
    def _row_to_cve(self, row) -> CVE:
        cvss = None
        if row['cvss_vector']:
            cvss = CVSS.from_vector_string(row['cvss_vector'])
            cvss.base_score = row['cvss_score']
        
        return CVE(
            id=row['id'],
            description=row['description'],
            summary=row['summary'],
            cvss=cvss,
            severity=Severity(row['severity']) if row['severity'] else Severity.UNKNOWN,
            references=json.loads(row['references_json']),
            affected_products=json.loads(row['affected_products']),
            affected_versions=json.loads(row['affected_versions']),
            published_date=row['published_date'],
            modified_date=row['modified_date'],
            cwe_ids=json.loads(row['cwe_ids']),
            has_exploit=bool(row['has_exploit']),
            exploit_ids=json.loads(row['exploit_ids']),
            source=row['source'],
            cached_at=row['cached_at']
        )
    
    # Exploit operations
    def save_exploit(self, exploit: Exploit):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO exploit_cache (
                id, title, description, exploit_type, platform, code, language,
                cve_ids, author, source, source_url, published_date, verified,
                tags, cached_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            exploit.id, exploit.title, exploit.description,
            exploit.exploit_type.value, exploit.platform,
            exploit.code, exploit.language,
            json.dumps(exploit.cve_ids),
            exploit.author, exploit.source, exploit.source_url,
            exploit.published_date,
            1 if exploit.verified else 0,
            json.dumps(exploit.tags),
            exploit.cached_at
        ))
        
        conn.commit()
        conn.close()
    
    def get_exploit(self, exploit_id: str) -> Optional[Exploit]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM exploit_cache WHERE id = ?', (exploit_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_exploit(row)
        return None
    
    def search_exploits(self, cve_id: str = None, keyword: str = None,
                        platform: str = None, verified_only: bool = False,
                        limit: int = 100) -> List[Exploit]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM exploit_cache WHERE 1=1'
        params = []
        
        if cve_id:
            query += ' AND cve_ids LIKE ?'
            params.append(f'%{cve_id}%')
        
        if keyword:
            query += ' AND (title LIKE ? OR description LIKE ?)'
            params.extend([f'%{keyword}%', f'%{keyword}%'])
        
        if platform:
            query += ' AND platform = ?'
            params.append(platform)
        
        if verified_only:
            query += ' AND verified = 1'
        
        query += ' ORDER BY published_date DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_exploit(row) for row in rows]
    
    def _row_to_exploit(self, row) -> Exploit:
        return Exploit(
            id=row['id'],
            title=row['title'],
            description=row['description'],
            exploit_type=ExploitType(row['exploit_type']) if row['exploit_type'] else ExploitType.REMOTE,
            platform=row['platform'],
            code=row['code'],
            language=row['language'],
            cve_ids=json.loads(row['cve_ids']),
            author=row['author'],
            source=row['source'],
            source_url=row['source_url'],
            published_date=row['published_date'],
            verified=bool(row['verified']),
            tags=json.loads(row['tags']),
            cached_at=row['cached_at']
        )
    
    # Vulnerability instance operations
    def save_vuln_instance(self, vuln: VulnInstance):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        vuln.updated_at = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vuln_instances (
                id, cve_id, finding_id, target_id, target_host, target_port,
                target_service, status, severity, risk_score, exploitability,
                business_impact, evidence, proof_of_concept, remediation_notes,
                remediation_deadline, remediated_at, remediated_by,
                assigned_to, assigned_at, discovered_at, updated_at, comments
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            vuln.id, vuln.cve_id, vuln.finding_id, vuln.target_id,
            vuln.target_host, vuln.target_port, vuln.target_service,
            vuln.status.value, vuln.severity.value,
            vuln.risk_score, vuln.exploitability, vuln.business_impact,
            vuln.evidence, vuln.proof_of_concept, vuln.remediation_notes,
            vuln.remediation_deadline, vuln.remediated_at, vuln.remediated_by,
            vuln.assigned_to, vuln.assigned_at,
            vuln.discovered_at, vuln.updated_at,
            json.dumps(vuln.comments)
        ))
        
        conn.commit()
        conn.close()
    
    def get_vuln_instance(self, vuln_id: str) -> Optional[VulnInstance]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vuln_instances WHERE id = ?', (vuln_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_vuln_instance(row)
        return None
    
    def list_vuln_instances(self, target_id: str = None, status: str = None,
                            severity: str = None, cve_id: str = None,
                            assigned_to: str = None, limit: int = 100) -> List[VulnInstance]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM vuln_instances WHERE 1=1'
        params = []
        
        if target_id:
            query += ' AND target_id = ?'
            params.append(target_id)
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        
        if cve_id:
            query += ' AND cve_id = ?'
            params.append(cve_id)
        
        if assigned_to:
            query += ' AND assigned_to = ?'
            params.append(assigned_to)
        
        query += ' ORDER BY risk_score DESC, discovered_at DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_vuln_instance(row) for row in rows]
    
    def _row_to_vuln_instance(self, row) -> VulnInstance:
        return VulnInstance(
            id=row['id'],
            cve_id=row['cve_id'],
            finding_id=row['finding_id'],
            target_id=row['target_id'],
            target_host=row['target_host'],
            target_port=row['target_port'],
            target_service=row['target_service'],
            status=VulnStatus(row['status']) if row['status'] else VulnStatus.NEW,
            severity=Severity(row['severity']) if row['severity'] else Severity.UNKNOWN,
            risk_score=row['risk_score'],
            exploitability=row['exploitability'],
            business_impact=row['business_impact'],
            evidence=row['evidence'],
            proof_of_concept=row['proof_of_concept'],
            remediation_notes=row['remediation_notes'],
            remediation_deadline=row['remediation_deadline'],
            remediated_at=row['remediated_at'],
            remediated_by=row['remediated_by'],
            assigned_to=row['assigned_to'],
            assigned_at=row['assigned_at'],
            discovered_at=row['discovered_at'],
            updated_at=row['updated_at'],
            comments=json.loads(row['comments'])
        )
    
    def get_statistics(self, target_id: str = None) -> VulnStats:
        """Get vulnerability statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = VulnStats()
        
        # Base query
        where = ' WHERE 1=1'
        params = []
        if target_id:
            where += ' AND target_id = ?'
            params.append(target_id)
        
        # Total count
        cursor.execute(f'SELECT COUNT(*) FROM vuln_instances{where}', params)
        stats.total = cursor.fetchone()[0]
        
        # By severity
        cursor.execute(f'SELECT severity, COUNT(*) FROM vuln_instances{where} GROUP BY severity', params)
        stats.by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        # By status
        cursor.execute(f'SELECT status, COUNT(*) FROM vuln_instances{where} GROUP BY status', params)
        stats.by_status = {row[0]: row[1] for row in cursor.fetchall()}
        
        # By CVE
        cursor.execute(f'SELECT cve_id, COUNT(*) FROM vuln_instances{where} AND cve_id != "" GROUP BY cve_id ORDER BY COUNT(*) DESC LIMIT 10', params)
        stats.by_cve = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Time-based stats
        now = datetime.now()
        week_ago = (now - timedelta(days=7)).isoformat()
        month_ago = (now - timedelta(days=30)).isoformat()
        
        cursor.execute(f'SELECT COUNT(*) FROM vuln_instances{where} AND discovered_at >= ?', params + [week_ago])
        stats.new_last_7_days = cursor.fetchone()[0]
        
        cursor.execute(f'SELECT COUNT(*) FROM vuln_instances{where} AND discovered_at >= ?', params + [month_ago])
        stats.new_last_30_days = cursor.fetchone()[0]
        
        cursor.execute(f'SELECT COUNT(*) FROM vuln_instances{where} AND remediated_at >= ?', params + [week_ago])
        stats.remediated_last_7_days = cursor.fetchone()[0]
        
        cursor.execute(f'SELECT COUNT(*) FROM vuln_instances{where} AND remediated_at >= ?', params + [month_ago])
        stats.remediated_last_30_days = cursor.fetchone()[0]
        
        # Overdue count
        cursor.execute(f'''
            SELECT COUNT(*) FROM vuln_instances{where} 
            AND remediation_deadline != '' 
            AND remediation_deadline < ?
            AND status NOT IN ('remediated', 'false_positive', 'accepted')
        ''', params + [now.isoformat()])
        stats.overdue_count = cursor.fetchone()[0]
        
        conn.close()
        return stats


# =============================================================================
# API CLIENTS
# =============================================================================

class NVDClient:
    """NVD (National Vulnerability Database) API client"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('NVD_API_KEY', '')
    
    def get_cve(self, cve_id: str) -> Optional[CVE]:
        """Fetch CVE details from NVD"""
        if not REQUESTS_AVAILABLE:
            logger.warning("requests library not available")
            return None
        
        try:
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params={'cveId': cve_id},
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('vulnerabilities'):
                    vuln_data = data['vulnerabilities'][0]['cve']
                    return self._parse_nvd_cve(vuln_data)
            
            logger.warning(f"NVD API error: {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"NVD API error: {e}")
            return None
    
    def search(self, keyword: str = None, cpe_name: str = None,
               cvss_v3_severity: str = None, pub_start_date: str = None,
               pub_end_date: str = None, results_per_page: int = 20) -> List[CVE]:
        """Search NVD for CVEs"""
        if not REQUESTS_AVAILABLE:
            return []
        
        try:
            params = {'resultsPerPage': results_per_page}
            
            if keyword:
                params['keywordSearch'] = keyword
            if cpe_name:
                params['cpeName'] = cpe_name
            if cvss_v3_severity:
                params['cvssV3Severity'] = cvss_v3_severity
            if pub_start_date:
                params['pubStartDate'] = pub_start_date
            if pub_end_date:
                params['pubEndDate'] = pub_end_date
            
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                for vuln in data.get('vulnerabilities', []):
                    cve = self._parse_nvd_cve(vuln['cve'])
                    if cve:
                        cves.append(cve)
                
                return cves
            
            return []
            
        except Exception as e:
            logger.error(f"NVD search error: {e}")
            return []
    
    def _parse_nvd_cve(self, data: Dict) -> Optional[CVE]:
        """Parse NVD CVE data"""
        try:
            cve_id = data.get('id', '')
            
            # Get description
            descriptions = data.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS
            cvss = None
            metrics = data.get('metrics', {})
            
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss = CVSS.from_vector_string(cvss_data.get('vectorString', ''))
                cvss.base_score = cvss_data.get('baseScore', 0)
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss = CVSS.from_vector_string(cvss_data.get('vectorString', ''))
                cvss.base_score = cvss_data.get('baseScore', 0)
            
            # Get references
            references = []
            for ref in data.get('references', []):
                references.append(ref.get('url', ''))
            
            # Get CWEs
            cwe_ids = []
            for weakness in data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('value', '').startswith('CWE-'):
                        cwe_ids.append(desc['value'])
            
            # Get affected products (CPE)
            affected_products = []
            for config in data.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        affected_products.append(cpe_match.get('criteria', ''))
            
            return CVE(
                id=cve_id,
                description=description,
                summary=description[:200] + '...' if len(description) > 200 else description,
                cvss=cvss,
                severity=cvss.get_severity() if cvss else Severity.UNKNOWN,
                references=references,
                affected_products=affected_products,
                cwe_ids=cwe_ids,
                published_date=data.get('published', ''),
                modified_date=data.get('lastModified', ''),
                source='NVD'
            )
            
        except Exception as e:
            logger.error(f"Error parsing CVE: {e}")
            return None


class ExploitDBClient:
    """Exploit-DB API client (using local searchsploit or API)"""
    
    SEARCH_URL = "https://www.exploit-db.com/search"
    
    def __init__(self):
        self.searchsploit_available = self._check_searchsploit()
    
    def _check_searchsploit(self) -> bool:
        """Check if searchsploit is available"""
        import shutil
        return shutil.which('searchsploit') is not None
    
    def search(self, query: str = None, cve: str = None, 
               exploit_type: str = None) -> List[Exploit]:
        """Search for exploits"""
        if self.searchsploit_available:
            return self._search_local(query, cve)
        return []
    
    def _search_local(self, query: str = None, cve: str = None) -> List[Exploit]:
        """Search using local searchsploit"""
        import subprocess
        
        try:
            cmd = ['searchsploit', '-j']
            
            if cve:
                cmd.append(cve)
            elif query:
                cmd.extend(query.split())
            else:
                return []
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                exploits = []
                
                for exp in data.get('RESULTS_EXPLOIT', []):
                    # Parse CVEs from title
                    cve_ids = []
                    cve_matches = re.findall(r'CVE-\d{4}-\d+', exp.get('Title', ''))
                    cve_ids.extend(cve_matches)
                    
                    # Determine exploit type
                    exp_type = ExploitType.REMOTE
                    path = exp.get('Path', '').lower()
                    if 'local' in path:
                        exp_type = ExploitType.LOCAL
                    elif 'webapps' in path:
                        exp_type = ExploitType.WEBAPP
                    elif 'dos' in path:
                        exp_type = ExploitType.DOS
                    elif 'shellcode' in path:
                        exp_type = ExploitType.SHELLCODE
                    
                    exploit = Exploit(
                        id=exp.get('EDB-ID', ''),
                        title=exp.get('Title', ''),
                        description=exp.get('Title', ''),
                        exploit_type=exp_type,
                        platform=exp.get('Platform', ''),
                        cve_ids=cve_ids,
                        author=exp.get('Author', ''),
                        source='ExploitDB',
                        source_url=f"https://www.exploit-db.com/exploits/{exp.get('EDB-ID', '')}",
                        published_date=exp.get('Date', ''),
                        verified=exp.get('Verified', '0') == '1'
                    )
                    exploits.append(exploit)
                
                return exploits
            
            return []
            
        except Exception as e:
            logger.error(f"searchsploit error: {e}")
            return []
    
    def get_exploit_code(self, exploit_id: str) -> str:
        """Get exploit code by ID"""
        import subprocess
        
        if not self.searchsploit_available:
            return ""
        
        try:
            result = subprocess.run(
                ['searchsploit', '-m', exploit_id],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Try to find and read the copied file
            # searchsploit copies to current directory
            import glob
            for f in glob.glob(f'*{exploit_id}*'):
                with open(f, 'r', errors='ignore') as file:
                    return file.read()
            
            return ""
            
        except Exception as e:
            logger.error(f"Error getting exploit code: {e}")
            return ""


# =============================================================================
# VULNERABILITY DATABASE MANAGER
# =============================================================================

class VulnDatabase:
    """
    Main vulnerability database manager.
    Coordinates CVE lookups, exploit searches, and vulnerability tracking.
    """
    
    def __init__(self, db_path: str = None, nvd_api_key: str = None):
        self.storage = VulnDatabaseStorage(db_path)
        self.nvd_client = NVDClient(nvd_api_key)
        self.exploitdb_client = ExploitDBClient()
    
    # CVE operations
    def get_cve(self, cve_id: str, use_cache: bool = True) -> Optional[CVE]:
        """Get CVE details, using cache if available"""
        # Normalize CVE ID
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        
        # Check cache first
        if use_cache:
            cached = self.storage.get_cve(cve_id)
            if cached:
                # Check cache age (refresh if > 7 days)
                cache_age = datetime.now() - datetime.fromisoformat(cached.cached_at)
                if cache_age.days < 7:
                    return cached
        
        # Fetch from NVD
        cve = self.nvd_client.get_cve(cve_id)
        
        if cve:
            # Check for exploits
            exploits = self.find_exploits(cve_id=cve_id)
            if exploits:
                cve.has_exploit = True
                cve.exploit_ids = [e.id for e in exploits]
            
            # Cache result
            self.storage.save_cve(cve)
        
        return cve
    
    def search_cves(self, keyword: str = None, severity: str = None,
                    has_exploit: bool = None, use_nvd: bool = True,
                    limit: int = 100) -> List[CVE]:
        """Search for CVEs"""
        # Search local cache first
        results = self.storage.search_cves(
            keyword=keyword,
            severity=severity,
            has_exploit=has_exploit,
            limit=limit
        )
        
        # If few results and NVD enabled, search NVD
        if len(results) < 10 and use_nvd and keyword:
            nvd_results = self.nvd_client.search(keyword=keyword)
            
            for cve in nvd_results:
                if not any(r.id == cve.id for r in results):
                    self.storage.save_cve(cve)
                    results.append(cve)
        
        return results[:limit]
    
    def bulk_lookup(self, cve_ids: List[str]) -> Dict[str, CVE]:
        """Look up multiple CVEs"""
        results = {}
        
        for cve_id in cve_ids:
            cve = self.get_cve(cve_id)
            if cve:
                results[cve_id] = cve
        
        return results
    
    # Exploit operations
    def find_exploits(self, cve_id: str = None, keyword: str = None,
                      platform: str = None, verified_only: bool = False) -> List[Exploit]:
        """Find exploits"""
        # Search local cache
        results = self.storage.search_exploits(
            cve_id=cve_id,
            keyword=keyword,
            platform=platform,
            verified_only=verified_only
        )
        
        # If searching by CVE, also check ExploitDB
        if cve_id and len(results) < 5:
            edb_results = self.exploitdb_client.search(cve=cve_id)
            
            for exploit in edb_results:
                if not any(r.id == exploit.id for r in results):
                    self.storage.save_exploit(exploit)
                    results.append(exploit)
        
        # If searching by keyword
        if keyword and not cve_id and len(results) < 5:
            edb_results = self.exploitdb_client.search(query=keyword)
            
            for exploit in edb_results:
                if not any(r.id == exploit.id for r in results):
                    self.storage.save_exploit(exploit)
                    results.append(exploit)
        
        return results
    
    def get_exploit_code(self, exploit_id: str) -> str:
        """Get exploit code"""
        return self.exploitdb_client.get_exploit_code(exploit_id)
    
    # Vulnerability tracking
    def create_vuln_instance(self, cve_id: str, target_id: str,
                             target_host: str, target_port: int = 0,
                             target_service: str = "",
                             evidence: str = "",
                             finding_id: str = "") -> VulnInstance:
        """Create a vulnerability instance for tracking"""
        # Get CVE details for severity
        cve = self.get_cve(cve_id) if cve_id else None
        
        severity = Severity.UNKNOWN
        risk_score = 0.0
        exploitability = 0.0
        
        if cve and cve.cvss:
            severity = cve.severity
            risk_score = cve.cvss.base_score
            exploitability = cve.cvss.exploitability_score
            
            # Increase risk if exploit exists
            if cve.has_exploit:
                risk_score = min(risk_score * 1.2, 10.0)
                exploitability = min(exploitability * 1.3, 10.0)
        
        vuln = VulnInstance(
            id="",
            cve_id=cve_id,
            finding_id=finding_id,
            target_id=target_id,
            target_host=target_host,
            target_port=target_port,
            target_service=target_service,
            severity=severity,
            risk_score=risk_score,
            exploitability=exploitability,
            evidence=evidence
        )
        
        self.storage.save_vuln_instance(vuln)
        logger.info(f"Created vulnerability instance: {vuln.id}")
        
        return vuln
    
    def update_vuln_instance(self, vuln_id: str, **updates) -> Optional[VulnInstance]:
        """Update a vulnerability instance"""
        vuln = self.storage.get_vuln_instance(vuln_id)
        if not vuln:
            return None
        
        for key, value in updates.items():
            if hasattr(vuln, key):
                if key == 'status':
                    value = VulnStatus(value) if isinstance(value, str) else value
                elif key == 'severity':
                    value = Severity(value) if isinstance(value, str) else value
                setattr(vuln, key, value)
        
        self.storage.save_vuln_instance(vuln)
        return vuln
    
    def remediate_vuln(self, vuln_id: str, notes: str = "",
                       remediated_by: str = "") -> Optional[VulnInstance]:
        """Mark vulnerability as remediated"""
        return self.update_vuln_instance(
            vuln_id,
            status=VulnStatus.REMEDIATED,
            remediation_notes=notes,
            remediated_at=datetime.now().isoformat(),
            remediated_by=remediated_by
        )
    
    def assign_vuln(self, vuln_id: str, user_id: str) -> Optional[VulnInstance]:
        """Assign vulnerability to a user"""
        return self.update_vuln_instance(
            vuln_id,
            assigned_to=user_id,
            assigned_at=datetime.now().isoformat()
        )
    
    def add_comment(self, vuln_id: str, user_id: str, content: str) -> Optional[VulnInstance]:
        """Add comment to vulnerability"""
        vuln = self.storage.get_vuln_instance(vuln_id)
        if not vuln:
            return None
        
        vuln.comments.append({
            'user_id': user_id,
            'content': content,
            'created_at': datetime.now().isoformat()
        })
        
        self.storage.save_vuln_instance(vuln)
        return vuln
    
    def get_vuln_instance(self, vuln_id: str) -> Optional[VulnInstance]:
        """Get vulnerability instance by ID"""
        return self.storage.get_vuln_instance(vuln_id)
    
    def list_vulns(self, **filters) -> List[VulnInstance]:
        """List vulnerability instances"""
        return self.storage.list_vuln_instances(**filters)
    
    def get_statistics(self, target_id: str = None) -> VulnStats:
        """Get vulnerability statistics"""
        return self.storage.get_statistics(target_id)
    
    # Correlation
    def correlate_finding(self, finding: Dict) -> Optional[CVE]:
        """Try to correlate a finding with a CVE"""
        # Look for CVE ID in finding
        text = f"{finding.get('title', '')} {finding.get('description', '')}"
        
        cve_matches = re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
        
        if cve_matches:
            return self.get_cve(cve_matches[0])
        
        # Try keyword search
        keywords = finding.get('title', '').split()[:5]
        if keywords:
            results = self.search_cves(keyword=' '.join(keywords), limit=5)
            if results:
                return results[0]
        
        return None


# =============================================================================
# FASTAPI INTEGRATION
# =============================================================================

def create_vuln_routes(app):
    """
    Add vulnerability database routes to FastAPI app.
    
    Usage in api_server.py:
        from vuln_database import create_vuln_routes
        create_vuln_routes(app)
    """
    from fastapi import APIRouter, HTTPException, Query
    from pydantic import BaseModel
    from typing import Optional, List
    
    router = APIRouter(prefix="/vulns", tags=["Vulnerability Database"])
    vuln_db = VulnDatabase()
    
    # Models
    class VulnInstanceCreate(BaseModel):
        cve_id: str = ""
        target_id: str
        target_host: str
        target_port: int = 0
        target_service: str = ""
        evidence: str = ""
        finding_id: str = ""
    
    class VulnInstanceUpdate(BaseModel):
        status: Optional[str] = None
        severity: Optional[str] = None
        business_impact: Optional[str] = None
        remediation_notes: Optional[str] = None
        remediation_deadline: Optional[str] = None
        assigned_to: Optional[str] = None
    
    # CVE routes
    @router.get("/cve/{cve_id}")
    async def get_cve(cve_id: str):
        """Get CVE details"""
        cve = vuln_db.get_cve(cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        return asdict(cve)
    
    @router.get("/cve")
    async def search_cves(
        keyword: str = None,
        severity: str = None,
        has_exploit: bool = None,
        limit: int = Query(default=50, le=200)
    ):
        """Search CVEs"""
        results = vuln_db.search_cves(
            keyword=keyword,
            severity=severity,
            has_exploit=has_exploit,
            limit=limit
        )
        return [asdict(cve) for cve in results]
    
    # Exploit routes
    @router.get("/exploits")
    async def search_exploits(
        cve_id: str = None,
        keyword: str = None,
        platform: str = None,
        verified_only: bool = False
    ):
        """Search exploits"""
        results = vuln_db.find_exploits(
            cve_id=cve_id,
            keyword=keyword,
            platform=platform,
            verified_only=verified_only
        )
        return [asdict(exp) for exp in results]
    
    @router.get("/exploits/{exploit_id}/code")
    async def get_exploit_code(exploit_id: str):
        """Get exploit code"""
        code = vuln_db.get_exploit_code(exploit_id)
        if not code:
            raise HTTPException(status_code=404, detail="Exploit code not found")
        return {"id": exploit_id, "code": code}
    
    # Vulnerability instance routes
    @router.post("/instances")
    async def create_vuln_instance(data: VulnInstanceCreate):
        """Create vulnerability instance"""
        vuln = vuln_db.create_vuln_instance(
            cve_id=data.cve_id,
            target_id=data.target_id,
            target_host=data.target_host,
            target_port=data.target_port,
            target_service=data.target_service,
            evidence=data.evidence,
            finding_id=data.finding_id
        )
        return asdict(vuln)
    
    @router.get("/instances")
    async def list_vulns(
        target_id: str = None,
        status: str = None,
        severity: str = None,
        cve_id: str = None,
        assigned_to: str = None,
        limit: int = Query(default=100, le=500)
    ):
        """List vulnerability instances"""
        results = vuln_db.list_vulns(
            target_id=target_id,
            status=status,
            severity=severity,
            cve_id=cve_id,
            assigned_to=assigned_to,
            limit=limit
        )
        return [asdict(v) for v in results]
    
    @router.get("/instances/{vuln_id}")
    async def get_vuln_instance(vuln_id: str):
        """Get vulnerability instance"""
        vuln = vuln_db.get_vuln_instance(vuln_id)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return asdict(vuln)
    
    @router.patch("/instances/{vuln_id}")
    async def update_vuln_instance(vuln_id: str, data: VulnInstanceUpdate):
        """Update vulnerability instance"""
        updates = {k: v for k, v in data.dict().items() if v is not None}
        vuln = vuln_db.update_vuln_instance(vuln_id, **updates)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return asdict(vuln)
    
    @router.post("/instances/{vuln_id}/remediate")
    async def remediate_vuln(vuln_id: str, notes: str = "", remediated_by: str = ""):
        """Mark vulnerability as remediated"""
        vuln = vuln_db.remediate_vuln(vuln_id, notes, remediated_by)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return asdict(vuln)
    
    @router.post("/instances/{vuln_id}/assign")
    async def assign_vuln(vuln_id: str, user_id: str):
        """Assign vulnerability to user"""
        vuln = vuln_db.assign_vuln(vuln_id, user_id)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return asdict(vuln)
    
    @router.post("/instances/{vuln_id}/comment")
    async def add_comment(vuln_id: str, user_id: str, content: str):
        """Add comment to vulnerability"""
        vuln = vuln_db.add_comment(vuln_id, user_id, content)
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return asdict(vuln)
    
    # Statistics
    @router.get("/stats")
    async def get_statistics(target_id: str = None):
        """Get vulnerability statistics"""
        stats = vuln_db.get_statistics(target_id)
        return asdict(stats)
    
    app.include_router(router)
    return router, vuln_db


# =============================================================================
# CLI
# =============================================================================

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           KALI-GPT VULNERABILITY DATABASE v4.1                   ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Features:                                                       ║
║  • CVE/NVD database integration                                  ║
║  • Exploit database (ExploitDB) search                           ║
║  • CVSS v3.1 scoring                                             ║
║  • Vulnerability tracking and remediation                        ║
║  • Risk scoring and prioritization                               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


def cli_main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Kali-GPT Vulnerability Database")
    subparsers = parser.add_subparsers(dest="command")
    
    # CVE lookup
    cve_parser = subparsers.add_parser("cve", help="Look up CVE")
    cve_parser.add_argument("cve_id", help="CVE ID (e.g., CVE-2021-44228)")
    
    # CVE search
    search_parser = subparsers.add_parser("search", help="Search CVEs")
    search_parser.add_argument("--keyword", "-k", help="Search keyword")
    search_parser.add_argument("--severity", "-s", choices=['critical', 'high', 'medium', 'low'])
    search_parser.add_argument("--has-exploit", "-e", action="store_true")
    search_parser.add_argument("--limit", "-l", type=int, default=20)
    
    # Exploit search
    exploit_parser = subparsers.add_parser("exploits", help="Search exploits")
    exploit_parser.add_argument("--cve", "-c", help="CVE ID")
    exploit_parser.add_argument("--keyword", "-k", help="Search keyword")
    exploit_parser.add_argument("--verified", "-v", action="store_true")
    
    # Stats
    stats_parser = subparsers.add_parser("stats", help="Show statistics")
    
    args = parser.parse_args()
    
    print_banner()
    
    vuln_db = VulnDatabase()
    
    if args.command == "cve":
        cve = vuln_db.get_cve(args.cve_id)
        if cve:
            print(f"\n{'='*60}")
            print(f"CVE ID: {cve.id}")
            print(f"Severity: {cve.severity.value.upper()}")
            if cve.cvss:
                print(f"CVSS Score: {cve.cvss.base_score}")
                print(f"CVSS Vector: {cve.cvss.to_vector_string()}")
            print(f"{'='*60}")
            print(f"\nDescription:\n{cve.description}")
            print(f"\nPublished: {cve.published_date}")
            print(f"Modified: {cve.modified_date}")
            
            if cve.cwe_ids:
                print(f"\nWeaknesses: {', '.join(cve.cwe_ids)}")
            
            if cve.has_exploit:
                print(f"\n⚠️  EXPLOITS AVAILABLE ({len(cve.exploit_ids)})")
            
            if cve.references:
                print(f"\nReferences:")
                for ref in cve.references[:5]:
                    print(f"  - {ref}")
        else:
            print(f"❌ CVE not found: {args.cve_id}")
    
    elif args.command == "search":
        results = vuln_db.search_cves(
            keyword=args.keyword,
            severity=args.severity,
            has_exploit=args.has_exploit if args.has_exploit else None,
            limit=args.limit
        )
        
        if results:
            print(f"\nFound {len(results)} CVEs:\n")
            print(f"{'CVE ID':<20} {'Score':<8} {'Severity':<10} {'Exploit':<8} Description")
            print("-" * 100)
            for cve in results:
                score = f"{cve.cvss.base_score:.1f}" if cve.cvss else "-"
                exploit = "Yes" if cve.has_exploit else "No"
                desc = cve.summary[:50] + "..." if len(cve.summary) > 50 else cve.summary
                print(f"{cve.id:<20} {score:<8} {cve.severity.value:<10} {exploit:<8} {desc}")
        else:
            print("No CVEs found.")
    
    elif args.command == "exploits":
        results = vuln_db.find_exploits(
            cve_id=args.cve,
            keyword=args.keyword,
            verified_only=args.verified
        )
        
        if results:
            print(f"\nFound {len(results)} exploits:\n")
            print(f"{'ID':<12} {'Type':<10} {'Platform':<12} {'Verified':<10} Title")
            print("-" * 100)
            for exp in results:
                verified = "✓" if exp.verified else ""
                title = exp.title[:50] + "..." if len(exp.title) > 50 else exp.title
                print(f"{exp.id:<12} {exp.exploit_type.value:<10} {exp.platform:<12} {verified:<10} {title}")
        else:
            print("No exploits found.")
    
    elif args.command == "stats":
        stats = vuln_db.get_statistics()
        
        print(f"\n{'='*40}")
        print(f"VULNERABILITY STATISTICS")
        print(f"{'='*40}")
        print(f"\nTotal Tracked: {stats.total}")
        print(f"\nBy Severity:")
        for sev, count in sorted(stats.by_severity.items()):
            print(f"  {sev}: {count}")
        print(f"\nBy Status:")
        for status, count in sorted(stats.by_status.items()):
            print(f"  {status}: {count}")
        print(f"\nNew Last 7 Days: {stats.new_last_7_days}")
        print(f"New Last 30 Days: {stats.new_last_30_days}")
        print(f"Remediated Last 7 Days: {stats.remediated_last_7_days}")
        print(f"Remediated Last 30 Days: {stats.remediated_last_30_days}")
        print(f"Overdue: {stats.overdue_count}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_main()
