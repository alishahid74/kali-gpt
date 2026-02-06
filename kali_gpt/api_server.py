#!/usr/bin/env python3
"""
Kali-GPT v4.1 - REST API Server

A comprehensive REST API for Kali-GPT penetration testing framework.
Provides endpoints for scan management, findings, reports, and real-time updates.

Features:
- RESTful API with FastAPI
- WebSocket support for real-time scan updates
- API key authentication
- Swagger/OpenAPI documentation
- Integration with all Kali-GPT modules

Usage:
    python3 api_server.py
    # or
    uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload

API Docs: http://localhost:8000/docs
"""

import os
import sys
import json
import asyncio
import hashlib
import secrets
import subprocess
import shutil
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Union
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field, asdict
import sqlite3
import uuid
import re

# FastAPI imports
try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
    from fastapi.security import APIKeyHeader, APIKeyQuery
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
    from pydantic import BaseModel, Field, validator
    import uvicorn
except ImportError:
    print("FastAPI not installed. Run: pip install fastapi uvicorn python-multipart websockets")
    sys.exit(1)


# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """API Server Configuration"""
    HOST = os.getenv("KALI_GPT_HOST", "0.0.0.0")
    PORT = int(os.getenv("KALI_GPT_PORT", "8000"))
    DEBUG = os.getenv("KALI_GPT_DEBUG", "false").lower() == "true"
    
    # Paths
    DATA_DIR = Path.home() / ".kali-gpt"
    DB_PATH = DATA_DIR / "api_server.db"
    REPORTS_DIR = Path.home() / "kali-gpt-reports"
    API_KEYS_FILE = DATA_DIR / "api_keys.json"
    
    # Security
    API_KEY_LENGTH = 32
    MAX_CONCURRENT_SCANS = 5
    SCAN_TIMEOUT = 3600  # 1 hour max
    
    # Rate limiting
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # seconds
    
    @classmethod
    def ensure_dirs(cls):
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)


Config.ensure_dirs()


# =============================================================================
# ENUMS AND MODELS
# =============================================================================

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    QUICK = "quick"           # Fast port scan
    STANDARD = "standard"     # Standard pentest
    FULL = "full"             # Comprehensive
    STEALTH = "stealth"       # Low and slow
    WEB = "web"               # Web application focused
    NETWORK = "network"       # Network infrastructure
    CUSTOM = "custom"         # Custom tool selection


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"


# =============================================================================
# PYDANTIC MODELS (Request/Response)
# =============================================================================

class TargetCreate(BaseModel):
    """Create a new target"""
    name: str = Field(..., min_length=1, max_length=255, description="Target name")
    host: str = Field(..., description="IP address or hostname")
    description: Optional[str] = Field(None, max_length=1000)
    tags: List[str] = Field(default_factory=list)
    scope: List[str] = Field(default_factory=list, description="In-scope items")
    out_of_scope: List[str] = Field(default_factory=list)
    
    @validator('host')
    def validate_host(cls, v):
        # Basic validation for IP or domain
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        domain_pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$'
        if not (re.match(ip_pattern, v) or re.match(domain_pattern, v)):
            # Allow localhost and simple hostnames too
            if v not in ['localhost', '127.0.0.1'] and not re.match(r'^[a-zA-Z0-9-]+$', v):
                raise ValueError('Invalid host format')
        return v


class TargetResponse(BaseModel):
    """Target response model"""
    id: str
    name: str
    host: str
    description: Optional[str]
    tags: List[str]
    scope: List[str]
    out_of_scope: List[str]
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0
    finding_count: int = 0


class ScanCreate(BaseModel):
    """Create a new scan"""
    target_id: str = Field(..., description="Target ID to scan")
    scan_type: ScanType = Field(default=ScanType.STANDARD)
    tools: List[str] = Field(default_factory=list, description="Specific tools to run")
    options: Dict[str, Any] = Field(default_factory=dict)
    scheduled_at: Optional[datetime] = Field(None, description="Schedule for later")


class ScanResponse(BaseModel):
    """Scan response model"""
    id: str
    target_id: str
    target_name: str
    target_host: str
    scan_type: ScanType
    status: ScanStatus
    tools: List[str]
    options: Dict[str, Any]
    progress: int = Field(ge=0, le=100)
    current_tool: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    finding_count: int = 0
    error: Optional[str]


class ScanProgress(BaseModel):
    """Real-time scan progress"""
    scan_id: str
    status: ScanStatus
    progress: int
    current_tool: Optional[str]
    current_action: Optional[str]
    findings_count: int
    elapsed_seconds: int
    estimated_remaining: Optional[int]


class FindingCreate(BaseModel):
    """Create a finding manually"""
    scan_id: Optional[str]
    target_id: str
    title: str = Field(..., min_length=1, max_length=500)
    description: str
    severity: Severity
    category: str = Field(default="general")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cve_ids: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    affected_ports: List[int] = Field(default_factory=list)
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    """Finding response model"""
    id: str
    scan_id: Optional[str]
    target_id: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    category: str
    cvss_score: Optional[float]
    cve_ids: List[str]
    affected_hosts: List[str]
    affected_ports: List[int]
    evidence: Optional[str]
    remediation: Optional[str]
    references: List[str]
    created_at: datetime
    updated_at: datetime
    confirmed_by: Optional[str]


class FindingUpdate(BaseModel):
    """Update a finding"""
    status: Optional[FindingStatus]
    severity: Optional[Severity]
    title: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    notes: Optional[str]


class ReportCreate(BaseModel):
    """Generate a report"""
    target_id: Optional[str]
    scan_ids: List[str] = Field(default_factory=list)
    format: str = Field(default="html", pattern="^(html|pdf|json|markdown)$")
    include_evidence: bool = True
    include_remediation: bool = True
    executive_summary: bool = True
    template: str = Field(default="standard")


class ReportResponse(BaseModel):
    """Report response model"""
    id: str
    target_id: Optional[str]
    scan_ids: List[str]
    format: str
    status: str
    file_path: Optional[str]
    file_size: Optional[int]
    created_at: datetime
    download_url: Optional[str]


class APIKeyCreate(BaseModel):
    """Create API key"""
    name: str = Field(..., min_length=1, max_length=100)
    permissions: List[str] = Field(default_factory=lambda: ["read", "write"])
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    """API key response"""
    id: str
    name: str
    key_prefix: str  # First 8 chars for identification
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime]
    last_used: Optional[datetime]
    is_active: bool


class StatsResponse(BaseModel):
    """Statistics response"""
    total_targets: int
    total_scans: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    scans_by_status: Dict[str, int]
    recent_scans: List[Dict]
    top_vulnerabilities: List[Dict]


class ToolInfo(BaseModel):
    """Tool information"""
    name: str
    category: str
    description: str
    installed: bool
    version: Optional[str]


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    uptime_seconds: int
    database: str
    ai_service: str
    active_scans: int
    system_load: float


# =============================================================================
# DATABASE LAYER
# =============================================================================

class Database:
    """SQLite database for API server"""
    
    def __init__(self, db_path: Path = Config.DB_PATH):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                description TEXT,
                tags TEXT DEFAULT '[]',
                scope TEXT DEFAULT '[]',
                out_of_scope TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                scan_type TEXT DEFAULT 'standard',
                status TEXT DEFAULT 'pending',
                tools TEXT DEFAULT '[]',
                options TEXT DEFAULT '{}',
                progress INTEGER DEFAULT 0,
                current_tool TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                error TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                target_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'info',
                status TEXT DEFAULT 'new',
                category TEXT DEFAULT 'general',
                cvss_score REAL,
                cve_ids TEXT DEFAULT '[]',
                affected_hosts TEXT DEFAULT '[]',
                affected_ports TEXT DEFAULT '[]',
                evidence TEXT,
                remediation TEXT,
                references TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                confirmed_by TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        # Reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                target_id TEXT,
                scan_ids TEXT DEFAULT '[]',
                format TEXT DEFAULT 'html',
                status TEXT DEFAULT 'pending',
                file_path TEXT,
                file_size INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # API Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                permissions TEXT DEFAULT '["read"]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                last_used TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Scan logs table (for detailed logging)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT DEFAULT 'info',
                tool TEXT,
                message TEXT,
                output TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    # ----- Target Operations -----
    
    def create_target(self, target: TargetCreate) -> str:
        """Create a new target"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        target_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO targets (id, name, host, description, tags, scope, out_of_scope)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            target_id,
            target.name,
            target.host,
            target.description,
            json.dumps(target.tags),
            json.dumps(target.scope),
            json.dumps(target.out_of_scope)
        ))
        
        conn.commit()
        conn.close()
        return target_id
    
    def get_target(self, target_id: str) -> Optional[Dict]:
        """Get a target by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM targets WHERE id = ?', (target_id,))
        row = cursor.fetchone()
        
        if row:
            # Get counts
            cursor.execute('SELECT COUNT(*) FROM scans WHERE target_id = ?', (target_id,))
            scan_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM findings WHERE target_id = ?', (target_id,))
            finding_count = cursor.fetchone()[0]
            
            conn.close()
            return {
                **dict(row),
                'tags': json.loads(row['tags']),
                'scope': json.loads(row['scope']),
                'out_of_scope': json.loads(row['out_of_scope']),
                'scan_count': scan_count,
                'finding_count': finding_count
            }
        
        conn.close()
        return None
    
    def list_targets(self, skip: int = 0, limit: int = 50) -> List[Dict]:
        """List all targets"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT t.*, 
                   (SELECT COUNT(*) FROM scans WHERE target_id = t.id) as scan_count,
                   (SELECT COUNT(*) FROM findings WHERE target_id = t.id) as finding_count
            FROM targets t
            ORDER BY t.created_at DESC
            LIMIT ? OFFSET ?
        ''', (limit, skip))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            **dict(row),
            'tags': json.loads(row['tags']),
            'scope': json.loads(row['scope']),
            'out_of_scope': json.loads(row['out_of_scope'])
        } for row in rows]
    
    def update_target(self, target_id: str, updates: Dict) -> bool:
        """Update a target"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Build update query
        set_clauses = []
        values = []
        
        for key, value in updates.items():
            if key in ['tags', 'scope', 'out_of_scope']:
                value = json.dumps(value)
            set_clauses.append(f"{key} = ?")
            values.append(value)
        
        set_clauses.append("updated_at = CURRENT_TIMESTAMP")
        values.append(target_id)
        
        cursor.execute(f'''
            UPDATE targets SET {', '.join(set_clauses)} WHERE id = ?
        ''', values)
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    def delete_target(self, target_id: str) -> bool:
        """Delete a target and related data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Delete related data
        cursor.execute('DELETE FROM findings WHERE target_id = ?', (target_id,))
        cursor.execute('DELETE FROM scan_logs WHERE scan_id IN (SELECT id FROM scans WHERE target_id = ?)', (target_id,))
        cursor.execute('DELETE FROM scans WHERE target_id = ?', (target_id,))
        cursor.execute('DELETE FROM targets WHERE id = ?', (target_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    # ----- Scan Operations -----
    
    def create_scan(self, scan: ScanCreate) -> str:
        """Create a new scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        scan_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO scans (id, target_id, scan_type, tools, options)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            scan_id,
            scan.target_id,
            scan.scan_type.value,
            json.dumps(scan.tools),
            json.dumps(scan.options)
        ))
        
        conn.commit()
        conn.close()
        return scan_id
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get a scan by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.*, t.name as target_name, t.host as target_host,
                   (SELECT COUNT(*) FROM findings WHERE scan_id = s.id) as finding_count
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id = ?
        ''', (scan_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                **dict(row),
                'tools': json.loads(row['tools']),
                'options': json.loads(row['options'])
            }
        return None
    
    def list_scans(self, target_id: str = None, status: str = None, 
                   skip: int = 0, limit: int = 50) -> List[Dict]:
        """List scans with optional filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT s.*, t.name as target_name, t.host as target_host,
                   (SELECT COUNT(*) FROM findings WHERE scan_id = s.id) as finding_count
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            WHERE 1=1
        '''
        params = []
        
        if target_id:
            query += ' AND s.target_id = ?'
            params.append(target_id)
        
        if status:
            query += ' AND s.status = ?'
            params.append(status)
        
        query += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, skip])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            **dict(row),
            'tools': json.loads(row['tools']),
            'options': json.loads(row['options'])
        } for row in rows]
    
    def update_scan(self, scan_id: str, updates: Dict) -> bool:
        """Update a scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        set_clauses = []
        values = []
        
        for key, value in updates.items():
            if key in ['tools', 'options']:
                value = json.dumps(value)
            set_clauses.append(f"{key} = ?")
            values.append(value)
        
        values.append(scan_id)
        
        cursor.execute(f'''
            UPDATE scans SET {', '.join(set_clauses)} WHERE id = ?
        ''', values)
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    def add_scan_log(self, scan_id: str, level: str, message: str, 
                     tool: str = None, output: str = None):
        """Add a log entry for a scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_logs (scan_id, level, tool, message, output)
            VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, level, tool, message, output))
        
        conn.commit()
        conn.close()
    
    def get_scan_logs(self, scan_id: str, limit: int = 100) -> List[Dict]:
        """Get logs for a scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scan_logs WHERE scan_id = ?
            ORDER BY timestamp DESC LIMIT ?
        ''', (scan_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    # ----- Finding Operations -----
    
    def create_finding(self, finding: FindingCreate) -> str:
        """Create a new finding"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        finding_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO findings (
                id, scan_id, target_id, title, description, severity,
                category, cvss_score, cve_ids, affected_hosts, affected_ports,
                evidence, remediation, references
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding_id,
            finding.scan_id,
            finding.target_id,
            finding.title,
            finding.description,
            finding.severity.value,
            finding.category,
            finding.cvss_score,
            json.dumps(finding.cve_ids),
            json.dumps(finding.affected_hosts),
            json.dumps(finding.affected_ports),
            finding.evidence,
            finding.remediation,
            json.dumps(finding.references)
        ))
        
        conn.commit()
        conn.close()
        return finding_id
    
    def get_finding(self, finding_id: str) -> Optional[Dict]:
        """Get a finding by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                **dict(row),
                'cve_ids': json.loads(row['cve_ids']),
                'affected_hosts': json.loads(row['affected_hosts']),
                'affected_ports': json.loads(row['affected_ports']),
                'references': json.loads(row['references'])
            }
        return None
    
    def list_findings(self, target_id: str = None, scan_id: str = None,
                      severity: str = None, status: str = None,
                      skip: int = 0, limit: int = 50) -> List[Dict]:
        """List findings with optional filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM findings WHERE 1=1'
        params = []
        
        if target_id:
            query += ' AND target_id = ?'
            params.append(target_id)
        
        if scan_id:
            query += ' AND scan_id = ?'
            params.append(scan_id)
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        query += ' ORDER BY CASE severity WHEN "critical" THEN 1 WHEN "high" THEN 2 WHEN "medium" THEN 3 WHEN "low" THEN 4 ELSE 5 END, created_at DESC'
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, skip])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            **dict(row),
            'cve_ids': json.loads(row['cve_ids']),
            'affected_hosts': json.loads(row['affected_hosts']),
            'affected_ports': json.loads(row['affected_ports']),
            'references': json.loads(row['references'])
        } for row in rows]
    
    def update_finding(self, finding_id: str, updates: Dict) -> bool:
        """Update a finding"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        set_clauses = ["updated_at = CURRENT_TIMESTAMP"]
        values = []
        
        for key, value in updates.items():
            if key in ['cve_ids', 'affected_hosts', 'affected_ports', 'references']:
                value = json.dumps(value)
            set_clauses.append(f"{key} = ?")
            values.append(value)
        
        values.append(finding_id)
        
        cursor.execute(f'''
            UPDATE findings SET {', '.join(set_clauses)} WHERE id = ?
        ''', values)
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM findings WHERE id = ?', (finding_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    # ----- API Key Operations -----
    
    def create_api_key(self, name: str, permissions: List[str], 
                       expires_in_days: int = None) -> tuple:
        """Create a new API key, returns (key_id, raw_key)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        key_id = str(uuid.uuid4())
        raw_key = secrets.token_urlsafe(Config.API_KEY_LENGTH)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:8]
        
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        cursor.execute('''
            INSERT INTO api_keys (id, name, key_hash, key_prefix, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (key_id, name, key_hash, key_prefix, json.dumps(permissions), expires_at))
        
        conn.commit()
        conn.close()
        
        return key_id, raw_key
    
    def validate_api_key(self, raw_key: str) -> Optional[Dict]:
        """Validate an API key and return its info"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        cursor.execute('''
            SELECT * FROM api_keys 
            WHERE key_hash = ? AND is_active = 1
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ''', (key_hash,))
        
        row = cursor.fetchone()
        
        if row:
            # Update last used
            cursor.execute('''
                UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?
            ''', (row['id'],))
            conn.commit()
            
            conn.close()
            return {
                **dict(row),
                'permissions': json.loads(row['permissions'])
            }
        
        conn.close()
        return None
    
    def list_api_keys(self) -> List[Dict]:
        """List all API keys (without hashes)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, key_prefix, permissions, created_at, 
                   expires_at, last_used, is_active
            FROM api_keys ORDER BY created_at DESC
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            **dict(row),
            'permissions': json.loads(row['permissions'])
        } for row in rows]
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE api_keys SET is_active = 0 WHERE id = ?', (key_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success
    
    # ----- Statistics -----
    
    def get_stats(self) -> Dict:
        """Get overall statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Totals
        cursor.execute('SELECT COUNT(*) FROM targets')
        total_targets = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM findings')
        total_findings = cursor.fetchone()[0]
        
        # Findings by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count FROM findings
            GROUP BY severity
        ''')
        findings_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Scans by status
        cursor.execute('''
            SELECT status, COUNT(*) as count FROM scans
            GROUP BY status
        ''')
        scans_by_status = {row['status']: row['count'] for row in cursor.fetchall()}
        
        # Recent scans
        cursor.execute('''
            SELECT s.id, s.status, s.created_at, t.name as target_name
            FROM scans s JOIN targets t ON s.target_id = t.id
            ORDER BY s.created_at DESC LIMIT 5
        ''')
        recent_scans = [dict(row) for row in cursor.fetchall()]
        
        # Top vulnerabilities
        cursor.execute('''
            SELECT title, severity, COUNT(*) as count
            FROM findings
            GROUP BY title
            ORDER BY count DESC LIMIT 10
        ''')
        top_vulnerabilities = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total_targets': total_targets,
            'total_scans': total_scans,
            'total_findings': total_findings,
            'findings_by_severity': findings_by_severity,
            'scans_by_status': scans_by_status,
            'recent_scans': recent_scans,
            'top_vulnerabilities': top_vulnerabilities
        }


# =============================================================================
# SCAN ENGINE
# =============================================================================

class ScanEngine:
    """Manages scan execution"""
    
    def __init__(self, db: Database):
        self.db = db
        self.active_scans: Dict[str, asyncio.Task] = {}
        self.websocket_connections: Dict[str, List[WebSocket]] = {}
    
    # Tool configurations for different scan types
    SCAN_PROFILES = {
        ScanType.QUICK: ['nmap'],
        ScanType.STANDARD: ['nmap', 'whatweb', 'nikto'],
        ScanType.FULL: ['nmap', 'whatweb', 'nikto', 'gobuster', 'nuclei'],
        ScanType.STEALTH: ['nmap'],  # With stealth options
        ScanType.WEB: ['whatweb', 'nikto', 'gobuster', 'sqlmap', 'nuclei'],
        ScanType.NETWORK: ['nmap', 'enum4linux', 'smbmap'],
    }
    
    # Tool commands
    TOOL_COMMANDS = {
        'nmap': 'nmap -sV -sC -T4 -oN {output} {target}',
        'nmap_stealth': 'nmap -sS -T2 -f -oN {output} {target}',
        'whatweb': 'whatweb -a 3 {target}',
        'nikto': 'nikto -h {target} -o {output} -Format txt -maxtime 300',
        'gobuster': 'gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -o {output} -q -t 30 --timeout 10s',
        'nuclei': 'nuclei -u {target} -o {output} -silent',
        'sqlmap': 'sqlmap -u "https://{target}" --batch --crawl=2 --output-dir={output_dir}',
        'enum4linux': 'enum4linux -a {target}',
        'smbmap': 'smbmap -H {target}',
    }
    
    async def start_scan(self, scan_id: str):
        """Start a scan in the background"""
        if len(self.active_scans) >= Config.MAX_CONCURRENT_SCANS:
            raise HTTPException(status_code=429, detail="Maximum concurrent scans reached")
        
        scan = self.db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if scan['status'] == ScanStatus.RUNNING:
            raise HTTPException(status_code=400, detail="Scan already running")
        
        # Create task
        task = asyncio.create_task(self._run_scan(scan_id))
        self.active_scans[scan_id] = task
        
        return scan_id
    
    async def _run_scan(self, scan_id: str):
        """Execute the scan"""
        try:
            scan = self.db.get_scan(scan_id)
            target = scan['target_host']
            scan_type = ScanType(scan['scan_type'])
            
            # Update status
            self.db.update_scan(scan_id, {
                'status': ScanStatus.RUNNING.value,
                'started_at': datetime.now().isoformat()
            })
            
            await self._broadcast_progress(scan_id, ScanStatus.RUNNING, 0, "Starting scan...")
            
            # Get tools to run
            tools = scan['tools'] if scan['tools'] else self.SCAN_PROFILES.get(scan_type, ['nmap'])
            
            # Create output directory
            output_dir = Config.REPORTS_DIR / f"scan_{scan_id}"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            total_tools = len(tools)
            
            for i, tool in enumerate(tools):
                if scan_id not in self.active_scans:
                    # Scan was cancelled
                    self.db.update_scan(scan_id, {'status': ScanStatus.CANCELLED.value})
                    return
                
                progress = int((i / total_tools) * 100)
                self.db.update_scan(scan_id, {
                    'progress': progress,
                    'current_tool': tool
                })
                
                await self._broadcast_progress(scan_id, ScanStatus.RUNNING, progress, f"Running {tool}...")
                
                self.db.add_scan_log(scan_id, 'info', f'Starting {tool}', tool=tool)
                
                # Run the tool
                try:
                    output = await self._run_tool(tool, target, output_dir, scan['options'])
                    
                    # Parse findings
                    findings = self._parse_tool_output(tool, output, target)
                    
                    for finding in findings:
                        finding['scan_id'] = scan_id
                        finding['target_id'] = scan['target_id']
                        self.db.create_finding(FindingCreate(**finding))
                    
                    self.db.add_scan_log(scan_id, 'info', 
                                         f'{tool} completed, {len(findings)} findings', 
                                         tool=tool, output=output[:5000])
                    
                except Exception as e:
                    self.db.add_scan_log(scan_id, 'error', f'{tool} failed: {str(e)}', tool=tool)
            
            # Complete
            self.db.update_scan(scan_id, {
                'status': ScanStatus.COMPLETED.value,
                'progress': 100,
                'current_tool': None,
                'completed_at': datetime.now().isoformat()
            })
            
            await self._broadcast_progress(scan_id, ScanStatus.COMPLETED, 100, "Scan completed")
            
        except Exception as e:
            self.db.update_scan(scan_id, {
                'status': ScanStatus.FAILED.value,
                'error': str(e)
            })
            self.db.add_scan_log(scan_id, 'error', f'Scan failed: {str(e)}')
            await self._broadcast_progress(scan_id, ScanStatus.FAILED, 0, f"Error: {str(e)}")
        
        finally:
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
    
    async def _run_tool(self, tool: str, target: str, output_dir: Path, 
                        options: Dict) -> str:
        """Run a specific tool and return output"""
        
        if not shutil.which(tool.split('_')[0]):  # Handle nmap_stealth etc
            return f"Tool {tool} not installed"
        
        cmd_template = self.TOOL_COMMANDS.get(tool, tool)
        output_file = output_dir / f"{tool}_output.txt"
        
        cmd = cmd_template.format(
            target=target,
            output=output_file,
            output_dir=output_dir
        )
        
        # Apply options
        if options.get('ports'):
            cmd = cmd.replace(target, f"-p {options['ports']} {target}")
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=options.get('timeout', 300)
            )
            
            output = stdout.decode() + stderr.decode()
            
            # Also read output file if created
            if output_file.exists():
                output += "\n" + output_file.read_text()
            
            return output
            
        except asyncio.TimeoutError:
            return f"Tool {tool} timed out"
        except Exception as e:
            return f"Tool {tool} error: {str(e)}"
    
    def _parse_tool_output(self, tool: str, output: str, target: str) -> List[Dict]:
        """Parse tool output for findings"""
        findings = []
        
        if tool.startswith('nmap'):
            findings.extend(self._parse_nmap(output, target))
        elif tool == 'nikto':
            findings.extend(self._parse_nikto(output, target))
        elif tool == 'nuclei':
            findings.extend(self._parse_nuclei(output, target))
        elif tool == 'gobuster':
            findings.extend(self._parse_gobuster(output, target))
        
        return findings
    
    def _parse_nmap(self, output: str, target: str) -> List[Dict]:
        """Parse nmap output"""
        findings = []
        
        # Open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)?'
        for match in re.finditer(port_pattern, output):
            port, service, version = match.groups()
            findings.append({
                'title': f'Open Port: {port}/tcp ({service})',
                'description': f'Port {port} is open running {service}. {version or ""}',
                'severity': Severity.INFO,
                'category': 'network',
                'affected_hosts': [target],
                'affected_ports': [int(port)]
            })
        
        # Vulnerabilities from scripts
        if 'VULNERABLE' in output:
            findings.append({
                'title': 'Vulnerability Detected by Nmap Scripts',
                'description': 'Nmap scripts detected a potential vulnerability',
                'severity': Severity.HIGH,
                'category': 'vulnerability',
                'affected_hosts': [target],
                'evidence': output
            })
        
        return findings
    
    def _parse_nikto(self, output: str, target: str) -> List[Dict]:
        """Parse nikto output"""
        findings = []
        
        # Common patterns
        patterns = [
            (r'Server:\s*(.+)', Severity.INFO, 'Server Version Disclosed'),
            (r'X-Powered-By:\s*(.+)', Severity.LOW, 'Technology Disclosed'),
            (r'OSVDB-\d+', Severity.MEDIUM, 'OSVDB Vulnerability'),
            (r'/admin', Severity.MEDIUM, 'Admin Panel Found'),
            (r'/backup', Severity.HIGH, 'Backup Files Found'),
        ]
        
        for pattern, severity, title in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                findings.append({
                    'title': title,
                    'description': f'Nikto detected: {title}',
                    'severity': severity,
                    'category': 'web',
                    'affected_hosts': [target]
                })
        
        return findings
    
    def _parse_nuclei(self, output: str, target: str) -> List[Dict]:
        """Parse nuclei output"""
        findings = []
        
        # Nuclei outputs JSON lines or formatted text
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        for line in output.split('\n'):
            if '[' in line and ']' in line:
                # Try to extract severity and title
                for sev_name, sev_enum in severity_map.items():
                    if f'[{sev_name}]' in line.lower():
                        findings.append({
                            'title': line.strip(),
                            'description': f'Nuclei finding: {line}',
                            'severity': sev_enum,
                            'category': 'vulnerability',
                            'affected_hosts': [target]
                        })
                        break
        
        return findings
    
    def _parse_gobuster(self, output: str, target: str) -> List[Dict]:
        """Parse gobuster output"""
        findings = []
        
        # Look for interesting paths
        interesting = ['/admin', '/backup', '/config', '/.git', '/.env', 
                       '/wp-admin', '/phpmyadmin', '/api', '/debug']
        
        for path in interesting:
            if path in output.lower():
                findings.append({
                    'title': f'Sensitive Path Found: {path}',
                    'description': f'Directory enumeration found {path}',
                    'severity': Severity.MEDIUM if path in ['/admin', '/.git', '/.env'] else Severity.LOW,
                    'category': 'web',
                    'affected_hosts': [target]
                })
        
        return findings
    
    async def _broadcast_progress(self, scan_id: str, status: ScanStatus, 
                                   progress: int, message: str):
        """Send progress update to connected WebSocket clients"""
        if scan_id not in self.websocket_connections:
            return
        
        update = {
            'scan_id': scan_id,
            'status': status.value,
            'progress': progress,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        dead_connections = []
        
        for ws in self.websocket_connections[scan_id]:
            try:
                await ws.send_json(update)
            except:
                dead_connections.append(ws)
        
        # Clean up dead connections
        for ws in dead_connections:
            self.websocket_connections[scan_id].remove(ws)
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].cancel()
            del self.active_scans[scan_id]
            self.db.update_scan(scan_id, {'status': ScanStatus.CANCELLED.value})
            return True
        return False
    
    def get_active_scan_count(self) -> int:
        """Get number of active scans"""
        return len(self.active_scans)


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

# Initialize
db = Database()
scan_engine = ScanEngine(db)
start_time = datetime.now()

# Create FastAPI app
app = FastAPI(
    title="Kali-GPT API",
    description="REST API for Kali-GPT AI-Powered Penetration Testing Framework",
    version="4.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)


async def get_api_key(
    header_key: str = Depends(api_key_header),
    query_key: str = Depends(api_key_query)
) -> Optional[Dict]:
    """Validate API key from header or query parameter"""
    key = header_key or query_key
    
    if not key:
        # Allow unauthenticated access in dev mode
        if Config.DEBUG:
            return {'permissions': ['read', 'write', 'admin']}
        raise HTTPException(status_code=401, detail="API key required")
    
    key_info = db.validate_api_key(key)
    if not key_info:
        raise HTTPException(status_code=401, detail="Invalid or expired API key")
    
    return key_info


def require_permission(permission: str):
    """Dependency to require specific permission"""
    async def check_permission(api_key: Dict = Depends(get_api_key)):
        if permission not in api_key.get('permissions', []):
            raise HTTPException(status_code=403, detail=f"Permission '{permission}' required")
        return api_key
    return check_permission


# =============================================================================
# ROUTES
# =============================================================================

# ----- Health & Info -----

@app.get("/", tags=["Info"])
async def root():
    """API root - basic info"""
    return {
        "name": "Kali-GPT API",
        "version": "4.1.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["Info"])
async def health_check():
    """Health check endpoint"""
    uptime = (datetime.now() - start_time).total_seconds()
    
    # Check database
    try:
        db.get_stats()
        db_status = "ok"
    except:
        db_status = "error"
    
    # Check AI service (placeholder)
    ai_status = "ok"  # TODO: Actually check
    
    # System load
    try:
        load = os.getloadavg()[0]
    except:
        load = 0.0
    
    return HealthResponse(
        status="healthy" if db_status == "ok" else "degraded",
        version="4.1.0",
        uptime_seconds=int(uptime),
        database=db_status,
        ai_service=ai_status,
        active_scans=scan_engine.get_active_scan_count(),
        system_load=load
    )


@app.get("/stats", response_model=StatsResponse, tags=["Info"])
async def get_statistics(api_key: Dict = Depends(get_api_key)):
    """Get overall statistics"""
    return db.get_stats()


@app.get("/tools", response_model=List[ToolInfo], tags=["Info"])
async def list_tools():
    """List available security tools"""
    tools = [
        ("nmap", "network", "Network scanner and security auditor"),
        ("nikto", "web", "Web server scanner"),
        ("gobuster", "web", "Directory/file brute-forcer"),
        ("sqlmap", "web", "SQL injection tool"),
        ("nuclei", "vulnerability", "Fast vulnerability scanner"),
        ("whatweb", "web", "Web technology identifier"),
        ("enum4linux", "network", "SMB enumeration tool"),
        ("smbmap", "network", "SMB share enumerator"),
        ("hydra", "password", "Network login cracker"),
        ("john", "password", "Password cracker"),
        ("searchsploit", "exploit", "Exploit database search"),
    ]
    
    result = []
    for name, category, description in tools:
        installed = shutil.which(name) is not None
        version = None
        
        if installed:
            try:
                proc = subprocess.run([name, '--version'], capture_output=True, text=True, timeout=5)
                version = proc.stdout.split('\n')[0][:50]
            except:
                pass
        
        result.append(ToolInfo(
            name=name,
            category=category,
            description=description,
            installed=installed,
            version=version
        ))
    
    return result


# ----- Targets -----

@app.post("/targets", response_model=TargetResponse, tags=["Targets"])
async def create_target(
    target: TargetCreate,
    api_key: Dict = Depends(require_permission("write"))
):
    """Create a new target"""
    target_id = db.create_target(target)
    return db.get_target(target_id)


@app.get("/targets", response_model=List[TargetResponse], tags=["Targets"])
async def list_targets(
    skip: int = 0,
    limit: int = 50,
    api_key: Dict = Depends(get_api_key)
):
    """List all targets"""
    return db.list_targets(skip=skip, limit=limit)


@app.get("/targets/{target_id}", response_model=TargetResponse, tags=["Targets"])
async def get_target(
    target_id: str,
    api_key: Dict = Depends(get_api_key)
):
    """Get a specific target"""
    target = db.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@app.put("/targets/{target_id}", response_model=TargetResponse, tags=["Targets"])
async def update_target(
    target_id: str,
    updates: Dict[str, Any],
    api_key: Dict = Depends(require_permission("write"))
):
    """Update a target"""
    if not db.update_target(target_id, updates):
        raise HTTPException(status_code=404, detail="Target not found")
    return db.get_target(target_id)


@app.delete("/targets/{target_id}", tags=["Targets"])
async def delete_target(
    target_id: str,
    api_key: Dict = Depends(require_permission("write"))
):
    """Delete a target and all related data"""
    if not db.delete_target(target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    return {"status": "deleted", "target_id": target_id}


# ----- Scans -----

@app.post("/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
    api_key: Dict = Depends(require_permission("write"))
):
    """Create and optionally start a new scan"""
    # Verify target exists
    target = db.get_target(scan.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    scan_id = db.create_scan(scan)
    
    # Auto-start if not scheduled
    if not scan.scheduled_at:
        background_tasks.add_task(scan_engine.start_scan, scan_id)
    
    return db.get_scan(scan_id)


@app.get("/scans", response_model=List[ScanResponse], tags=["Scans"])
async def list_scans(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    api_key: Dict = Depends(get_api_key)
):
    """List scans with optional filters"""
    return db.list_scans(target_id=target_id, status=status, skip=skip, limit=limit)


@app.get("/scans/{scan_id}", response_model=ScanResponse, tags=["Scans"])
async def get_scan(
    scan_id: str,
    api_key: Dict = Depends(get_api_key)
):
    """Get a specific scan"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/scans/{scan_id}/start", tags=["Scans"])
async def start_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    api_key: Dict = Depends(require_permission("write"))
):
    """Start a pending scan"""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan['status'] not in [ScanStatus.PENDING.value, ScanStatus.PAUSED.value]:
        raise HTTPException(status_code=400, detail=f"Cannot start scan in '{scan['status']}' status")
    
    background_tasks.add_task(scan_engine.start_scan, scan_id)
    
    return {"status": "starting", "scan_id": scan_id}


@app.post("/scans/{scan_id}/cancel", tags=["Scans"])
async def cancel_scan(
    scan_id: str,
    api_key: Dict = Depends(require_permission("write"))
):
    """Cancel a running scan"""
    if scan_engine.cancel_scan(scan_id):
        return {"status": "cancelled", "scan_id": scan_id}
    raise HTTPException(status_code=400, detail="Scan not running or not found")


@app.get("/scans/{scan_id}/logs", tags=["Scans"])
async def get_scan_logs(
    scan_id: str,
    limit: int = 100,
    api_key: Dict = Depends(get_api_key)
):
    """Get logs for a scan"""
    logs = db.get_scan_logs(scan_id, limit=limit)
    return {"scan_id": scan_id, "logs": logs}


# ----- Findings -----

@app.post("/findings", response_model=FindingResponse, tags=["Findings"])
async def create_finding(
    finding: FindingCreate,
    api_key: Dict = Depends(require_permission("write"))
):
    """Create a finding manually"""
    finding_id = db.create_finding(finding)
    return db.get_finding(finding_id)


@app.get("/findings", response_model=List[FindingResponse], tags=["Findings"])
async def list_findings(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
    api_key: Dict = Depends(get_api_key)
):
    """List findings with optional filters"""
    return db.list_findings(
        target_id=target_id,
        scan_id=scan_id,
        severity=severity,
        status=status,
        skip=skip,
        limit=limit
    )


@app.get("/findings/{finding_id}", response_model=FindingResponse, tags=["Findings"])
async def get_finding(
    finding_id: str,
    api_key: Dict = Depends(get_api_key)
):
    """Get a specific finding"""
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@app.patch("/findings/{finding_id}", response_model=FindingResponse, tags=["Findings"])
async def update_finding(
    finding_id: str,
    update: FindingUpdate,
    api_key: Dict = Depends(require_permission("write"))
):
    """Update a finding"""
    updates = {k: v for k, v in update.dict().items() if v is not None}
    
    if not db.update_finding(finding_id, updates):
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return db.get_finding(finding_id)


@app.delete("/findings/{finding_id}", tags=["Findings"])
async def delete_finding(
    finding_id: str,
    api_key: Dict = Depends(require_permission("write"))
):
    """Delete a finding"""
    if not db.delete_finding(finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": "deleted", "finding_id": finding_id}


# ----- Reports -----

@app.post("/reports", response_model=ReportResponse, tags=["Reports"])
async def generate_report(
    report: ReportCreate,
    background_tasks: BackgroundTasks,
    api_key: Dict = Depends(require_permission("write"))
):
    """Generate a report"""
    # TODO: Implement report generation
    # For now, return placeholder
    report_id = str(uuid.uuid4())
    
    return ReportResponse(
        id=report_id,
        target_id=report.target_id,
        scan_ids=report.scan_ids,
        format=report.format,
        status="pending",
        file_path=None,
        file_size=None,
        created_at=datetime.now(),
        download_url=None
    )


@app.get("/reports/{report_id}/download", tags=["Reports"])
async def download_report(
    report_id: str,
    api_key: Dict = Depends(get_api_key)
):
    """Download a generated report"""
    # TODO: Implement
    raise HTTPException(status_code=501, detail="Not implemented yet")


# ----- API Keys -----

@app.post("/api-keys", tags=["API Keys"])
async def create_api_key(
    key_data: APIKeyCreate,
    api_key: Dict = Depends(require_permission("admin"))
):
    """Create a new API key (requires admin permission)"""
    key_id, raw_key = db.create_api_key(
        name=key_data.name,
        permissions=key_data.permissions,
        expires_in_days=key_data.expires_in_days
    )
    
    return {
        "id": key_id,
        "key": raw_key,  # Only shown once!
        "name": key_data.name,
        "permissions": key_data.permissions,
        "message": "Save this key! It won't be shown again."
    }


@app.get("/api-keys", response_model=List[APIKeyResponse], tags=["API Keys"])
async def list_api_keys(api_key: Dict = Depends(require_permission("admin"))):
    """List all API keys"""
    return db.list_api_keys()


@app.delete("/api-keys/{key_id}", tags=["API Keys"])
async def revoke_api_key(
    key_id: str,
    api_key: Dict = Depends(require_permission("admin"))
):
    """Revoke an API key"""
    if not db.revoke_api_key(key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    return {"status": "revoked", "key_id": key_id}


# ----- WebSocket for Real-time Updates -----

@app.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates"""
    await websocket.accept()
    
    # Register connection
    if scan_id not in scan_engine.websocket_connections:
        scan_engine.websocket_connections[scan_id] = []
    scan_engine.websocket_connections[scan_id].append(websocket)
    
    try:
        # Send current status
        scan = db.get_scan(scan_id)
        if scan:
            await websocket.send_json({
                'scan_id': scan_id,
                'status': scan['status'],
                'progress': scan['progress'],
                'current_tool': scan['current_tool']
            })
        
        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Handle ping/pong
                if data == 'ping':
                    await websocket.send_text('pong')
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({'type': 'heartbeat'})
    
    except WebSocketDisconnect:
        pass
    finally:
        # Remove connection
        if scan_id in scan_engine.websocket_connections:
            if websocket in scan_engine.websocket_connections[scan_id]:
                scan_engine.websocket_connections[scan_id].remove(websocket)


# =============================================================================
# CLI SETUP
# =============================================================================

def setup_initial_api_key():
    """Create initial API key if none exists"""
    keys = db.list_api_keys()
    if not keys:
        key_id, raw_key = db.create_api_key(
            name="Initial Admin Key",
            permissions=["read", "write", "admin"]
        )
        print(f"\n{'='*60}")
        print("🔑 INITIAL API KEY CREATED")
        print(f"{'='*60}")
        print(f"Key: {raw_key}")
        print(f"{'='*60}")
        print("⚠️  Save this key! It won't be shown again.")
        print(f"{'='*60}\n")


def print_banner():
    """Print startup banner"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                    KALI-GPT API SERVER v4.1                      ║
╠══════════════════════════════════════════════════════════════════╣
║  REST API for AI-Powered Penetration Testing                     ║
║                                                                  ║
║  Endpoints:                                                      ║
║    • Targets:   /targets                                         ║
║    • Scans:     /scans                                           ║
║    • Findings:  /findings                                        ║
║    • Reports:   /reports                                         ║
║    • WebSocket: /ws/scans/{id}                                   ║
║                                                                  ║
║  Documentation: http://localhost:8000/docs                       ║
╚══════════════════════════════════════════════════════════════════╝
""")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print_banner()
    setup_initial_api_key()
    
    print(f"🚀 Starting server on http://{Config.HOST}:{Config.PORT}")
    print(f"📚 API Docs: http://localhost:{Config.PORT}/docs")
    print(f"🔧 Debug Mode: {Config.DEBUG}")
    print()
    
    uvicorn.run(
        "api_server:app",
        host=Config.HOST,
        port=Config.PORT,
        reload=Config.DEBUG,
        log_level="info" if Config.DEBUG else "warning"
    )
