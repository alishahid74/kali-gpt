"""
Kali-GPT v4.1 - Persistent Memory System

Remembers across sessions:
- Past engagements and targets
- Findings and vulnerabilities
- Successful exploits
- User preferences
- AI conversation context

Uses SQLite for reliable local storage.

Author: Kali-GPT Team
Version: 4.1
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()


# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

DB_PATH = os.path.expanduser("~/.kali-gpt/memory.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Engagement:
    """A penetration test engagement"""
    id: Optional[int] = None
    name: str = ""
    target: str = ""
    target_type: str = ""  # ip, domain, network, web, cloud
    start_time: str = ""
    end_time: str = ""
    status: str = "active"  # active, completed, paused
    notes: str = ""
    findings_count: int = 0
    tools_used: str = ""  # JSON list
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MemoryFinding:
    """A remembered finding"""
    id: Optional[int] = None
    engagement_id: int = 0
    type: str = ""
    value: str = ""
    severity: str = "info"
    host: str = ""
    details: str = ""  # JSON
    discovered_at: str = ""
    verified: bool = False


@dataclass
class Credential:
    """A discovered credential"""
    id: Optional[int] = None
    engagement_id: int = 0
    username: str = ""
    password: str = ""
    hash_value: str = ""
    service: str = ""
    host: str = ""
    discovered_at: str = ""
    verified: bool = False


@dataclass
class Note:
    """A user note"""
    id: Optional[int] = None
    engagement_id: Optional[int] = None
    content: str = ""
    created_at: str = ""
    tags: str = ""  # JSON list


# =============================================================================
# MEMORY DATABASE
# =============================================================================

class MemoryDB:
    """SQLite-based persistent memory"""
    
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()
    
    @contextmanager
    def _get_conn(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            # Engagements table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS engagements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    target TEXT NOT NULL,
                    target_type TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    status TEXT DEFAULT 'active',
                    notes TEXT,
                    findings_count INTEGER DEFAULT 0,
                    tools_used TEXT
                )
            """)
            
            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    type TEXT,
                    value TEXT,
                    severity TEXT DEFAULT 'info',
                    host TEXT,
                    details TEXT,
                    discovered_at TEXT,
                    verified INTEGER DEFAULT 0,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            # Credentials table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    username TEXT,
                    password TEXT,
                    hash_value TEXT,
                    service TEXT,
                    host TEXT,
                    discovered_at TEXT,
                    verified INTEGER DEFAULT 0,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            # Notes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    content TEXT,
                    created_at TEXT,
                    tags TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            # Preferences table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS preferences (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            """)
            
            # Command history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    command TEXT,
                    output TEXT,
                    success INTEGER,
                    executed_at TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            # AI context table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_context (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    role TEXT,
                    content TEXT,
                    created_at TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            conn.commit()
    
    # =========================================================================
    # ENGAGEMENTS
    # =========================================================================
    
    def create_engagement(self, target: str, name: str = None, target_type: str = None) -> int:
        """Create new engagement"""
        if not name:
            name = f"Engagement - {target}"
        
        if not target_type:
            target_type = self._detect_target_type(target)
        
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO engagements (name, target, target_type, start_time, status)
                VALUES (?, ?, ?, ?, 'active')
            """, (name, target, target_type, datetime.now().isoformat()))
            conn.commit()
            return cursor.lastrowid
    
    def _detect_target_type(self, target: str) -> str:
        """Detect target type from target string"""
        import re
        
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return 'ip'
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', target):
            return 'network'
        elif target.startswith(('http://', 'https://')):
            return 'web'
        elif re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$', target):
            return 'domain'
        else:
            return 'unknown'
    
    def get_engagement(self, engagement_id: int) -> Optional[Engagement]:
        """Get engagement by ID"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
            row = cursor.fetchone()
            if row:
                return Engagement(**dict(row))
            return None
    
    def get_active_engagement(self) -> Optional[Engagement]:
        """Get most recent active engagement"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM engagements 
                WHERE status = 'active' 
                ORDER BY start_time DESC 
                LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                return Engagement(**dict(row))
            return None
    
    def get_recent_engagements(self, limit: int = 10) -> List[Engagement]:
        """Get recent engagements"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM engagements 
                ORDER BY start_time DESC 
                LIMIT ?
            """, (limit,))
            return [Engagement(**dict(row)) for row in cursor.fetchall()]
    
    def update_engagement(self, engagement_id: int, **kwargs):
        """Update engagement fields"""
        allowed = ['name', 'status', 'notes', 'end_time', 'findings_count', 'tools_used']
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        
        if not updates:
            return
        
        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [engagement_id]
        
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE engagements SET {set_clause} WHERE id = ?", values)
            conn.commit()
    
    def complete_engagement(self, engagement_id: int):
        """Mark engagement as completed"""
        self.update_engagement(
            engagement_id,
            status='completed',
            end_time=datetime.now().isoformat()
        )
    
    def get_engagements_for_target(self, target: str) -> List[Engagement]:
        """Get all engagements for a target"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM engagements 
                WHERE target = ? OR target LIKE ?
                ORDER BY start_time DESC
            """, (target, f"%{target}%"))
            return [Engagement(**dict(row)) for row in cursor.fetchall()]
    
    # =========================================================================
    # FINDINGS
    # =========================================================================
    
    def add_finding(self, engagement_id: int, finding_type: str, value: str,
                    severity: str = "info", host: str = "", details: Dict = None) -> int:
        """Add a finding"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO findings (engagement_id, type, value, severity, host, details, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                engagement_id,
                finding_type,
                value,
                severity,
                host,
                json.dumps(details or {}),
                datetime.now().isoformat()
            ))
            conn.commit()
            
            # Update findings count
            cursor.execute("""
                UPDATE engagements 
                SET findings_count = (SELECT COUNT(*) FROM findings WHERE engagement_id = ?)
                WHERE id = ?
            """, (engagement_id, engagement_id))
            conn.commit()
            
            return cursor.lastrowid
    
    def get_findings(self, engagement_id: int, severity: str = None) -> List[MemoryFinding]:
        """Get findings for engagement"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            if severity:
                cursor.execute("""
                    SELECT * FROM findings 
                    WHERE engagement_id = ? AND severity = ?
                    ORDER BY discovered_at DESC
                """, (engagement_id, severity))
            else:
                cursor.execute("""
                    SELECT * FROM findings 
                    WHERE engagement_id = ?
                    ORDER BY discovered_at DESC
                """, (engagement_id,))
            
            return [MemoryFinding(**dict(row)) for row in cursor.fetchall()]
    
    def search_findings(self, query: str, limit: int = 50) -> List[MemoryFinding]:
        """Search all findings"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM findings 
                WHERE value LIKE ? OR type LIKE ? OR host LIKE ?
                ORDER BY discovered_at DESC
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
            return [MemoryFinding(**dict(row)) for row in cursor.fetchall()]
    
    # =========================================================================
    # CREDENTIALS
    # =========================================================================
    
    def add_credential(self, engagement_id: int, username: str = "", password: str = "",
                       hash_value: str = "", service: str = "", host: str = "") -> int:
        """Add a credential"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO credentials (engagement_id, username, password, hash_value, service, host, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                engagement_id,
                username,
                password,
                hash_value,
                service,
                host,
                datetime.now().isoformat()
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_credentials(self, engagement_id: int = None) -> List[Credential]:
        """Get credentials"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            if engagement_id:
                cursor.execute("""
                    SELECT * FROM credentials WHERE engagement_id = ?
                    ORDER BY discovered_at DESC
                """, (engagement_id,))
            else:
                cursor.execute("""
                    SELECT * FROM credentials
                    ORDER BY discovered_at DESC
                """)
            
            return [Credential(**dict(row)) for row in cursor.fetchall()]
    
    # =========================================================================
    # NOTES
    # =========================================================================
    
    def add_note(self, content: str, engagement_id: int = None, tags: List[str] = None) -> int:
        """Add a note"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO notes (engagement_id, content, created_at, tags)
                VALUES (?, ?, ?, ?)
            """, (
                engagement_id,
                content,
                datetime.now().isoformat(),
                json.dumps(tags or [])
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_notes(self, engagement_id: int = None) -> List[Note]:
        """Get notes"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            if engagement_id:
                cursor.execute("""
                    SELECT * FROM notes WHERE engagement_id = ?
                    ORDER BY created_at DESC
                """, (engagement_id,))
            else:
                cursor.execute("""
                    SELECT * FROM notes
                    ORDER BY created_at DESC
                """)
            
            return [Note(**dict(row)) for row in cursor.fetchall()]
    
    # =========================================================================
    # PREFERENCES
    # =========================================================================
    
    def set_preference(self, key: str, value: Any):
        """Set a preference"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO preferences (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, json.dumps(value), datetime.now().isoformat()))
            conn.commit()
    
    def get_preference(self, key: str, default: Any = None) -> Any:
        """Get a preference"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM preferences WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['value'])
            return default
    
    # =========================================================================
    # COMMAND HISTORY
    # =========================================================================
    
    def add_command(self, command: str, output: str = "", success: bool = True,
                    engagement_id: int = None):
        """Add command to history"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO command_history (engagement_id, command, output, success, executed_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                engagement_id,
                command,
                output[:10000],  # Limit output size
                1 if success else 0,
                datetime.now().isoformat()
            ))
            conn.commit()
    
    def get_command_history(self, engagement_id: int = None, limit: int = 100) -> List[Dict]:
        """Get command history"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            if engagement_id:
                cursor.execute("""
                    SELECT * FROM command_history 
                    WHERE engagement_id = ?
                    ORDER BY executed_at DESC
                    LIMIT ?
                """, (engagement_id, limit))
            else:
                cursor.execute("""
                    SELECT * FROM command_history
                    ORDER BY executed_at DESC
                    LIMIT ?
                """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # =========================================================================
    # AI CONTEXT
    # =========================================================================
    
    def add_ai_context(self, role: str, content: str, engagement_id: int = None):
        """Add AI conversation context"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ai_context (engagement_id, role, content, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                engagement_id,
                role,
                content[:5000],  # Limit content size
                datetime.now().isoformat()
            ))
            conn.commit()
    
    def get_ai_context(self, engagement_id: int = None, limit: int = 20) -> List[Dict]:
        """Get recent AI context"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            if engagement_id:
                cursor.execute("""
                    SELECT role, content FROM ai_context 
                    WHERE engagement_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (engagement_id, limit))
            else:
                cursor.execute("""
                    SELECT role, content FROM ai_context
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))
            
            # Return in chronological order
            return [dict(row) for row in cursor.fetchall()][::-1]
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total engagements
            cursor.execute("SELECT COUNT(*) FROM engagements")
            stats['total_engagements'] = cursor.fetchone()[0]
            
            # Active engagements
            cursor.execute("SELECT COUNT(*) FROM engagements WHERE status = 'active'")
            stats['active_engagements'] = cursor.fetchone()[0]
            
            # Total findings
            cursor.execute("SELECT COUNT(*) FROM findings")
            stats['total_findings'] = cursor.fetchone()[0]
            
            # Findings by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM findings 
                GROUP BY severity
            """)
            stats['findings_by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Total credentials
            cursor.execute("SELECT COUNT(*) FROM credentials")
            stats['total_credentials'] = cursor.fetchone()[0]
            
            # Commands executed
            cursor.execute("SELECT COUNT(*) FROM command_history")
            stats['total_commands'] = cursor.fetchone()[0]
            
            # Unique targets
            cursor.execute("SELECT COUNT(DISTINCT target) FROM engagements")
            stats['unique_targets'] = cursor.fetchone()[0]
            
            return stats


# =============================================================================
# MEMORY MANAGER (High-level interface)
# =============================================================================

class MemoryManager:
    """
    High-level interface for Kali-GPT memory system.
    
    Provides easy-to-use methods for:
    - Managing engagements
    - Storing and retrieving findings
    - Maintaining context across sessions
    - Smart recall of past information
    """
    
    def __init__(self):
        self.db = MemoryDB()
        self.current_engagement: Optional[Engagement] = None
        
        # Try to resume active engagement
        active = self.db.get_active_engagement()
        if active:
            self.current_engagement = active
    
    def start_engagement(self, target: str, name: str = None) -> Engagement:
        """Start a new engagement"""
        # Check for existing engagement with same target
        existing = self.db.get_engagements_for_target(target)
        if existing:
            console.print(f"[yellow]Found {len(existing)} previous engagement(s) for this target[/yellow]")
        
        engagement_id = self.db.create_engagement(target, name)
        self.current_engagement = self.db.get_engagement(engagement_id)
        
        return self.current_engagement
    
    def resume_engagement(self, engagement_id: int = None) -> Optional[Engagement]:
        """Resume an existing engagement"""
        if engagement_id:
            self.current_engagement = self.db.get_engagement(engagement_id)
        else:
            self.current_engagement = self.db.get_active_engagement()
        
        return self.current_engagement
    
    def end_engagement(self):
        """End current engagement"""
        if self.current_engagement:
            self.db.complete_engagement(self.current_engagement.id)
            self.current_engagement = None
    
    def remember_finding(self, finding_type: str, value: str, severity: str = "info",
                         host: str = "", details: Dict = None):
        """Remember a finding"""
        if not self.current_engagement:
            return
        
        self.db.add_finding(
            self.current_engagement.id,
            finding_type,
            value,
            severity,
            host,
            details
        )
    
    def remember_credential(self, username: str = "", password: str = "",
                           hash_value: str = "", service: str = "", host: str = ""):
        """Remember a credential"""
        if not self.current_engagement:
            return
        
        self.db.add_credential(
            self.current_engagement.id,
            username,
            password,
            hash_value,
            service,
            host
        )
    
    def remember_command(self, command: str, output: str = "", success: bool = True):
        """Remember a command execution"""
        engagement_id = self.current_engagement.id if self.current_engagement else None
        self.db.add_command(command, output, success, engagement_id)
    
    def add_note(self, content: str, tags: List[str] = None):
        """Add a note"""
        engagement_id = self.current_engagement.id if self.current_engagement else None
        self.db.add_note(content, engagement_id, tags)
    
    def recall_target(self, target: str) -> Dict:
        """Recall everything known about a target"""
        engagements = self.db.get_engagements_for_target(target)
        
        all_findings = []
        all_credentials = []
        
        for eng in engagements:
            all_findings.extend(self.db.get_findings(eng.id))
            all_credentials.extend(self.db.get_credentials(eng.id))
        
        return {
            'engagements': engagements,
            'findings': all_findings,
            'credentials': all_credentials,
            'total_assessments': len(engagements)
        }
    
    def get_context_for_ai(self, target: str = None) -> str:
        """Get context string for AI"""
        context_parts = []
        
        # Current engagement info
        if self.current_engagement:
            context_parts.append(f"Current engagement: {self.current_engagement.target}")
            
            findings = self.db.get_findings(self.current_engagement.id)
            if findings:
                context_parts.append(f"Findings so far: {len(findings)}")
                critical = sum(1 for f in findings if f.severity == 'critical')
                high = sum(1 for f in findings if f.severity == 'high')
                if critical or high:
                    context_parts.append(f"Critical: {critical}, High: {high}")
        
        # Past knowledge of target
        if target:
            past = self.recall_target(target)
            if past['total_assessments'] > 0:
                context_parts.append(f"Past assessments: {past['total_assessments']}")
                context_parts.append(f"Known findings: {len(past['findings'])}")
                if past['credentials']:
                    context_parts.append(f"Known credentials: {len(past['credentials'])}")
        
        return "\n".join(context_parts) if context_parts else ""
    
    def get_stats(self) -> Dict:
        """Get statistics"""
        return self.db.get_statistics()


# =============================================================================
# INTERACTIVE MENU
# =============================================================================

async def memory_menu(memory: MemoryManager):
    """Interactive memory management menu"""
    
    console.print(Panel(
        "[bold cyan]🧠 MEMORY SYSTEM[/bold cyan]\n\n"
        "Kali-GPT remembers across sessions:\n"
        "  📋 Past engagements and targets\n"
        "  🔍 All findings and vulnerabilities\n"
        "  🔑 Discovered credentials\n"
        "  📝 Your notes\n"
        "  ⚡ Command history\n\n"
        f"[dim]Database: {DB_PATH}[/dim]",
        title="Memory",
        border_style="cyan"
    ))
    
    # Show current state
    if memory.current_engagement:
        console.print(f"\n[green]Active engagement: {memory.current_engagement.target}[/green]")
    
    stats = memory.get_stats()
    console.print(f"\n[dim]Stats: {stats['total_engagements']} engagements, "
                  f"{stats['total_findings']} findings, "
                  f"{stats['total_credentials']} credentials[/dim]")
    
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_row("1", "📋 View Engagements")
    table.add_row("2", "🔍 Search Findings")
    table.add_row("3", "🔑 View Credentials")
    table.add_row("4", "📝 Add Note")
    table.add_row("5", "⚡ Command History")
    table.add_row("6", "📊 Statistics")
    table.add_row("7", "🎯 Recall Target")
    table.add_row("b", "⬅️  Back")
    console.print(table)
    
    choice = Prompt.ask("\nSelect", default="b")
    
    if choice == '1':
        # View engagements
        engagements = memory.db.get_recent_engagements(20)
        
        if not engagements:
            console.print("[yellow]No engagements found[/yellow]")
        else:
            table = Table(title="Recent Engagements", box=box.ROUNDED)
            table.add_column("ID", style="cyan")
            table.add_column("Target")
            table.add_column("Status")
            table.add_column("Findings")
            table.add_column("Date")
            
            for eng in engagements:
                status_color = "green" if eng.status == "active" else "dim"
                table.add_row(
                    str(eng.id),
                    eng.target,
                    f"[{status_color}]{eng.status}[/{status_color}]",
                    str(eng.findings_count),
                    eng.start_time[:10] if eng.start_time else ""
                )
            
            console.print(table)
    
    elif choice == '2':
        # Search findings
        query = Prompt.ask("Search query")
        if query:
            findings = memory.db.search_findings(query)
            
            if not findings:
                console.print("[yellow]No findings found[/yellow]")
            else:
                console.print(f"\n[green]Found {len(findings)} results:[/green]\n")
                for f in findings[:20]:
                    color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(f.severity, "dim")
                    console.print(f"[{color}][{f.severity}][/{color}] {f.type}: {f.value[:60]}")
    
    elif choice == '3':
        # View credentials
        creds = memory.db.get_credentials()
        
        if not creds:
            console.print("[yellow]No credentials found[/yellow]")
        else:
            table = Table(title="Discovered Credentials", box=box.ROUNDED)
            table.add_column("Username")
            table.add_column("Password/Hash")
            table.add_column("Service")
            table.add_column("Host")
            
            for c in creds[:20]:
                table.add_row(
                    c.username or "-",
                    (c.password or c.hash_value or "-")[:20],
                    c.service or "-",
                    c.host or "-"
                )
            
            console.print(table)
    
    elif choice == '4':
        # Add note
        content = Prompt.ask("Note content")
        if content:
            tags = Prompt.ask("Tags (comma-separated)", default="")
            tag_list = [t.strip() for t in tags.split(",") if t.strip()]
            memory.add_note(content, tag_list)
            console.print("[green]✓ Note saved[/green]")
    
    elif choice == '5':
        # Command history
        history = memory.db.get_command_history(limit=20)
        
        if not history:
            console.print("[yellow]No command history[/yellow]")
        else:
            for cmd in history:
                status = "✓" if cmd['success'] else "✗"
                console.print(f"[dim]{cmd['executed_at'][:19]}[/dim] {status} {cmd['command'][:60]}")
    
    elif choice == '6':
        # Statistics
        stats = memory.get_stats()
        
        console.print(Panel(
            f"[bold]Total Engagements:[/bold] {stats['total_engagements']}\n"
            f"[bold]Active Engagements:[/bold] {stats['active_engagements']}\n"
            f"[bold]Unique Targets:[/bold] {stats['unique_targets']}\n"
            f"[bold]Total Findings:[/bold] {stats['total_findings']}\n"
            f"[bold]Total Credentials:[/bold] {stats['total_credentials']}\n"
            f"[bold]Commands Executed:[/bold] {stats['total_commands']}\n\n"
            f"[bold]Findings by Severity:[/bold]\n" +
            "\n".join([f"  {k}: {v}" for k, v in stats.get('findings_by_severity', {}).items()]),
            title="📊 Statistics",
            border_style="green"
        ))
    
    elif choice == '7':
        # Recall target
        target = Prompt.ask("Target to recall")
        if target:
            data = memory.recall_target(target)
            
            if data['total_assessments'] == 0:
                console.print(f"[yellow]No data found for {target}[/yellow]")
            else:
                console.print(f"\n[bold]Known information about {target}:[/bold]\n")
                console.print(f"  Past assessments: {data['total_assessments']}")
                console.print(f"  Total findings: {len(data['findings'])}")
                console.print(f"  Known credentials: {len(data['credentials'])}")
                
                if data['findings']:
                    console.print("\n[bold]Recent findings:[/bold]")
                    for f in data['findings'][:10]:
                        console.print(f"  [{f.severity}] {f.value[:50]}")
    
    Prompt.ask("\nPress Enter to continue")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("Memory System module loaded")
    print(f"Database: {DB_PATH}")
    
    # Test
    memory = MemoryManager()
    print(f"Stats: {memory.get_stats()}")
