"""
Persistent Memory System

SQLite-based memory for:
- Engagement history
- Discovered vulnerabilities
- Successful exploitation patterns
- Target fingerprints
- Learning from past engagements
"""

import aiosqlite
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class EngagementRecord:
    """Record of a penetration testing engagement"""
    id: Optional[int] = None
    target: str = ""
    target_fingerprint: str = ""
    start_time: str = ""
    end_time: Optional[str] = None
    phase_reached: str = ""
    total_actions: int = 0
    vulnerabilities_found: int = 0
    success_rate: float = 0.0
    notes: str = ""
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class VulnerabilityRecord:
    """Record of a discovered vulnerability"""
    id: Optional[int] = None
    engagement_id: int = 0
    cve_id: Optional[str] = None
    vulnerability_type: str = ""
    target: str = ""
    service: str = ""
    port: Optional[int] = None
    severity: str = "unknown"
    description: str = ""
    exploitation_successful: bool = False
    exploit_used: Optional[str] = None
    discovered_at: str = ""
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ActionPattern:
    """Pattern of successful actions for learning"""
    id: Optional[int] = None
    target_fingerprint: str = ""
    action_type: str = ""
    tool: str = ""
    command_pattern: str = ""
    success_rate: float = 0.0
    times_used: int = 0
    average_execution_time: float = 0.0
    last_used: str = ""
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class MemoryStore:
    """Persistent memory storage using SQLite"""
    
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / ".kali-gpt-v3"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "memory.db")
        
        self.db_path = db_path
        self._initialized = False
    
    async def initialize(self):
        """Initialize database tables"""
        if self._initialized:
            return
        
        async with aiosqlite.connect(self.db_path) as db:
            # Engagements table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS engagements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    target_fingerprint TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    phase_reached TEXT,
                    total_actions INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 0.0,
                    notes TEXT,
                    metadata TEXT
                )
            """)
            
            # Vulnerabilities table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    cve_id TEXT,
                    vulnerability_type TEXT,
                    target TEXT,
                    service TEXT,
                    port INTEGER,
                    severity TEXT,
                    description TEXT,
                    exploitation_successful INTEGER DEFAULT 0,
                    exploit_used TEXT,
                    discovered_at TEXT,
                    metadata TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            # Action patterns table (for learning)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS action_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_fingerprint TEXT,
                    action_type TEXT,
                    tool TEXT,
                    command_pattern TEXT,
                    success_rate REAL DEFAULT 0.0,
                    times_used INTEGER DEFAULT 0,
                    average_execution_time REAL DEFAULT 0.0,
                    last_used TEXT,
                    metadata TEXT
                )
            """)
            
            # Actions log table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS actions_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id INTEGER,
                    timestamp TEXT,
                    tool TEXT,
                    command TEXT,
                    success INTEGER,
                    output_summary TEXT,
                    findings_count INTEGER DEFAULT 0,
                    execution_time REAL,
                    metadata TEXT,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
                )
            """)
            
            # Target fingerprints table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS target_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT UNIQUE,
                    target_type TEXT,
                    os_type TEXT,
                    services TEXT,
                    technologies TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    engagement_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_engagements_target ON engagements(target)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_engagements_fingerprint ON engagements(target_fingerprint)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vulnerability_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_patterns_fingerprint ON action_patterns(target_fingerprint)")
            
            await db.commit()
        
        self._initialized = True
    
    # Engagement methods
    async def create_engagement(self, target: str, metadata: Dict = None) -> int:
        """Create a new engagement record"""
        await self.initialize()
        
        fingerprint = self._generate_fingerprint(target)
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO engagements (target, target_fingerprint, start_time, metadata)
                VALUES (?, ?, ?, ?)
            """, (target, fingerprint, datetime.now().isoformat(), json.dumps(metadata or {})))
            
            await db.commit()
            return cursor.lastrowid
    
    async def update_engagement(self, engagement_id: int, **kwargs):
        """Update engagement record"""
        await self.initialize()
        
        allowed_fields = [
            'end_time', 'phase_reached', 'total_actions',
            'vulnerabilities_found', 'success_rate', 'notes', 'metadata'
        ]
        
        updates = []
        values = []
        
        for field, value in kwargs.items():
            if field in allowed_fields:
                updates.append(f"{field} = ?")
                if field == 'metadata':
                    values.append(json.dumps(value))
                else:
                    values.append(value)
        
        if not updates:
            return
        
        values.append(engagement_id)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(f"""
                UPDATE engagements 
                SET {', '.join(updates)}
                WHERE id = ?
            """, values)
            await db.commit()
    
    async def get_engagement(self, engagement_id: int) -> Optional[EngagementRecord]:
        """Get engagement by ID"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM engagements WHERE id = ?",
                (engagement_id,)
            )
            row = await cursor.fetchone()
            
            if row:
                return EngagementRecord(
                    id=row['id'],
                    target=row['target'],
                    target_fingerprint=row['target_fingerprint'],
                    start_time=row['start_time'],
                    end_time=row['end_time'],
                    phase_reached=row['phase_reached'],
                    total_actions=row['total_actions'],
                    vulnerabilities_found=row['vulnerabilities_found'],
                    success_rate=row['success_rate'],
                    notes=row['notes'],
                    metadata=json.loads(row['metadata']) if row['metadata'] else {}
                )
        
        return None
    
    async def get_similar_engagements(self, target: str, limit: int = 5) -> List[EngagementRecord]:
        """Find similar past engagements"""
        await self.initialize()
        
        fingerprint = self._generate_fingerprint(target)
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM engagements 
                WHERE target_fingerprint = ? OR target LIKE ?
                ORDER BY start_time DESC
                LIMIT ?
            """, (fingerprint, f"%{target}%", limit))
            
            rows = await cursor.fetchall()
            return [
                EngagementRecord(
                    id=row['id'],
                    target=row['target'],
                    target_fingerprint=row['target_fingerprint'],
                    start_time=row['start_time'],
                    end_time=row['end_time'],
                    phase_reached=row['phase_reached'],
                    total_actions=row['total_actions'],
                    vulnerabilities_found=row['vulnerabilities_found'],
                    success_rate=row['success_rate'],
                    notes=row['notes'],
                    metadata=json.loads(row['metadata']) if row['metadata'] else {}
                )
                for row in rows
            ]
    
    # Vulnerability methods
    async def add_vulnerability(
        self,
        engagement_id: int,
        vulnerability_type: str,
        target: str,
        **kwargs
    ) -> int:
        """Record a discovered vulnerability"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO vulnerabilities 
                (engagement_id, vulnerability_type, target, service, port, 
                 severity, description, cve_id, discovered_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                engagement_id,
                vulnerability_type,
                target,
                kwargs.get('service', ''),
                kwargs.get('port'),
                kwargs.get('severity', 'unknown'),
                kwargs.get('description', ''),
                kwargs.get('cve_id'),
                datetime.now().isoformat(),
                json.dumps(kwargs.get('metadata', {}))
            ))
            
            await db.commit()
            
            # Update engagement count
            await db.execute("""
                UPDATE engagements 
                SET vulnerabilities_found = vulnerabilities_found + 1
                WHERE id = ?
            """, (engagement_id,))
            await db.commit()
            
            return cursor.lastrowid
    
    async def get_vulnerabilities_by_type(
        self,
        vulnerability_type: str,
        limit: int = 20
    ) -> List[VulnerabilityRecord]:
        """Get vulnerabilities by type for learning"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM vulnerabilities 
                WHERE vulnerability_type = ?
                ORDER BY discovered_at DESC
                LIMIT ?
            """, (vulnerability_type, limit))
            
            rows = await cursor.fetchall()
            return [self._row_to_vulnerability(row) for row in rows]
    
    # Action pattern methods
    async def record_action_pattern(
        self,
        target_fingerprint: str,
        action_type: str,
        tool: str,
        command_pattern: str,
        success: bool,
        execution_time: float
    ):
        """Record or update an action pattern for learning"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            # Check if pattern exists
            cursor = await db.execute("""
                SELECT id, times_used, success_rate, average_execution_time 
                FROM action_patterns
                WHERE target_fingerprint = ? AND tool = ? AND command_pattern = ?
            """, (target_fingerprint, tool, command_pattern))
            
            existing = await cursor.fetchone()
            
            if existing:
                # Update existing pattern
                pattern_id, times_used, old_success_rate, avg_time = existing
                new_times = times_used + 1
                new_success_rate = ((old_success_rate * times_used) + (1 if success else 0)) / new_times
                new_avg_time = ((avg_time * times_used) + execution_time) / new_times
                
                await db.execute("""
                    UPDATE action_patterns
                    SET times_used = ?, success_rate = ?, average_execution_time = ?, last_used = ?
                    WHERE id = ?
                """, (new_times, new_success_rate, new_avg_time, datetime.now().isoformat(), pattern_id))
            else:
                # Create new pattern
                await db.execute("""
                    INSERT INTO action_patterns 
                    (target_fingerprint, action_type, tool, command_pattern, 
                     success_rate, times_used, average_execution_time, last_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    target_fingerprint, action_type, tool, command_pattern,
                    1.0 if success else 0.0, 1, execution_time, datetime.now().isoformat()
                ))
            
            await db.commit()
    
    async def get_successful_patterns(
        self,
        target_fingerprint: str,
        min_success_rate: float = 0.7,
        limit: int = 10
    ) -> List[ActionPattern]:
        """Get successful action patterns for a target type"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM action_patterns
                WHERE target_fingerprint = ? AND success_rate >= ?
                ORDER BY success_rate DESC, times_used DESC
                LIMIT ?
            """, (target_fingerprint, min_success_rate, limit))
            
            rows = await cursor.fetchall()
            return [self._row_to_pattern(row) for row in rows]
    
    async def get_recommended_tools(
        self,
        target_fingerprint: str,
        action_type: str
    ) -> List[Dict[str, Any]]:
        """Get tool recommendations based on past success"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT tool, command_pattern, success_rate, times_used
                FROM action_patterns
                WHERE target_fingerprint = ? AND action_type = ?
                ORDER BY success_rate DESC, times_used DESC
                LIMIT 5
            """, (target_fingerprint, action_type))
            
            rows = await cursor.fetchall()
            return [
                {
                    "tool": row['tool'],
                    "command_pattern": row['command_pattern'],
                    "success_rate": row['success_rate'],
                    "times_used": row['times_used']
                }
                for row in rows
            ]
    
    # Action logging
    async def log_action(
        self,
        engagement_id: int,
        tool: str,
        command: str,
        success: bool,
        output_summary: str,
        findings_count: int,
        execution_time: float
    ):
        """Log an action for history"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO actions_log 
                (engagement_id, timestamp, tool, command, success, 
                 output_summary, findings_count, execution_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                engagement_id,
                datetime.now().isoformat(),
                tool,
                command,
                1 if success else 0,
                output_summary[:500],  # Limit summary length
                findings_count,
                execution_time
            ))
            
            # Update engagement action count
            await db.execute("""
                UPDATE engagements 
                SET total_actions = total_actions + 1
                WHERE id = ?
            """, (engagement_id,))
            
            await db.commit()
    
    # Helper methods
    def _generate_fingerprint(self, target: str) -> str:
        """Generate a fingerprint for target similarity matching"""
        # Simple fingerprint based on domain/IP structure
        # In production, this would be more sophisticated
        normalized = target.lower().strip()
        
        # Extract key parts
        parts = []
        if '.' in normalized:
            domain_parts = normalized.split('.')
            if len(domain_parts) >= 2:
                # Get TLD and SLD pattern
                parts.append(domain_parts[-1])  # TLD
                if len(domain_parts[-2]) > 0:
                    parts.append(f"len_{len(domain_parts[-2])}")
        
        fingerprint_str = "_".join(parts) if parts else normalized
        return hashlib.md5(fingerprint_str.encode()).hexdigest()[:16]
    
    def _row_to_vulnerability(self, row) -> VulnerabilityRecord:
        return VulnerabilityRecord(
            id=row['id'],
            engagement_id=row['engagement_id'],
            cve_id=row['cve_id'],
            vulnerability_type=row['vulnerability_type'],
            target=row['target'],
            service=row['service'],
            port=row['port'],
            severity=row['severity'],
            description=row['description'],
            exploitation_successful=bool(row['exploitation_successful']),
            exploit_used=row['exploit_used'],
            discovered_at=row['discovered_at'],
            metadata=json.loads(row['metadata']) if row['metadata'] else {}
        )
    
    def _row_to_pattern(self, row) -> ActionPattern:
        return ActionPattern(
            id=row['id'],
            target_fingerprint=row['target_fingerprint'],
            action_type=row['action_type'],
            tool=row['tool'],
            command_pattern=row['command_pattern'],
            success_rate=row['success_rate'],
            times_used=row['times_used'],
            average_execution_time=row['average_execution_time'],
            last_used=row['last_used'],
            metadata=json.loads(row['metadata']) if row['metadata'] else {}
        )
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        await self.initialize()
        
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}
            
            # Total engagements
            cursor = await db.execute("SELECT COUNT(*) FROM engagements")
            stats['total_engagements'] = (await cursor.fetchone())[0]
            
            # Total vulnerabilities
            cursor = await db.execute("SELECT COUNT(*) FROM vulnerabilities")
            stats['total_vulnerabilities'] = (await cursor.fetchone())[0]
            
            # Total actions
            cursor = await db.execute("SELECT COUNT(*) FROM actions_log")
            stats['total_actions'] = (await cursor.fetchone())[0]
            
            # Average success rate
            cursor = await db.execute(
                "SELECT AVG(success_rate) FROM action_patterns WHERE times_used > 3"
            )
            avg = await cursor.fetchone()
            stats['average_success_rate'] = avg[0] if avg[0] else 0.0
            
            # Most common vulnerability types
            cursor = await db.execute("""
                SELECT vulnerability_type, COUNT(*) as count 
                FROM vulnerabilities 
                GROUP BY vulnerability_type 
                ORDER BY count DESC 
                LIMIT 5
            """)
            stats['top_vulnerability_types'] = [
                {"type": row[0], "count": row[1]} 
                for row in await cursor.fetchall()
            ]
            
            return stats
