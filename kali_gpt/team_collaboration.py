#!/usr/bin/env python3
"""
Kali-GPT v4.1 - Team Collaboration Module

Features:
- User accounts with authentication
- Role-based access control (RBAC)
- Teams and workspaces
- Shared targets, scans, and findings
- Activity audit logging
- Comments and annotations
- Task assignment
- Real-time collaboration

Usage:
    from team_collaboration import TeamManager, User, Team
    
    manager = TeamManager()
    user = manager.create_user("alice", "alice@example.com", "password123")
    team = manager.create_team("Red Team", owner_id=user.id)
"""

import os
import sys
import json
import uuid
import sqlite3
import hashlib
import secrets
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
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


# ============================================================================
# ENUMS AND CONSTANTS
# ============================================================================

class Role(Enum):
    """User roles with increasing privileges"""
    VIEWER = "viewer"           # Read-only access
    ANALYST = "analyst"         # Can create/edit findings, comments
    OPERATOR = "operator"       # Can run scans
    ADMIN = "admin"             # Full access to team
    OWNER = "owner"             # Team owner, can delete team


class Permission(Enum):
    """Granular permissions"""
    # Targets
    VIEW_TARGETS = "view_targets"
    CREATE_TARGETS = "create_targets"
    EDIT_TARGETS = "edit_targets"
    DELETE_TARGETS = "delete_targets"
    
    # Scans
    VIEW_SCANS = "view_scans"
    CREATE_SCANS = "create_scans"
    CANCEL_SCANS = "cancel_scans"
    DELETE_SCANS = "delete_scans"
    
    # Findings
    VIEW_FINDINGS = "view_findings"
    CREATE_FINDINGS = "create_findings"
    EDIT_FINDINGS = "edit_findings"
    DELETE_FINDINGS = "delete_findings"
    VERIFY_FINDINGS = "verify_findings"
    
    # Reports
    VIEW_REPORTS = "view_reports"
    CREATE_REPORTS = "create_reports"
    EXPORT_REPORTS = "export_reports"
    
    # Team management
    VIEW_TEAM = "view_team"
    INVITE_MEMBERS = "invite_members"
    REMOVE_MEMBERS = "remove_members"
    EDIT_ROLES = "edit_roles"
    EDIT_TEAM = "edit_team"
    DELETE_TEAM = "delete_team"
    
    # Comments
    VIEW_COMMENTS = "view_comments"
    CREATE_COMMENTS = "create_comments"
    DELETE_COMMENTS = "delete_comments"
    
    # Tasks
    VIEW_TASKS = "view_tasks"
    CREATE_TASKS = "create_tasks"
    ASSIGN_TASKS = "assign_tasks"
    COMPLETE_TASKS = "complete_tasks"


# Role permission mappings
ROLE_PERMISSIONS = {
    Role.VIEWER: {
        Permission.VIEW_TARGETS,
        Permission.VIEW_SCANS,
        Permission.VIEW_FINDINGS,
        Permission.VIEW_REPORTS,
        Permission.VIEW_TEAM,
        Permission.VIEW_COMMENTS,
        Permission.VIEW_TASKS,
    },
    Role.ANALYST: {
        Permission.VIEW_TARGETS,
        Permission.VIEW_SCANS,
        Permission.VIEW_FINDINGS,
        Permission.CREATE_FINDINGS,
        Permission.EDIT_FINDINGS,
        Permission.VERIFY_FINDINGS,
        Permission.VIEW_REPORTS,
        Permission.CREATE_REPORTS,
        Permission.VIEW_TEAM,
        Permission.VIEW_COMMENTS,
        Permission.CREATE_COMMENTS,
        Permission.VIEW_TASKS,
        Permission.CREATE_TASKS,
        Permission.COMPLETE_TASKS,
    },
    Role.OPERATOR: {
        Permission.VIEW_TARGETS,
        Permission.CREATE_TARGETS,
        Permission.EDIT_TARGETS,
        Permission.VIEW_SCANS,
        Permission.CREATE_SCANS,
        Permission.CANCEL_SCANS,
        Permission.VIEW_FINDINGS,
        Permission.CREATE_FINDINGS,
        Permission.EDIT_FINDINGS,
        Permission.VERIFY_FINDINGS,
        Permission.VIEW_REPORTS,
        Permission.CREATE_REPORTS,
        Permission.EXPORT_REPORTS,
        Permission.VIEW_TEAM,
        Permission.VIEW_COMMENTS,
        Permission.CREATE_COMMENTS,
        Permission.VIEW_TASKS,
        Permission.CREATE_TASKS,
        Permission.ASSIGN_TASKS,
        Permission.COMPLETE_TASKS,
    },
    Role.ADMIN: {
        Permission.VIEW_TARGETS,
        Permission.CREATE_TARGETS,
        Permission.EDIT_TARGETS,
        Permission.DELETE_TARGETS,
        Permission.VIEW_SCANS,
        Permission.CREATE_SCANS,
        Permission.CANCEL_SCANS,
        Permission.DELETE_SCANS,
        Permission.VIEW_FINDINGS,
        Permission.CREATE_FINDINGS,
        Permission.EDIT_FINDINGS,
        Permission.DELETE_FINDINGS,
        Permission.VERIFY_FINDINGS,
        Permission.VIEW_REPORTS,
        Permission.CREATE_REPORTS,
        Permission.EXPORT_REPORTS,
        Permission.VIEW_TEAM,
        Permission.INVITE_MEMBERS,
        Permission.REMOVE_MEMBERS,
        Permission.EDIT_ROLES,
        Permission.EDIT_TEAM,
        Permission.VIEW_COMMENTS,
        Permission.CREATE_COMMENTS,
        Permission.DELETE_COMMENTS,
        Permission.VIEW_TASKS,
        Permission.CREATE_TASKS,
        Permission.ASSIGN_TASKS,
        Permission.COMPLETE_TASKS,
    },
    Role.OWNER: set(Permission),  # All permissions
}


class ActivityType(Enum):
    """Types of auditable activities"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    
    TEAM_CREATED = "team_created"
    TEAM_UPDATED = "team_updated"
    TEAM_DELETED = "team_deleted"
    MEMBER_ADDED = "member_added"
    MEMBER_REMOVED = "member_removed"
    ROLE_CHANGED = "role_changed"
    
    TARGET_CREATED = "target_created"
    TARGET_UPDATED = "target_updated"
    TARGET_DELETED = "target_deleted"
    
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_CANCELLED = "scan_cancelled"
    
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_VERIFIED = "finding_verified"
    FINDING_DELETED = "finding_deleted"
    
    COMMENT_ADDED = "comment_added"
    TASK_CREATED = "task_created"
    TASK_ASSIGNED = "task_assigned"
    TASK_COMPLETED = "task_completed"


class TaskStatus(Enum):
    """Task status"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REVIEW = "review"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class User:
    """User account"""
    id: str
    username: str
    email: str
    password_hash: str = ""
    display_name: str = ""
    avatar_url: str = ""
    is_active: bool = True
    is_verified: bool = False
    mfa_enabled: bool = False
    mfa_secret: str = ""
    last_login: str = ""
    created_at: str = ""
    updated_at: str = ""
    settings: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:12]
        if not self.display_name:
            self.display_name = self.username
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self, include_sensitive: bool = False) -> Dict:
        """Convert to dictionary, optionally excluding sensitive fields"""
        data = asdict(self)
        if not include_sensitive:
            del data['password_hash']
            del data['mfa_secret']
        return data


@dataclass
class Team:
    """Team/workspace"""
    id: str
    name: str
    slug: str = ""
    description: str = ""
    owner_id: str = ""
    avatar_url: str = ""
    is_active: bool = True
    settings: Dict = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:12]
        if not self.slug:
            self.slug = self.name.lower().replace(' ', '-')[:50]
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()


@dataclass
class TeamMember:
    """Team membership"""
    id: str
    team_id: str
    user_id: str
    role: Role
    custom_permissions: Set[Permission] = field(default_factory=set)
    joined_at: str = ""
    invited_by: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:12]
        if not self.joined_at:
            self.joined_at = datetime.now().isoformat()
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if member has a specific permission"""
        role_perms = ROLE_PERMISSIONS.get(self.role, set())
        return permission in role_perms or permission in self.custom_permissions


@dataclass
class Invitation:
    """Team invitation"""
    id: str
    team_id: str
    email: str
    role: Role
    token: str = ""
    invited_by: str = ""
    expires_at: str = ""
    accepted_at: str = ""
    created_at: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:12]
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = (datetime.now() + timedelta(days=7)).isoformat()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > datetime.fromisoformat(self.expires_at)
    
    @property
    def is_accepted(self) -> bool:
        return bool(self.accepted_at)


@dataclass
class Comment:
    """Comment on a resource"""
    id: str
    team_id: str
    user_id: str
    resource_type: str  # "target", "scan", "finding"
    resource_id: str
    content: str
    parent_id: str = ""  # For threaded comments
    is_edited: bool = False
    created_at: str = ""
    updated_at: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:12]
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()


@dataclass
class Task:
    """Task/todo item"""
    id: str
    team_id: str
    title: str
    description: str = ""
    status: TaskStatus = TaskStatus.OPEN
    priority: TaskPriority = TaskPriority.MEDIUM
    created_by: str = ""
    assigned_to: str = ""
    resource_type: str = ""  # Optional link to resource
    resource_id: str = ""
    due_date: str = ""
    completed_at: str = ""
    created_at: str = ""
    updated_at: str = ""
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:12]
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()


@dataclass
class ActivityLog:
    """Audit log entry"""
    id: str
    team_id: str
    user_id: str
    activity_type: ActivityType
    resource_type: str = ""
    resource_id: str = ""
    details: Dict = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    created_at: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:16]
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


@dataclass
class Session:
    """User session"""
    id: str
    user_id: str
    token: str
    ip_address: str = ""
    user_agent: str = ""
    expires_at: str = ""
    created_at: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:16]
        if not self.token:
            self.token = secrets.token_urlsafe(48)
        if not self.expires_at:
            self.expires_at = (datetime.now() + timedelta(days=7)).isoformat()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    @property
    def is_expired(self) -> bool:
        return datetime.now() > datetime.fromisoformat(self.expires_at)


# ============================================================================
# DATABASE LAYER
# ============================================================================

class TeamDatabase:
    """SQLite database for team collaboration"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            data_dir = Path.home() / ".kali-gpt"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "teams.db")
        
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                avatar_url TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                is_verified INTEGER DEFAULT 0,
                mfa_enabled INTEGER DEFAULT 0,
                mfa_secret TEXT DEFAULT '',
                last_login TEXT DEFAULT '',
                created_at TEXT,
                updated_at TEXT,
                settings TEXT DEFAULT '{}'
            )
        ''')
        
        # Teams table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                description TEXT DEFAULT '',
                owner_id TEXT NOT NULL,
                avatar_url TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                settings TEXT DEFAULT '{}',
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        ''')
        
        # Team members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS team_members (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                custom_permissions TEXT DEFAULT '[]',
                joined_at TEXT,
                invited_by TEXT,
                FOREIGN KEY (team_id) REFERENCES teams(id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(team_id, user_id)
            )
        ''')
        
        # Invitations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invitations (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                invited_by TEXT,
                expires_at TEXT,
                accepted_at TEXT DEFAULT '',
                created_at TEXT,
                FOREIGN KEY (team_id) REFERENCES teams(id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                expires_at TEXT,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Comments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                content TEXT NOT NULL,
                parent_id TEXT DEFAULT '',
                is_edited INTEGER DEFAULT 0,
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (team_id) REFERENCES teams(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Tasks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'medium',
                created_by TEXT,
                assigned_to TEXT DEFAULT '',
                resource_type TEXT DEFAULT '',
                resource_id TEXT DEFAULT '',
                due_date TEXT DEFAULT '',
                completed_at TEXT DEFAULT '',
                created_at TEXT,
                updated_at TEXT,
                tags TEXT DEFAULT '[]',
                FOREIGN KEY (team_id) REFERENCES teams(id)
            )
        ''')
        
        # Activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                team_id TEXT,
                user_id TEXT,
                activity_type TEXT NOT NULL,
                resource_type TEXT DEFAULT '',
                resource_id TEXT DEFAULT '',
                details TEXT DEFAULT '{}',
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                created_at TEXT
            )
        ''')
        
        # Resource sharing table (for sharing between teams)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_resources (
                id TEXT PRIMARY KEY,
                owner_team_id TEXT NOT NULL,
                shared_with_team_id TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                permissions TEXT DEFAULT '["view"]',
                shared_by TEXT,
                created_at TEXT,
                FOREIGN KEY (owner_team_id) REFERENCES teams(id),
                FOREIGN KEY (shared_with_team_id) REFERENCES teams(id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_comments_resource ON comments(resource_type, resource_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_team ON tasks(team_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_team ON activity_log(team_id)')
        
        conn.commit()
        conn.close()
    
    # User methods
    def save_user(self, user: User) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO users (
                id, username, email, password_hash, display_name, avatar_url,
                is_active, is_verified, mfa_enabled, mfa_secret, last_login,
                created_at, updated_at, settings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user.id, user.username, user.email, user.password_hash,
            user.display_name, user.avatar_url, user.is_active, user.is_verified,
            user.mfa_enabled, user.mfa_secret, user.last_login,
            user.created_at, user.updated_at, json.dumps(user.settings)
        ))
        
        conn.commit()
        conn.close()
        return user.id
    
    def get_user(self, user_id: str = None, username: str = None, email: str = None) -> Optional[User]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        elif username:
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        elif email:
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        else:
            return None
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row['id'],
                username=row['username'],
                email=row['email'],
                password_hash=row['password_hash'],
                display_name=row['display_name'],
                avatar_url=row['avatar_url'],
                is_active=bool(row['is_active']),
                is_verified=bool(row['is_verified']),
                mfa_enabled=bool(row['mfa_enabled']),
                mfa_secret=row['mfa_secret'],
                last_login=row['last_login'],
                created_at=row['created_at'],
                updated_at=row['updated_at'],
                settings=json.loads(row['settings'])
            )
        return None
    
    def list_users(self, is_active: bool = None) -> List[User]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if is_active is not None:
            cursor.execute('SELECT * FROM users WHERE is_active = ?', (is_active,))
        else:
            cursor.execute('SELECT * FROM users')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [User(**{**dict(row), 'settings': json.loads(row['settings']),
                       'is_active': bool(row['is_active']),
                       'is_verified': bool(row['is_verified']),
                       'mfa_enabled': bool(row['mfa_enabled'])}) for row in rows]
    
    # Team methods
    def save_team(self, team: Team) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO teams (
                id, name, slug, description, owner_id, avatar_url,
                is_active, settings, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            team.id, team.name, team.slug, team.description, team.owner_id,
            team.avatar_url, team.is_active, json.dumps(team.settings),
            team.created_at, team.updated_at
        ))
        
        conn.commit()
        conn.close()
        return team.id
    
    def get_team(self, team_id: str = None, slug: str = None) -> Optional[Team]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if team_id:
            cursor.execute('SELECT * FROM teams WHERE id = ?', (team_id,))
        elif slug:
            cursor.execute('SELECT * FROM teams WHERE slug = ?', (slug,))
        else:
            return None
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return Team(
                id=row['id'],
                name=row['name'],
                slug=row['slug'],
                description=row['description'],
                owner_id=row['owner_id'],
                avatar_url=row['avatar_url'],
                is_active=bool(row['is_active']),
                settings=json.loads(row['settings']),
                created_at=row['created_at'],
                updated_at=row['updated_at']
            )
        return None
    
    def list_teams(self, user_id: str = None) -> List[Team]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('''
                SELECT t.* FROM teams t
                JOIN team_members tm ON t.id = tm.team_id
                WHERE tm.user_id = ? AND t.is_active = 1
            ''', (user_id,))
        else:
            cursor.execute('SELECT * FROM teams WHERE is_active = 1')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [Team(**{**dict(row), 'settings': json.loads(row['settings']),
                       'is_active': bool(row['is_active'])}) for row in rows]
    
    def delete_team(self, team_id: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE teams SET is_active = 0 WHERE id = ?', (team_id,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return deleted
    
    # Team member methods
    def save_member(self, member: TeamMember) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        custom_perms = json.dumps([p.value for p in member.custom_permissions])
        
        cursor.execute('''
            INSERT OR REPLACE INTO team_members (
                id, team_id, user_id, role, custom_permissions, joined_at, invited_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            member.id, member.team_id, member.user_id, member.role.value,
            custom_perms, member.joined_at, member.invited_by
        ))
        
        conn.commit()
        conn.close()
        return member.id
    
    def get_member(self, team_id: str, user_id: str) -> Optional[TeamMember]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM team_members WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            custom_perms = set(Permission(p) for p in json.loads(row['custom_permissions']))
            return TeamMember(
                id=row['id'],
                team_id=row['team_id'],
                user_id=row['user_id'],
                role=Role(row['role']),
                custom_permissions=custom_perms,
                joined_at=row['joined_at'],
                invited_by=row['invited_by']
            )
        return None
    
    def list_members(self, team_id: str) -> List[TeamMember]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM team_members WHERE team_id = ?', (team_id,))
        rows = cursor.fetchall()
        conn.close()
        
        members = []
        for row in rows:
            custom_perms = set(Permission(p) for p in json.loads(row['custom_permissions']))
            members.append(TeamMember(
                id=row['id'],
                team_id=row['team_id'],
                user_id=row['user_id'],
                role=Role(row['role']),
                custom_permissions=custom_perms,
                joined_at=row['joined_at'],
                invited_by=row['invited_by']
            ))
        return members
    
    def remove_member(self, team_id: str, user_id: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM team_members WHERE team_id = ? AND user_id = ?
        ''', (team_id, user_id))
        removed = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return removed
    
    # Session methods
    def save_session(self, session: Session) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.id, session.user_id, session.token, session.ip_address,
            session.user_agent, session.expires_at, session.created_at
        ))
        
        conn.commit()
        conn.close()
        return session.id
    
    def get_session(self, token: str) -> Optional[Session]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM sessions WHERE token = ?', (token,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return Session(**dict(row))
        return None
    
    def delete_session(self, token: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return deleted
    
    def cleanup_expired_sessions(self) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        cursor.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        return deleted
    
    # Invitation methods
    def save_invitation(self, invitation: Invitation) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO invitations (
                id, team_id, email, role, token, invited_by, expires_at, accepted_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            invitation.id, invitation.team_id, invitation.email, invitation.role.value,
            invitation.token, invitation.invited_by, invitation.expires_at,
            invitation.accepted_at, invitation.created_at
        ))
        
        conn.commit()
        conn.close()
        return invitation.id
    
    def get_invitation(self, token: str = None, invitation_id: str = None) -> Optional[Invitation]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if token:
            cursor.execute('SELECT * FROM invitations WHERE token = ?', (token,))
        elif invitation_id:
            cursor.execute('SELECT * FROM invitations WHERE id = ?', (invitation_id,))
        else:
            return None
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return Invitation(
                id=row['id'],
                team_id=row['team_id'],
                email=row['email'],
                role=Role(row['role']),
                token=row['token'],
                invited_by=row['invited_by'],
                expires_at=row['expires_at'],
                accepted_at=row['accepted_at'],
                created_at=row['created_at']
            )
        return None
    
    # Comment methods
    def save_comment(self, comment: Comment) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO comments (
                id, team_id, user_id, resource_type, resource_id, content,
                parent_id, is_edited, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            comment.id, comment.team_id, comment.user_id, comment.resource_type,
            comment.resource_id, comment.content, comment.parent_id,
            comment.is_edited, comment.created_at, comment.updated_at
        ))
        
        conn.commit()
        conn.close()
        return comment.id
    
    def list_comments(self, team_id: str, resource_type: str, resource_id: str) -> List[Comment]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM comments 
            WHERE team_id = ? AND resource_type = ? AND resource_id = ?
            ORDER BY created_at ASC
        ''', (team_id, resource_type, resource_id))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [Comment(**{**dict(row), 'is_edited': bool(row['is_edited'])}) for row in rows]
    
    # Task methods
    def save_task(self, task: Task) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO tasks (
                id, team_id, title, description, status, priority,
                created_by, assigned_to, resource_type, resource_id,
                due_date, completed_at, created_at, updated_at, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task.id, task.team_id, task.title, task.description,
            task.status.value, task.priority.value, task.created_by,
            task.assigned_to, task.resource_type, task.resource_id,
            task.due_date, task.completed_at, task.created_at,
            task.updated_at, json.dumps(task.tags)
        ))
        
        conn.commit()
        conn.close()
        return task.id
    
    def list_tasks(self, team_id: str, status: str = None, assigned_to: str = None) -> List[Task]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM tasks WHERE team_id = ?'
        params = [team_id]
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        if assigned_to:
            query += ' AND assigned_to = ?'
            params.append(assigned_to)
        
        query += ' ORDER BY CASE priority WHEN "critical" THEN 1 WHEN "high" THEN 2 WHEN "medium" THEN 3 ELSE 4 END, due_date ASC'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [Task(**{**dict(row), 'status': TaskStatus(row['status']),
                       'priority': TaskPriority(row['priority']),
                       'tags': json.loads(row['tags'])}) for row in rows]
    
    # Activity log methods
    def log_activity(self, activity: ActivityLog) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_log (
                id, team_id, user_id, activity_type, resource_type, resource_id,
                details, ip_address, user_agent, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            activity.id, activity.team_id, activity.user_id,
            activity.activity_type.value, activity.resource_type, activity.resource_id,
            json.dumps(activity.details), activity.ip_address, activity.user_agent,
            activity.created_at
        ))
        
        conn.commit()
        conn.close()
        return activity.id
    
    def get_activity_log(self, team_id: str, limit: int = 50, 
                         user_id: str = None, activity_type: str = None) -> List[ActivityLog]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM activity_log WHERE team_id = ?'
        params = [team_id]
        
        if user_id:
            query += ' AND user_id = ?'
            params.append(user_id)
        
        if activity_type:
            query += ' AND activity_type = ?'
            params.append(activity_type)
        
        query += ' ORDER BY created_at DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [ActivityLog(**{**dict(row), 
                              'activity_type': ActivityType(row['activity_type']),
                              'details': json.loads(row['details'])}) for row in rows]


# ============================================================================
# TEAM MANAGER
# ============================================================================

class TeamManager:
    """
    Main class for managing teams and collaboration.
    """
    
    def __init__(self, db_path: str = None):
        self.db = TeamDatabase(db_path)
    
    # Authentication
    def hash_password(self, password: str) -> str:
        """Hash a password"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{hash_obj.hex()}"
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash"""
        try:
            salt, hash_hex = password_hash.split(':')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hash_obj.hex() == hash_hex
        except:
            return False
    
    # User management
    def create_user(self, username: str, email: str, password: str, 
                    display_name: str = None) -> User:
        """Create a new user"""
        # Check if user exists
        if self.db.get_user(username=username):
            raise ValueError(f"Username '{username}' already exists")
        if self.db.get_user(email=email):
            raise ValueError(f"Email '{email}' already registered")
        
        user = User(
            id="",
            username=username,
            email=email,
            password_hash=self.hash_password(password),
            display_name=display_name or username
        )
        
        self.db.save_user(user)
        logger.info(f"Created user: {username}")
        
        return user
    
    def authenticate(self, username_or_email: str, password: str, 
                     ip_address: str = "", user_agent: str = "") -> Optional[Session]:
        """Authenticate user and create session"""
        user = self.db.get_user(username=username_or_email)
        if not user:
            user = self.db.get_user(email=username_or_email)
        
        if not user or not user.is_active:
            return None
        
        if not self.verify_password(password, user.password_hash):
            return None
        
        # Update last login
        user.last_login = datetime.now().isoformat()
        self.db.save_user(user)
        
        # Create session
        session = Session(
            id="",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.db.save_session(session)
        
        # Log activity
        self.db.log_activity(ActivityLog(
            id="",
            team_id="",
            user_id=user.id,
            activity_type=ActivityType.USER_LOGIN,
            ip_address=ip_address,
            user_agent=user_agent
        ))
        
        logger.info(f"User logged in: {user.username}")
        return session
    
    def logout(self, token: str) -> bool:
        """Logout user by invalidating session"""
        session = self.db.get_session(token)
        if session:
            self.db.log_activity(ActivityLog(
                id="",
                team_id="",
                user_id=session.user_id,
                activity_type=ActivityType.USER_LOGOUT
            ))
        return self.db.delete_session(token)
    
    def get_current_user(self, token: str) -> Optional[User]:
        """Get current user from session token"""
        session = self.db.get_session(token)
        if not session or session.is_expired:
            return None
        return self.db.get_user(user_id=session.user_id)
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.db.get_user(user_id=user_id)
    
    def update_user(self, user_id: str, **updates) -> Optional[User]:
        """Update user profile"""
        user = self.db.get_user(user_id=user_id)
        if not user:
            return None
        
        for key, value in updates.items():
            if hasattr(user, key) and key not in ['id', 'password_hash']:
                setattr(user, key, value)
        
        user.updated_at = datetime.now().isoformat()
        self.db.save_user(user)
        return user
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password"""
        user = self.db.get_user(user_id=user_id)
        if not user:
            return False
        
        if not self.verify_password(old_password, user.password_hash):
            return False
        
        user.password_hash = self.hash_password(new_password)
        user.updated_at = datetime.now().isoformat()
        self.db.save_user(user)
        
        logger.info(f"Password changed for user: {user.username}")
        return True
    
    # Team management
    def create_team(self, name: str, owner_id: str, description: str = "") -> Team:
        """Create a new team"""
        user = self.db.get_user(user_id=owner_id)
        if not user:
            raise ValueError("Owner user not found")
        
        team = Team(
            id="",
            name=name,
            description=description,
            owner_id=owner_id
        )
        
        self.db.save_team(team)
        
        # Add owner as member with owner role
        member = TeamMember(
            id="",
            team_id=team.id,
            user_id=owner_id,
            role=Role.OWNER
        )
        self.db.save_member(member)
        
        # Log activity
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team.id,
            user_id=owner_id,
            activity_type=ActivityType.TEAM_CREATED,
            details={"team_name": name}
        ))
        
        logger.info(f"Created team: {name}")
        return team
    
    def get_team(self, team_id: str) -> Optional[Team]:
        """Get team by ID"""
        return self.db.get_team(team_id=team_id)
    
    def list_user_teams(self, user_id: str) -> List[Team]:
        """List all teams a user belongs to"""
        return self.db.list_teams(user_id=user_id)
    
    def update_team(self, team_id: str, user_id: str, **updates) -> Optional[Team]:
        """Update team settings"""
        if not self.check_permission(team_id, user_id, Permission.EDIT_TEAM):
            raise PermissionError("Not authorized to edit team")
        
        team = self.db.get_team(team_id=team_id)
        if not team:
            return None
        
        for key, value in updates.items():
            if hasattr(team, key) and key not in ['id', 'owner_id']:
                setattr(team, key, value)
        
        team.updated_at = datetime.now().isoformat()
        self.db.save_team(team)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=user_id,
            activity_type=ActivityType.TEAM_UPDATED,
            details=updates
        ))
        
        return team
    
    def delete_team(self, team_id: str, user_id: str) -> bool:
        """Delete (deactivate) a team"""
        if not self.check_permission(team_id, user_id, Permission.DELETE_TEAM):
            raise PermissionError("Not authorized to delete team")
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=user_id,
            activity_type=ActivityType.TEAM_DELETED
        ))
        
        return self.db.delete_team(team_id)
    
    # Member management
    def add_member(self, team_id: str, user_id: str, role: Role, 
                   invited_by: str = "") -> TeamMember:
        """Add a member to a team"""
        if invited_by and not self.check_permission(team_id, invited_by, Permission.INVITE_MEMBERS):
            raise PermissionError("Not authorized to invite members")
        
        user = self.db.get_user(user_id=user_id)
        if not user:
            raise ValueError("User not found")
        
        # Check if already a member
        existing = self.db.get_member(team_id, user_id)
        if existing:
            raise ValueError("User is already a team member")
        
        member = TeamMember(
            id="",
            team_id=team_id,
            user_id=user_id,
            role=role,
            invited_by=invited_by
        )
        
        self.db.save_member(member)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=invited_by or user_id,
            activity_type=ActivityType.MEMBER_ADDED,
            details={"added_user_id": user_id, "role": role.value}
        ))
        
        logger.info(f"Added member {user_id} to team {team_id}")
        return member
    
    def remove_member(self, team_id: str, user_id: str, removed_by: str) -> bool:
        """Remove a member from a team"""
        if not self.check_permission(team_id, removed_by, Permission.REMOVE_MEMBERS):
            raise PermissionError("Not authorized to remove members")
        
        # Can't remove the owner
        team = self.db.get_team(team_id=team_id)
        if team and team.owner_id == user_id:
            raise ValueError("Cannot remove team owner")
        
        removed = self.db.remove_member(team_id, user_id)
        
        if removed:
            self.db.log_activity(ActivityLog(
                id="",
                team_id=team_id,
                user_id=removed_by,
                activity_type=ActivityType.MEMBER_REMOVED,
                details={"removed_user_id": user_id}
            ))
        
        return removed
    
    def change_member_role(self, team_id: str, user_id: str, new_role: Role, 
                           changed_by: str) -> Optional[TeamMember]:
        """Change a member's role"""
        if not self.check_permission(team_id, changed_by, Permission.EDIT_ROLES):
            raise PermissionError("Not authorized to change roles")
        
        member = self.db.get_member(team_id, user_id)
        if not member:
            return None
        
        # Can't change owner role
        if member.role == Role.OWNER:
            raise ValueError("Cannot change owner role")
        
        old_role = member.role
        member.role = new_role
        self.db.save_member(member)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=changed_by,
            activity_type=ActivityType.ROLE_CHANGED,
            details={"user_id": user_id, "old_role": old_role.value, "new_role": new_role.value}
        ))
        
        return member
    
    def list_members(self, team_id: str) -> List[Dict]:
        """List all team members with user info"""
        members = self.db.list_members(team_id)
        result = []
        
        for member in members:
            user = self.db.get_user(user_id=member.user_id)
            if user:
                result.append({
                    'member_id': member.id,
                    'user_id': member.user_id,
                    'username': user.username,
                    'display_name': user.display_name,
                    'email': user.email,
                    'avatar_url': user.avatar_url,
                    'role': member.role.value,
                    'joined_at': member.joined_at
                })
        
        return result
    
    # Invitation management
    def create_invitation(self, team_id: str, email: str, role: Role, 
                          invited_by: str) -> Invitation:
        """Create a team invitation"""
        if not self.check_permission(team_id, invited_by, Permission.INVITE_MEMBERS):
            raise PermissionError("Not authorized to invite members")
        
        # Check if user already exists and is a member
        existing_user = self.db.get_user(email=email)
        if existing_user:
            existing_member = self.db.get_member(team_id, existing_user.id)
            if existing_member:
                raise ValueError("User is already a team member")
        
        invitation = Invitation(
            id="",
            team_id=team_id,
            email=email,
            role=role,
            invited_by=invited_by
        )
        
        self.db.save_invitation(invitation)
        logger.info(f"Created invitation for {email} to team {team_id}")
        
        return invitation
    
    def accept_invitation(self, token: str, user_id: str) -> Optional[TeamMember]:
        """Accept a team invitation"""
        invitation = self.db.get_invitation(token=token)
        
        if not invitation:
            raise ValueError("Invitation not found")
        
        if invitation.is_expired:
            raise ValueError("Invitation has expired")
        
        if invitation.is_accepted:
            raise ValueError("Invitation already accepted")
        
        user = self.db.get_user(user_id=user_id)
        if not user or user.email != invitation.email:
            raise ValueError("Invitation email doesn't match user")
        
        # Add as member
        member = self.add_member(
            team_id=invitation.team_id,
            user_id=user_id,
            role=invitation.role,
            invited_by=invitation.invited_by
        )
        
        # Mark invitation as accepted
        invitation.accepted_at = datetime.now().isoformat()
        # Update in DB (would need an update method)
        
        return member
    
    # Permission checking
    def check_permission(self, team_id: str, user_id: str, permission: Permission) -> bool:
        """Check if user has a specific permission in a team"""
        member = self.db.get_member(team_id, user_id)
        if not member:
            return False
        return member.has_permission(permission)
    
    def get_user_permissions(self, team_id: str, user_id: str) -> Set[Permission]:
        """Get all permissions for a user in a team"""
        member = self.db.get_member(team_id, user_id)
        if not member:
            return set()
        
        role_perms = ROLE_PERMISSIONS.get(member.role, set())
        return role_perms | member.custom_permissions
    
    # Comments
    def add_comment(self, team_id: str, user_id: str, resource_type: str,
                    resource_id: str, content: str, parent_id: str = "") -> Comment:
        """Add a comment to a resource"""
        if not self.check_permission(team_id, user_id, Permission.CREATE_COMMENTS):
            raise PermissionError("Not authorized to add comments")
        
        comment = Comment(
            id="",
            team_id=team_id,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            content=content,
            parent_id=parent_id
        )
        
        self.db.save_comment(comment)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=user_id,
            activity_type=ActivityType.COMMENT_ADDED,
            resource_type=resource_type,
            resource_id=resource_id
        ))
        
        return comment
    
    def list_comments(self, team_id: str, user_id: str, resource_type: str,
                      resource_id: str) -> List[Dict]:
        """List comments on a resource with user info"""
        if not self.check_permission(team_id, user_id, Permission.VIEW_COMMENTS):
            raise PermissionError("Not authorized to view comments")
        
        comments = self.db.list_comments(team_id, resource_type, resource_id)
        result = []
        
        for comment in comments:
            user = self.db.get_user(user_id=comment.user_id)
            result.append({
                **asdict(comment),
                'username': user.username if user else 'Unknown',
                'display_name': user.display_name if user else 'Unknown',
                'avatar_url': user.avatar_url if user else ''
            })
        
        return result
    
    # Tasks
    def create_task(self, team_id: str, user_id: str, title: str,
                    description: str = "", priority: TaskPriority = TaskPriority.MEDIUM,
                    assigned_to: str = "", due_date: str = "",
                    resource_type: str = "", resource_id: str = "",
                    tags: List[str] = None) -> Task:
        """Create a task"""
        if not self.check_permission(team_id, user_id, Permission.CREATE_TASKS):
            raise PermissionError("Not authorized to create tasks")
        
        task = Task(
            id="",
            team_id=team_id,
            title=title,
            description=description,
            priority=priority,
            created_by=user_id,
            assigned_to=assigned_to,
            due_date=due_date,
            resource_type=resource_type,
            resource_id=resource_id,
            tags=tags or []
        )
        
        self.db.save_task(task)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=user_id,
            activity_type=ActivityType.TASK_CREATED,
            details={"task_id": task.id, "title": title}
        ))
        
        return task
    
    def assign_task(self, team_id: str, user_id: str, task_id: str, 
                    assignee_id: str) -> Optional[Task]:
        """Assign a task to a user"""
        if not self.check_permission(team_id, user_id, Permission.ASSIGN_TASKS):
            raise PermissionError("Not authorized to assign tasks")
        
        tasks = self.db.list_tasks(team_id)
        task = next((t for t in tasks if t.id == task_id), None)
        
        if not task:
            return None
        
        task.assigned_to = assignee_id
        task.updated_at = datetime.now().isoformat()
        self.db.save_task(task)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=user_id,
            activity_type=ActivityType.TASK_ASSIGNED,
            details={"task_id": task_id, "assignee_id": assignee_id}
        ))
        
        return task
    
    def complete_task(self, team_id: str, user_id: str, task_id: str) -> Optional[Task]:
        """Mark a task as completed"""
        if not self.check_permission(team_id, user_id, Permission.COMPLETE_TASKS):
            raise PermissionError("Not authorized to complete tasks")
        
        tasks = self.db.list_tasks(team_id)
        task = next((t for t in tasks if t.id == task_id), None)
        
        if not task:
            return None
        
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now().isoformat()
        task.updated_at = datetime.now().isoformat()
        self.db.save_task(task)
        
        self.db.log_activity(ActivityLog(
            id="",
            team_id=team_id,
            user_id=user_id,
            activity_type=ActivityType.TASK_COMPLETED,
            details={"task_id": task_id}
        ))
        
        return task
    
    def list_tasks(self, team_id: str, user_id: str, status: str = None,
                   assigned_to: str = None) -> List[Task]:
        """List tasks"""
        if not self.check_permission(team_id, user_id, Permission.VIEW_TASKS):
            raise PermissionError("Not authorized to view tasks")
        
        return self.db.list_tasks(team_id, status=status, assigned_to=assigned_to)
    
    # Activity log
    def get_activity_log(self, team_id: str, user_id: str, limit: int = 50,
                         filter_user_id: str = None, 
                         activity_type: str = None) -> List[Dict]:
        """Get team activity log"""
        if not self.check_permission(team_id, user_id, Permission.VIEW_TEAM):
            raise PermissionError("Not authorized to view activity")
        
        activities = self.db.get_activity_log(
            team_id, limit=limit, 
            user_id=filter_user_id, 
            activity_type=activity_type
        )
        
        result = []
        for activity in activities:
            user = self.db.get_user(user_id=activity.user_id) if activity.user_id else None
            result.append({
                **asdict(activity),
                'activity_type': activity.activity_type.value,
                'username': user.username if user else 'System',
                'display_name': user.display_name if user else 'System'
            })
        
        return result


# ============================================================================
# FASTAPI INTEGRATION
# ============================================================================

def create_team_routes(app):
    """
    Add team collaboration routes to FastAPI app.
    
    Usage in api_server.py:
        from team_collaboration import create_team_routes
        create_team_routes(app)
    """
    from fastapi import APIRouter, HTTPException, Depends, Header
    from pydantic import BaseModel, EmailStr
    from typing import Optional, List
    
    router = APIRouter(prefix="/team", tags=["Team Collaboration"])
    manager = TeamManager()
    
    # Pydantic models
    class UserCreate(BaseModel):
        username: str
        email: EmailStr
        password: str
        display_name: Optional[str] = None
    
    class UserLogin(BaseModel):
        username_or_email: str
        password: str
    
    class TeamCreate(BaseModel):
        name: str
        description: Optional[str] = ""
    
    class MemberAdd(BaseModel):
        user_id: str
        role: str
    
    class InvitationCreate(BaseModel):
        email: EmailStr
        role: str
    
    class CommentCreate(BaseModel):
        resource_type: str
        resource_id: str
        content: str
        parent_id: Optional[str] = ""
    
    class TaskCreate(BaseModel):
        title: str
        description: Optional[str] = ""
        priority: Optional[str] = "medium"
        assigned_to: Optional[str] = ""
        due_date: Optional[str] = ""
        tags: Optional[List[str]] = []
    
    # Auth dependency
    async def get_current_user(authorization: str = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        token = authorization.replace("Bearer ", "")
        user = manager.get_current_user(token)
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        return user
    
    # Auth endpoints
    @router.post("/auth/register")
    async def register(data: UserCreate):
        """Register a new user"""
        try:
            user = manager.create_user(
                username=data.username,
                email=data.email,
                password=data.password,
                display_name=data.display_name
            )
            return user.to_dict()
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/auth/login")
    async def login(data: UserLogin):
        """Login and get session token"""
        session = manager.authenticate(data.username_or_email, data.password)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"token": session.token, "expires_at": session.expires_at}
    
    @router.post("/auth/logout")
    async def logout(user: User = Depends(get_current_user), 
                     authorization: str = Header(None)):
        """Logout current session"""
        token = authorization.replace("Bearer ", "")
        manager.logout(token)
        return {"message": "Logged out"}
    
    @router.get("/auth/me")
    async def get_me(user: User = Depends(get_current_user)):
        """Get current user profile"""
        return user.to_dict()
    
    # Team endpoints
    @router.post("/teams")
    async def create_team(data: TeamCreate, user: User = Depends(get_current_user)):
        """Create a new team"""
        team = manager.create_team(
            name=data.name,
            owner_id=user.id,
            description=data.description
        )
        return asdict(team)
    
    @router.get("/teams")
    async def list_teams(user: User = Depends(get_current_user)):
        """List user's teams"""
        teams = manager.list_user_teams(user.id)
        return [asdict(t) for t in teams]
    
    @router.get("/teams/{team_id}")
    async def get_team(team_id: str, user: User = Depends(get_current_user)):
        """Get team details"""
        team = manager.get_team(team_id)
        if not team:
            raise HTTPException(status_code=404, detail="Team not found")
        return asdict(team)
    
    @router.get("/teams/{team_id}/members")
    async def list_members(team_id: str, user: User = Depends(get_current_user)):
        """List team members"""
        return manager.list_members(team_id)
    
    @router.post("/teams/{team_id}/members")
    async def add_member(team_id: str, data: MemberAdd, 
                         user: User = Depends(get_current_user)):
        """Add a team member"""
        try:
            member = manager.add_member(
                team_id=team_id,
                user_id=data.user_id,
                role=Role(data.role),
                invited_by=user.id
            )
            return {"member_id": member.id}
        except (ValueError, PermissionError) as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.delete("/teams/{team_id}/members/{user_id}")
    async def remove_member(team_id: str, user_id: str,
                           user: User = Depends(get_current_user)):
        """Remove a team member"""
        try:
            if manager.remove_member(team_id, user_id, user.id):
                return {"removed": True}
            raise HTTPException(status_code=404, detail="Member not found")
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    # Invitation endpoints
    @router.post("/teams/{team_id}/invitations")
    async def create_invitation(team_id: str, data: InvitationCreate,
                                user: User = Depends(get_current_user)):
        """Create team invitation"""
        try:
            invitation = manager.create_invitation(
                team_id=team_id,
                email=data.email,
                role=Role(data.role),
                invited_by=user.id
            )
            return {"invitation_id": invitation.id, "token": invitation.token}
        except (ValueError, PermissionError) as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    # Comment endpoints
    @router.post("/teams/{team_id}/comments")
    async def add_comment(team_id: str, data: CommentCreate,
                          user: User = Depends(get_current_user)):
        """Add a comment"""
        try:
            comment = manager.add_comment(
                team_id=team_id,
                user_id=user.id,
                resource_type=data.resource_type,
                resource_id=data.resource_id,
                content=data.content,
                parent_id=data.parent_id
            )
            return {"comment_id": comment.id}
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    @router.get("/teams/{team_id}/comments/{resource_type}/{resource_id}")
    async def list_comments(team_id: str, resource_type: str, resource_id: str,
                           user: User = Depends(get_current_user)):
        """List comments on a resource"""
        try:
            return manager.list_comments(team_id, user.id, resource_type, resource_id)
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    # Task endpoints
    @router.post("/teams/{team_id}/tasks")
    async def create_task(team_id: str, data: TaskCreate,
                          user: User = Depends(get_current_user)):
        """Create a task"""
        try:
            task = manager.create_task(
                team_id=team_id,
                user_id=user.id,
                title=data.title,
                description=data.description,
                priority=TaskPriority(data.priority),
                assigned_to=data.assigned_to,
                due_date=data.due_date,
                tags=data.tags
            )
            return asdict(task)
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    @router.get("/teams/{team_id}/tasks")
    async def list_tasks(team_id: str, status: str = None, assigned_to: str = None,
                        user: User = Depends(get_current_user)):
        """List tasks"""
        try:
            tasks = manager.list_tasks(team_id, user.id, status=status, assigned_to=assigned_to)
            return [asdict(t) for t in tasks]
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    @router.post("/teams/{team_id}/tasks/{task_id}/complete")
    async def complete_task(team_id: str, task_id: str,
                           user: User = Depends(get_current_user)):
        """Complete a task"""
        try:
            task = manager.complete_task(team_id, user.id, task_id)
            if not task:
                raise HTTPException(status_code=404, detail="Task not found")
            return asdict(task)
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    # Activity log
    @router.get("/teams/{team_id}/activity")
    async def get_activity(team_id: str, limit: int = 50,
                          user: User = Depends(get_current_user)):
        """Get team activity log"""
        try:
            return manager.get_activity_log(team_id, user.id, limit=limit)
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
    
    app.include_router(router)
    return router, manager


# ============================================================================
# CLI INTERFACE
# ============================================================================

def cli_main():
    """CLI interface"""
    import argparse
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           KALI-GPT TEAM COLLABORATION v4.1                       ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Manage teams, users, and collaboration features.                ║
║                                                                  ║
║  Commands:                                                       ║
║    user create  - Create a new user                              ║
║    user list    - List all users                                 ║
║    team create  - Create a new team                              ║
║    team list    - List teams for a user                          ║
║    member add   - Add member to team                             ║
║    member list  - List team members                              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    parser = argparse.ArgumentParser(description="Kali-GPT Team Collaboration")
    subparsers = parser.add_subparsers(dest="command")
    
    # User commands
    user_parser = subparsers.add_parser("user")
    user_sub = user_parser.add_subparsers(dest="action")
    
    user_create = user_sub.add_parser("create")
    user_create.add_argument("--username", required=True)
    user_create.add_argument("--email", required=True)
    user_create.add_argument("--password", required=True)
    
    user_list = user_sub.add_parser("list")
    
    # Team commands
    team_parser = subparsers.add_parser("team")
    team_sub = team_parser.add_subparsers(dest="action")
    
    team_create = team_sub.add_parser("create")
    team_create.add_argument("--name", required=True)
    team_create.add_argument("--owner", required=True, help="Owner user ID")
    
    team_list = team_sub.add_parser("list")
    team_list.add_argument("--user", help="User ID")
    
    # Member commands
    member_parser = subparsers.add_parser("member")
    member_sub = member_parser.add_subparsers(dest="action")
    
    member_add = member_sub.add_parser("add")
    member_add.add_argument("--team", required=True)
    member_add.add_argument("--user", required=True)
    member_add.add_argument("--role", default="analyst", 
                           choices=["viewer", "analyst", "operator", "admin"])
    
    member_list = member_sub.add_parser("list")
    member_list.add_argument("--team", required=True)
    
    args = parser.parse_args()
    manager = TeamManager()
    
    if args.command == "user":
        if args.action == "create":
            try:
                user = manager.create_user(args.username, args.email, args.password)
                print(f"✓ Created user: {user.username} (ID: {user.id})")
            except ValueError as e:
                print(f"✗ Error: {e}")
        
        elif args.action == "list":
            users = manager.db.list_users()
            print(f"{'ID':<14} {'Username':<20} {'Email':<30} {'Active':<8}")
            print("-" * 75)
            for u in users:
                status = "Yes" if u.is_active else "No"
                print(f"{u.id:<14} {u.username:<20} {u.email:<30} {status:<8}")
    
    elif args.command == "team":
        if args.action == "create":
            try:
                team = manager.create_team(args.name, args.owner)
                print(f"✓ Created team: {team.name} (ID: {team.id})")
            except ValueError as e:
                print(f"✗ Error: {e}")
        
        elif args.action == "list":
            teams = manager.list_user_teams(args.user) if args.user else manager.db.list_teams()
            print(f"{'ID':<14} {'Name':<25} {'Owner':<14}")
            print("-" * 55)
            for t in teams:
                print(f"{t.id:<14} {t.name:<25} {t.owner_id:<14}")
    
    elif args.command == "member":
        if args.action == "add":
            try:
                member = manager.add_member(args.team, args.user, Role(args.role))
                print(f"✓ Added member (ID: {member.id})")
            except (ValueError, PermissionError) as e:
                print(f"✗ Error: {e}")
        
        elif args.action == "list":
            members = manager.list_members(args.team)
            print(f"{'User ID':<14} {'Username':<20} {'Role':<12} {'Joined':<20}")
            print("-" * 70)
            for m in members:
                print(f"{m['user_id']:<14} {m['username']:<20} {m['role']:<12} {m['joined_at'][:19]:<20}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_main()
