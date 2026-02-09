#!/usr/bin/env python3
"""
Kali-GPT v4.1 - Scheduled Scans Module

Features:
- Cron-like scheduling for recurring scans
- One-time scheduled scans
- Scan templates for quick setup
- Email/Slack notifications on completion
- Scan windows (only run during specific hours)
- Priority queuing
- Automatic retry on failure

Usage:
    from scan_scheduler import ScanScheduler
    
    scheduler = ScanScheduler(api_url="http://localhost:8000")
    scheduler.add_recurring_scan(
        target_id="abc123",
        scan_type="standard",
        cron="0 2 * * *"  # Daily at 2 AM
    )
    scheduler.start()
"""

import os
import sys
import json
import time
import uuid
import sqlite3
import asyncio
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests not installed. API integration disabled.")

try:
    from croniter import croniter
    CRONITER_AVAILABLE = True
except ImportError:
    CRONITER_AVAILABLE = False
    logger.warning("croniter not installed. Using basic scheduling only.")


class ScheduleType(Enum):
    """Types of schedules"""
    ONCE = "once"           # Run once at specified time
    RECURRING = "recurring"  # Run on cron schedule
    INTERVAL = "interval"    # Run every N minutes/hours


class ScheduleStatus(Enum):
    """Status of a scheduled scan"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class NotificationType(Enum):
    """Notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    DISCORD = "discord"


@dataclass
class ScanWindow:
    """Define when scans are allowed to run"""
    start_hour: int = 0      # 0-23
    end_hour: int = 24       # 0-24 (24 = midnight)
    days_of_week: List[int] = field(default_factory=lambda: [0,1,2,3,4,5,6])  # 0=Mon, 6=Sun
    timezone: str = "UTC"
    
    def is_allowed_now(self) -> bool:
        """Check if current time is within the scan window"""
        now = datetime.now()
        current_hour = now.hour
        current_day = now.weekday()
        
        if current_day not in self.days_of_week:
            return False
        
        if self.end_hour > self.start_hour:
            return self.start_hour <= current_hour < self.end_hour
        else:
            # Handles overnight windows (e.g., 22:00 - 06:00)
            return current_hour >= self.start_hour or current_hour < self.end_hour


@dataclass
class NotificationConfig:
    """Configuration for notifications"""
    type: NotificationType
    enabled: bool = True
    on_start: bool = False
    on_complete: bool = True
    on_failure: bool = True
    on_findings: bool = True  # Notify if critical findings
    config: Dict = field(default_factory=dict)
    # config examples:
    # email: {"to": "admin@example.com", "smtp_server": "...", "smtp_port": 587}
    # slack: {"webhook_url": "https://hooks.slack.com/..."}
    # webhook: {"url": "https://...", "headers": {}}
    # discord: {"webhook_url": "https://discord.com/api/webhooks/..."}


@dataclass
class ScheduledScan:
    """Represents a scheduled scan job"""
    id: str
    name: str
    target_id: str
    scan_type: str
    schedule_type: ScheduleType
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    
    # Scheduling options
    cron_expression: str = ""          # For recurring: "0 2 * * *"
    interval_minutes: int = 0          # For interval: run every N minutes
    scheduled_time: str = ""           # For once: ISO datetime
    
    # Execution tracking
    last_run: str = ""
    next_run: str = ""
    run_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    last_scan_id: str = ""
    last_error: str = ""
    
    # Options
    priority: int = 5                  # 1-10, higher = more important
    max_retries: int = 3
    retry_delay_minutes: int = 15
    scan_options: Dict = field(default_factory=dict)
    scan_window: Optional[ScanWindow] = None
    notifications: List[NotificationConfig] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: str = ""
    updated_at: str = ""
    created_by: str = ""
    description: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
        
        # Calculate next run time
        if not self.next_run:
            self._calculate_next_run()
    
    def _calculate_next_run(self):
        """Calculate the next run time based on schedule type"""
        now = datetime.now()
        
        if self.schedule_type == ScheduleType.ONCE:
            if self.scheduled_time:
                self.next_run = self.scheduled_time
        
        elif self.schedule_type == ScheduleType.INTERVAL:
            if self.last_run:
                last = datetime.fromisoformat(self.last_run)
                next_time = last + timedelta(minutes=self.interval_minutes)
            else:
                next_time = now + timedelta(minutes=self.interval_minutes)
            self.next_run = next_time.isoformat()
        
        elif self.schedule_type == ScheduleType.RECURRING:
            if CRONITER_AVAILABLE and self.cron_expression:
                try:
                    cron = croniter(self.cron_expression, now)
                    next_time = cron.get_next(datetime)
                    self.next_run = next_time.isoformat()
                except Exception as e:
                    logger.error(f"Invalid cron expression: {e}")
            else:
                # Fallback: daily at midnight
                tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                self.next_run = tomorrow.isoformat()
    
    def should_run_now(self) -> bool:
        """Check if this scan should run now"""
        if self.status != ScheduleStatus.ACTIVE:
            return False
        
        if not self.next_run:
            return False
        
        now = datetime.now()
        next_run = datetime.fromisoformat(self.next_run)
        
        if now < next_run:
            return False
        
        # Check scan window
        if self.scan_window and not self.scan_window.is_allowed_now():
            return False
        
        return True
    
    def mark_started(self):
        """Mark the scan as started"""
        self.last_run = datetime.now().isoformat()
        self.run_count += 1
        self.updated_at = datetime.now().isoformat()
    
    def mark_completed(self, scan_id: str):
        """Mark the scan as completed"""
        self.last_scan_id = scan_id
        self.success_count += 1
        self.last_error = ""
        self.updated_at = datetime.now().isoformat()
        
        if self.schedule_type == ScheduleType.ONCE:
            self.status = ScheduleStatus.COMPLETED
        else:
            self._calculate_next_run()
    
    def mark_failed(self, error: str):
        """Mark the scan as failed"""
        self.failure_count += 1
        self.last_error = error
        self.updated_at = datetime.now().isoformat()
        
        if self.schedule_type == ScheduleType.ONCE:
            if self.failure_count >= self.max_retries:
                self.status = ScheduleStatus.FAILED
            else:
                # Schedule retry
                retry_time = datetime.now() + timedelta(minutes=self.retry_delay_minutes)
                self.next_run = retry_time.isoformat()
        else:
            self._calculate_next_run()


@dataclass
class ScanTemplate:
    """Predefined scan configuration template"""
    id: str
    name: str
    description: str
    scan_type: str
    scan_options: Dict = field(default_factory=dict)
    default_cron: str = ""
    default_notifications: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


# Built-in templates
SCAN_TEMPLATES = [
    ScanTemplate(
        id="daily-quick",
        name="Daily Quick Scan",
        description="Fast daily reconnaissance scan",
        scan_type="quick",
        default_cron="0 6 * * *",  # 6 AM daily
        tags=["daily", "quick"]
    ),
    ScanTemplate(
        id="weekly-full",
        name="Weekly Full Scan",
        description="Comprehensive weekly security assessment",
        scan_type="full",
        default_cron="0 2 * * 0",  # 2 AM Sunday
        tags=["weekly", "comprehensive"]
    ),
    ScanTemplate(
        id="monthly-compliance",
        name="Monthly Compliance Scan",
        description="Monthly compliance and vulnerability check",
        scan_type="full",
        scan_options={"compliance_check": True},
        default_cron="0 3 1 * *",  # 3 AM, 1st of month
        tags=["monthly", "compliance"]
    ),
    ScanTemplate(
        id="continuous-monitor",
        name="Continuous Monitoring",
        description="Frequent lightweight monitoring scan",
        scan_type="quick",
        default_cron="0 */4 * * *",  # Every 4 hours
        tags=["continuous", "monitoring"]
    ),
    ScanTemplate(
        id="nightly-web",
        name="Nightly Web App Scan",
        description="Web application security scan during off-hours",
        scan_type="web",
        default_cron="0 1 * * 1-5",  # 1 AM Mon-Fri
        tags=["nightly", "web"]
    ),
]


class SchedulerDatabase:
    """SQLite database for persistent schedule storage"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            data_dir = Path.home() / ".kali-gpt"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "scheduler.db")
        
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target_id TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                schedule_type TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                cron_expression TEXT DEFAULT '',
                interval_minutes INTEGER DEFAULT 0,
                scheduled_time TEXT DEFAULT '',
                last_run TEXT DEFAULT '',
                next_run TEXT DEFAULT '',
                run_count INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                last_scan_id TEXT DEFAULT '',
                last_error TEXT DEFAULT '',
                priority INTEGER DEFAULT 5,
                max_retries INTEGER DEFAULT 3,
                retry_delay_minutes INTEGER DEFAULT 15,
                scan_options TEXT DEFAULT '{}',
                scan_window TEXT DEFAULT '',
                notifications TEXT DEFAULT '[]',
                tags TEXT DEFAULT '[]',
                created_at TEXT,
                updated_at TEXT,
                created_by TEXT DEFAULT '',
                description TEXT DEFAULT ''
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                schedule_id TEXT NOT NULL,
                scan_id TEXT,
                started_at TEXT,
                completed_at TEXT,
                status TEXT,
                findings_count INTEGER DEFAULT 0,
                error TEXT DEFAULT '',
                FOREIGN KEY (schedule_id) REFERENCES scheduled_scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scheduled_scans_status 
            ON scheduled_scans(status)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run 
            ON scheduled_scans(next_run)
        ''')
        
        conn.commit()
        conn.close()
    
    def save_schedule(self, schedule: ScheduledScan) -> str:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scheduled_scans (
                id, name, target_id, scan_type, schedule_type, status,
                cron_expression, interval_minutes, scheduled_time,
                last_run, next_run, run_count, success_count, failure_count,
                last_scan_id, last_error, priority, max_retries, retry_delay_minutes,
                scan_options, scan_window, notifications, tags,
                created_at, updated_at, created_by, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            schedule.id,
            schedule.name,
            schedule.target_id,
            schedule.scan_type,
            schedule.schedule_type.value,
            schedule.status.value,
            schedule.cron_expression,
            schedule.interval_minutes,
            schedule.scheduled_time,
            schedule.last_run,
            schedule.next_run,
            schedule.run_count,
            schedule.success_count,
            schedule.failure_count,
            schedule.last_scan_id,
            schedule.last_error,
            schedule.priority,
            schedule.max_retries,
            schedule.retry_delay_minutes,
            json.dumps(schedule.scan_options),
            json.dumps(asdict(schedule.scan_window)) if schedule.scan_window else '',
            json.dumps([asdict(n) if hasattr(n, '__dataclass_fields__') else n for n in schedule.notifications]),
            json.dumps(schedule.tags),
            schedule.created_at,
            schedule.updated_at,
            schedule.created_by,
            schedule.description
        ))
        
        conn.commit()
        conn.close()
        return schedule.id
    
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scheduled_scans WHERE id = ?', (schedule_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_schedule(row)
        return None
    
    def list_schedules(self, status: str = None, target_id: str = None) -> List[ScheduledScan]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM scheduled_scans WHERE 1=1'
        params = []
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        if target_id:
            query += ' AND target_id = ?'
            params.append(target_id)
        
        query += ' ORDER BY priority DESC, next_run ASC'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_schedule(row) for row in rows]
    
    def get_due_schedules(self) -> List[ScheduledScan]:
        """Get all schedules that are due to run"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        cursor.execute('''
            SELECT * FROM scheduled_scans 
            WHERE status = 'active' AND next_run <= ?
            ORDER BY priority DESC, next_run ASC
        ''', (now,))
        
        rows = cursor.fetchall()
        conn.close()
        
        schedules = []
        for row in rows:
            schedule = self._row_to_schedule(row)
            if schedule.should_run_now():
                schedules.append(schedule)
        
        return schedules
    
    def delete_schedule(self, schedule_id: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM scheduled_scans WHERE id = ?', (schedule_id,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        return deleted
    
    def add_history(self, schedule_id: str, scan_id: str, status: str, 
                    findings_count: int = 0, error: str = ""):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        history_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO scan_history (
                id, schedule_id, scan_id, started_at, completed_at, 
                status, findings_count, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (history_id, schedule_id, scan_id, now, now, status, findings_count, error))
        
        conn.commit()
        conn.close()
    
    def get_history(self, schedule_id: str, limit: int = 10) -> List[Dict]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scan_history 
            WHERE schedule_id = ?
            ORDER BY started_at DESC
            LIMIT ?
        ''', (schedule_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def _row_to_schedule(self, row) -> ScheduledScan:
        """Convert database row to ScheduledScan object"""
        scan_window = None
        if row['scan_window']:
            try:
                sw_data = json.loads(row['scan_window'])
                scan_window = ScanWindow(**sw_data)
            except:
                pass
        
        notifications = []
        try:
            notif_data = json.loads(row['notifications'])
            for n in notif_data:
                if isinstance(n, dict):
                    n['type'] = NotificationType(n['type']) if isinstance(n['type'], str) else n['type']
                    notifications.append(NotificationConfig(**n))
        except:
            pass
        
        return ScheduledScan(
            id=row['id'],
            name=row['name'],
            target_id=row['target_id'],
            scan_type=row['scan_type'],
            schedule_type=ScheduleType(row['schedule_type']),
            status=ScheduleStatus(row['status']),
            cron_expression=row['cron_expression'],
            interval_minutes=row['interval_minutes'],
            scheduled_time=row['scheduled_time'],
            last_run=row['last_run'],
            next_run=row['next_run'],
            run_count=row['run_count'],
            success_count=row['success_count'],
            failure_count=row['failure_count'],
            last_scan_id=row['last_scan_id'],
            last_error=row['last_error'],
            priority=row['priority'],
            max_retries=row['max_retries'],
            retry_delay_minutes=row['retry_delay_minutes'],
            scan_options=json.loads(row['scan_options']),
            scan_window=scan_window,
            notifications=notifications,
            tags=json.loads(row['tags']),
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            created_by=row['created_by'],
            description=row['description']
        )


class NotificationManager:
    """Handle sending notifications"""
    
    @staticmethod
    def send(config: NotificationConfig, subject: str, message: str, data: Dict = None):
        """Send notification based on config type"""
        if not config.enabled:
            return
        
        try:
            if config.type == NotificationType.EMAIL:
                NotificationManager._send_email(config.config, subject, message)
            elif config.type == NotificationType.SLACK:
                NotificationManager._send_slack(config.config, subject, message, data)
            elif config.type == NotificationType.DISCORD:
                NotificationManager._send_discord(config.config, subject, message, data)
            elif config.type == NotificationType.WEBHOOK:
                NotificationManager._send_webhook(config.config, subject, message, data)
        except Exception as e:
            logger.error(f"Failed to send {config.type.value} notification: {e}")
    
    @staticmethod
    def _send_email(config: Dict, subject: str, message: str):
        """Send email notification"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            
            msg = MIMEText(message)
            msg['Subject'] = f"[Kali-GPT] {subject}"
            msg['From'] = config.get('from', 'kali-gpt@localhost')
            msg['To'] = config.get('to', '')
            
            server = smtplib.SMTP(
                config.get('smtp_server', 'localhost'),
                config.get('smtp_port', 25)
            )
            
            if config.get('smtp_user'):
                server.login(config['smtp_user'], config.get('smtp_pass', ''))
            
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            server.quit()
            
            logger.info(f"Email sent to {msg['To']}")
        except Exception as e:
            logger.error(f"Email failed: {e}")
    
    @staticmethod
    def _send_slack(config: Dict, subject: str, message: str, data: Dict = None):
        """Send Slack notification"""
        if not REQUESTS_AVAILABLE:
            return
        
        webhook_url = config.get('webhook_url', '')
        if not webhook_url:
            return
        
        # Build Slack message with blocks
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🔍 {subject}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message}
            }
        ]
        
        if data:
            fields = []
            if 'target' in data:
                fields.append({"type": "mrkdwn", "text": f"*Target:* {data['target']}"})
            if 'scan_type' in data:
                fields.append({"type": "mrkdwn", "text": f"*Type:* {data['scan_type']}"})
            if 'findings' in data:
                fields.append({"type": "mrkdwn", "text": f"*Findings:* {data['findings']}"})
            if 'duration' in data:
                fields.append({"type": "mrkdwn", "text": f"*Duration:* {data['duration']}"})
            
            if fields:
                blocks.append({
                    "type": "section",
                    "fields": fields
                })
        
        payload = {"blocks": blocks}
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Slack notification sent")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
    
    @staticmethod
    def _send_discord(config: Dict, subject: str, message: str, data: Dict = None):
        """Send Discord notification"""
        if not REQUESTS_AVAILABLE:
            return
        
        webhook_url = config.get('webhook_url', '')
        if not webhook_url:
            return
        
        # Build Discord embed
        embed = {
            "title": f"🔍 {subject}",
            "description": message,
            "color": 3447003,  # Blue
            "timestamp": datetime.now().isoformat(),
            "footer": {"text": "Kali-GPT Scanner"}
        }
        
        if data:
            fields = []
            if 'target' in data:
                fields.append({"name": "Target", "value": data['target'], "inline": True})
            if 'scan_type' in data:
                fields.append({"name": "Type", "value": data['scan_type'], "inline": True})
            if 'findings' in data:
                fields.append({"name": "Findings", "value": str(data['findings']), "inline": True})
            
            if fields:
                embed['fields'] = fields
        
        payload = {"embeds": [embed]}
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Discord notification sent")
        except Exception as e:
            logger.error(f"Discord notification failed: {e}")
    
    @staticmethod
    def _send_webhook(config: Dict, subject: str, message: str, data: Dict = None):
        """Send generic webhook notification"""
        if not REQUESTS_AVAILABLE:
            return
        
        url = config.get('url', '')
        if not url:
            return
        
        payload = {
            "event": "scan_notification",
            "subject": subject,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "data": data or {}
        }
        
        headers = config.get('headers', {})
        headers['Content-Type'] = 'application/json'
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            logger.info("Webhook notification sent")
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")


class ScanScheduler:
    """
    Main scheduler class that manages scheduled scans.
    
    Features:
    - Add/remove/update scheduled scans
    - Execute scans via API
    - Send notifications
    - Background scheduler loop
    """
    
    def __init__(self, api_url: str = "http://localhost:8000", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key or os.getenv('KALI_GPT_API_KEY', '')
        self.db = SchedulerDatabase()
        self.running = False
        self._thread = None
        self._check_interval = 60  # Check every 60 seconds
    
    def add_schedule(self, 
                     name: str,
                     target_id: str,
                     scan_type: str,
                     schedule_type: ScheduleType,
                     cron: str = "",
                     interval_minutes: int = 0,
                     scheduled_time: str = "",
                     priority: int = 5,
                     scan_options: Dict = None,
                     scan_window: ScanWindow = None,
                     notifications: List[NotificationConfig] = None,
                     description: str = "") -> ScheduledScan:
        """Add a new scheduled scan"""
        
        schedule = ScheduledScan(
            id="",
            name=name,
            target_id=target_id,
            scan_type=scan_type,
            schedule_type=schedule_type,
            cron_expression=cron,
            interval_minutes=interval_minutes,
            scheduled_time=scheduled_time,
            priority=priority,
            scan_options=scan_options or {},
            scan_window=scan_window,
            notifications=notifications or [],
            description=description
        )
        
        self.db.save_schedule(schedule)
        logger.info(f"Added schedule: {schedule.name} (ID: {schedule.id})")
        
        return schedule
    
    def add_recurring_scan(self, target_id: str, scan_type: str, cron: str,
                          name: str = None, **kwargs) -> ScheduledScan:
        """Convenience method to add a recurring scan"""
        if not name:
            name = f"Recurring {scan_type} scan"
        
        return self.add_schedule(
            name=name,
            target_id=target_id,
            scan_type=scan_type,
            schedule_type=ScheduleType.RECURRING,
            cron=cron,
            **kwargs
        )
    
    def add_one_time_scan(self, target_id: str, scan_type: str, 
                          scheduled_time: datetime, name: str = None, **kwargs) -> ScheduledScan:
        """Convenience method to add a one-time scheduled scan"""
        if not name:
            name = f"One-time {scan_type} scan"
        
        return self.add_schedule(
            name=name,
            target_id=target_id,
            scan_type=scan_type,
            schedule_type=ScheduleType.ONCE,
            scheduled_time=scheduled_time.isoformat(),
            **kwargs
        )
    
    def add_interval_scan(self, target_id: str, scan_type: str, 
                          interval_minutes: int, name: str = None, **kwargs) -> ScheduledScan:
        """Convenience method to add an interval-based scan"""
        if not name:
            name = f"Every {interval_minutes}min {scan_type} scan"
        
        return self.add_schedule(
            name=name,
            target_id=target_id,
            scan_type=scan_type,
            schedule_type=ScheduleType.INTERVAL,
            interval_minutes=interval_minutes,
            **kwargs
        )
    
    def add_from_template(self, template_id: str, target_id: str, 
                          name: str = None, **kwargs) -> Optional[ScheduledScan]:
        """Create a scheduled scan from a template"""
        template = next((t for t in SCAN_TEMPLATES if t.id == template_id), None)
        
        if not template:
            logger.error(f"Template not found: {template_id}")
            return None
        
        return self.add_schedule(
            name=name or template.name,
            target_id=target_id,
            scan_type=template.scan_type,
            schedule_type=ScheduleType.RECURRING,
            cron=kwargs.get('cron', template.default_cron),
            scan_options={**template.scan_options, **kwargs.get('scan_options', {})},
            description=template.description,
            **{k: v for k, v in kwargs.items() if k not in ['cron', 'scan_options']}
        )
    
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get a schedule by ID"""
        return self.db.get_schedule(schedule_id)
    
    def list_schedules(self, status: str = None, target_id: str = None) -> List[ScheduledScan]:
        """List all schedules"""
        return self.db.list_schedules(status=status, target_id=target_id)
    
    def update_schedule(self, schedule_id: str, **updates) -> Optional[ScheduledScan]:
        """Update a schedule"""
        schedule = self.db.get_schedule(schedule_id)
        if not schedule:
            return None
        
        for key, value in updates.items():
            if hasattr(schedule, key):
                setattr(schedule, key, value)
        
        schedule.updated_at = datetime.now().isoformat()
        
        if 'cron_expression' in updates or 'interval_minutes' in updates:
            schedule._calculate_next_run()
        
        self.db.save_schedule(schedule)
        return schedule
    
    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a schedule"""
        schedule = self.update_schedule(schedule_id, status=ScheduleStatus.PAUSED)
        return schedule is not None
    
    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused schedule"""
        schedule = self.update_schedule(schedule_id, status=ScheduleStatus.ACTIVE)
        if schedule:
            schedule._calculate_next_run()
            self.db.save_schedule(schedule)
        return schedule is not None
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule"""
        return self.db.delete_schedule(schedule_id)
    
    def get_history(self, schedule_id: str, limit: int = 10) -> List[Dict]:
        """Get execution history for a schedule"""
        return self.db.get_history(schedule_id, limit)
    
    def get_templates(self) -> List[ScanTemplate]:
        """Get available scan templates"""
        return SCAN_TEMPLATES
    
    def _execute_scan(self, schedule: ScheduledScan) -> bool:
        """Execute a scheduled scan via API"""
        if not REQUESTS_AVAILABLE:
            logger.error("requests library not available")
            return False
        
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        
        # Notify start
        for notif in schedule.notifications:
            if notif.on_start:
                NotificationManager.send(
                    notif,
                    f"Scan Started: {schedule.name}",
                    f"Starting {schedule.scan_type} scan on target {schedule.target_id}",
                    {"target": schedule.target_id, "scan_type": schedule.scan_type}
                )
        
        # Create scan via API
        try:
            response = requests.post(
                f"{self.api_url}/scans",
                json={
                    "target_id": schedule.target_id,
                    "scan_type": schedule.scan_type,
                    "options": schedule.scan_options
                },
                headers=headers,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                data = response.json()
                scan_id = data.get('id', '')
                
                schedule.mark_completed(scan_id)
                self.db.save_schedule(schedule)
                self.db.add_history(schedule.id, scan_id, "completed")
                
                # Notify completion
                for notif in schedule.notifications:
                    if notif.on_complete:
                        NotificationManager.send(
                            notif,
                            f"Scan Completed: {schedule.name}",
                            f"Scan completed successfully. ID: {scan_id}",
                            {
                                "target": schedule.target_id,
                                "scan_type": schedule.scan_type,
                                "scan_id": scan_id
                            }
                        )
                
                logger.info(f"Scan executed: {schedule.name} -> {scan_id}")
                return True
            else:
                error = response.text
                schedule.mark_failed(error)
                self.db.save_schedule(schedule)
                self.db.add_history(schedule.id, "", "failed", error=error)
                
                # Notify failure
                for notif in schedule.notifications:
                    if notif.on_failure:
                        NotificationManager.send(
                            notif,
                            f"Scan Failed: {schedule.name}",
                            f"Scan failed: {error}",
                            {"target": schedule.target_id, "error": error}
                        )
                
                logger.error(f"Scan failed: {schedule.name} - {error}")
                return False
                
        except Exception as e:
            error = str(e)
            schedule.mark_failed(error)
            self.db.save_schedule(schedule)
            self.db.add_history(schedule.id, "", "failed", error=error)
            
            for notif in schedule.notifications:
                if notif.on_failure:
                    NotificationManager.send(
                        notif,
                        f"Scan Error: {schedule.name}",
                        f"Error: {error}",
                        {"target": schedule.target_id, "error": error}
                    )
            
            logger.error(f"Scan error: {schedule.name} - {error}")
            return False
    
    def run_due_scans(self) -> int:
        """Execute all due scans"""
        due_schedules = self.db.get_due_schedules()
        
        if not due_schedules:
            return 0
        
        # Sort by priority
        due_schedules.sort(key=lambda s: s.priority, reverse=True)
        
        executed = 0
        for schedule in due_schedules:
            schedule.mark_started()
            self.db.save_schedule(schedule)
            
            if self._execute_scan(schedule):
                executed += 1
        
        return executed
    
    def _scheduler_loop(self):
        """Background scheduler loop"""
        logger.info("Scheduler started")
        
        while self.running:
            try:
                executed = self.run_due_scans()
                if executed > 0:
                    logger.info(f"Executed {executed} scheduled scan(s)")
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
            
            # Sleep in small intervals to allow clean shutdown
            for _ in range(self._check_interval):
                if not self.running:
                    break
                time.sleep(1)
        
        logger.info("Scheduler stopped")
    
    def start(self, blocking: bool = False):
        """Start the scheduler"""
        if self.running:
            logger.warning("Scheduler already running")
            return
        
        self.running = True
        
        if blocking:
            self._scheduler_loop()
        else:
            self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self._thread.start()
            logger.info("Scheduler started in background")
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Scheduler stopped")


# FastAPI integration
def create_scheduler_routes(app):
    """
    Add scheduler routes to FastAPI app.
    
    Usage in api_server.py:
        from scan_scheduler import create_scheduler_routes
        create_scheduler_routes(app)
    """
    from fastapi import APIRouter, HTTPException, BackgroundTasks
    from pydantic import BaseModel
    from typing import Optional
    
    router = APIRouter(prefix="/schedules", tags=["Scheduled Scans"])
    scheduler = ScanScheduler()
    
    class ScheduleCreate(BaseModel):
        name: str
        target_id: str
        scan_type: str
        schedule_type: str  # "once", "recurring", "interval"
        cron_expression: Optional[str] = ""
        interval_minutes: Optional[int] = 0
        scheduled_time: Optional[str] = ""
        priority: Optional[int] = 5
        description: Optional[str] = ""
    
    class ScheduleUpdate(BaseModel):
        name: Optional[str] = None
        status: Optional[str] = None
        cron_expression: Optional[str] = None
        interval_minutes: Optional[int] = None
        priority: Optional[int] = None
    
    @router.get("")
    async def list_schedules(status: str = None, target_id: str = None):
        """List all scheduled scans"""
        schedules = scheduler.list_schedules(status=status, target_id=target_id)
        return [asdict(s) for s in schedules]
    
    @router.get("/templates")
    async def get_templates():
        """Get available scan templates"""
        return [asdict(t) for t in scheduler.get_templates()]
    
    @router.post("")
    async def create_schedule(data: ScheduleCreate):
        """Create a new scheduled scan"""
        try:
            schedule = scheduler.add_schedule(
                name=data.name,
                target_id=data.target_id,
                scan_type=data.scan_type,
                schedule_type=ScheduleType(data.schedule_type),
                cron=data.cron_expression,
                interval_minutes=data.interval_minutes,
                scheduled_time=data.scheduled_time,
                priority=data.priority,
                description=data.description
            )
            return asdict(schedule)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/from-template/{template_id}")
    async def create_from_template(template_id: str, target_id: str, name: str = None):
        """Create scheduled scan from template"""
        schedule = scheduler.add_from_template(template_id, target_id, name)
        if not schedule:
            raise HTTPException(status_code=404, detail="Template not found")
        return asdict(schedule)
    
    @router.get("/{schedule_id}")
    async def get_schedule(schedule_id: str):
        """Get schedule details"""
        schedule = scheduler.get_schedule(schedule_id)
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return asdict(schedule)
    
    @router.patch("/{schedule_id}")
    async def update_schedule(schedule_id: str, data: ScheduleUpdate):
        """Update a schedule"""
        updates = {k: v for k, v in data.dict().items() if v is not None}
        
        if 'status' in updates:
            updates['status'] = ScheduleStatus(updates['status'])
        
        schedule = scheduler.update_schedule(schedule_id, **updates)
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return asdict(schedule)
    
    @router.post("/{schedule_id}/pause")
    async def pause_schedule(schedule_id: str):
        """Pause a schedule"""
        if not scheduler.pause_schedule(schedule_id):
            raise HTTPException(status_code=404, detail="Schedule not found")
        return {"status": "paused"}
    
    @router.post("/{schedule_id}/resume")
    async def resume_schedule(schedule_id: str):
        """Resume a paused schedule"""
        if not scheduler.resume_schedule(schedule_id):
            raise HTTPException(status_code=404, detail="Schedule not found")
        return {"status": "active"}
    
    @router.delete("/{schedule_id}")
    async def delete_schedule(schedule_id: str):
        """Delete a schedule"""
        if not scheduler.delete_schedule(schedule_id):
            raise HTTPException(status_code=404, detail="Schedule not found")
        return {"deleted": True}
    
    @router.get("/{schedule_id}/history")
    async def get_history(schedule_id: str, limit: int = 10):
        """Get execution history"""
        return scheduler.get_history(schedule_id, limit)
    
    @router.post("/run-now")
    async def run_due_scans(background_tasks: BackgroundTasks):
        """Manually trigger execution of all due scans"""
        background_tasks.add_task(scheduler.run_due_scans)
        return {"message": "Checking for due scans"}
    
    @router.post("/scheduler/start")
    async def start_scheduler():
        """Start the background scheduler"""
        scheduler.start(blocking=False)
        return {"status": "started"}
    
    @router.post("/scheduler/stop")
    async def stop_scheduler():
        """Stop the background scheduler"""
        scheduler.stop()
        return {"status": "stopped"}
    
    app.include_router(router)
    return router, scheduler


# CLI Interface
def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           KALI-GPT SCAN SCHEDULER v4.1                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Schedule recurring security scans with cron-like syntax.        ║
║                                                                  ║
║  Examples:                                                       ║
║    "0 2 * * *"     - Daily at 2 AM                               ║
║    "0 */4 * * *"   - Every 4 hours                               ║
║    "0 0 * * 0"     - Weekly on Sunday at midnight                ║
║    "0 3 1 * *"     - Monthly on the 1st at 3 AM                  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


def cli_main():
    """CLI interface for the scheduler"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Kali-GPT Scan Scheduler")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API server URL")
    parser.add_argument("--api-key", help="API key")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List schedules")
    list_parser.add_argument("--status", help="Filter by status")
    
    # Add command
    add_parser = subparsers.add_parser("add", help="Add schedule")
    add_parser.add_argument("--name", required=True, help="Schedule name")
    add_parser.add_argument("--target", required=True, help="Target ID")
    add_parser.add_argument("--type", default="standard", help="Scan type")
    add_parser.add_argument("--cron", help="Cron expression")
    add_parser.add_argument("--interval", type=int, help="Interval in minutes")
    add_parser.add_argument("--once", help="One-time at datetime (ISO)")
    
    # Delete command
    del_parser = subparsers.add_parser("delete", help="Delete schedule")
    del_parser.add_argument("id", help="Schedule ID")
    
    # Pause/Resume commands
    pause_parser = subparsers.add_parser("pause", help="Pause schedule")
    pause_parser.add_argument("id", help="Schedule ID")
    
    resume_parser = subparsers.add_parser("resume", help="Resume schedule")
    resume_parser.add_argument("id", help="Schedule ID")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Start scheduler daemon")
    
    # Templates command
    templates_parser = subparsers.add_parser("templates", help="List templates")
    
    args = parser.parse_args()
    
    print_banner()
    
    scheduler = ScanScheduler(api_url=args.api_url, api_key=args.api_key)
    
    if args.command == "list":
        schedules = scheduler.list_schedules(status=args.status)
        if not schedules:
            print("No schedules found.")
        else:
            print(f"{'ID':<10} {'Name':<25} {'Type':<12} {'Status':<10} {'Next Run':<20}")
            print("-" * 80)
            for s in schedules:
                next_run = s.next_run[:19] if s.next_run else "-"
                print(f"{s.id:<10} {s.name[:24]:<25} {s.scan_type:<12} {s.status.value:<10} {next_run:<20}")
    
    elif args.command == "add":
        if args.cron:
            schedule = scheduler.add_recurring_scan(
                target_id=args.target,
                scan_type=args.type,
                cron=args.cron,
                name=args.name
            )
        elif args.interval:
            schedule = scheduler.add_interval_scan(
                target_id=args.target,
                scan_type=args.type,
                interval_minutes=args.interval,
                name=args.name
            )
        elif args.once:
            schedule = scheduler.add_one_time_scan(
                target_id=args.target,
                scan_type=args.type,
                scheduled_time=datetime.fromisoformat(args.once),
                name=args.name
            )
        else:
            print("Error: Specify --cron, --interval, or --once")
            return
        
        print(f"✓ Created schedule: {schedule.id}")
        print(f"  Name: {schedule.name}")
        print(f"  Next run: {schedule.next_run}")
    
    elif args.command == "delete":
        if scheduler.delete_schedule(args.id):
            print(f"✓ Deleted: {args.id}")
        else:
            print(f"✗ Not found: {args.id}")
    
    elif args.command == "pause":
        if scheduler.pause_schedule(args.id):
            print(f"✓ Paused: {args.id}")
        else:
            print(f"✗ Not found: {args.id}")
    
    elif args.command == "resume":
        if scheduler.resume_schedule(args.id):
            print(f"✓ Resumed: {args.id}")
        else:
            print(f"✗ Not found: {args.id}")
    
    elif args.command == "run":
        print("Starting scheduler daemon...")
        print("Press Ctrl+C to stop\n")
        try:
            scheduler.start(blocking=True)
        except KeyboardInterrupt:
            scheduler.stop()
            print("\nScheduler stopped.")
    
    elif args.command == "templates":
        print(f"{'ID':<20} {'Name':<30} {'Default Cron':<15}")
        print("-" * 65)
        for t in SCAN_TEMPLATES:
            print(f"{t.id:<20} {t.name:<30} {t.default_cron:<15}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_main()
