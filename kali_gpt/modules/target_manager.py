"""Target Management Module"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import uuid

class TargetManager:
    """Manages penetration testing targets"""

    def __init__(self, config_manager):
        """Initialize target manager"""
        self.config = config_manager
        self.targets_file = Path(config_manager.config_dir) / "targets.json"
        self.targets = self.load_targets()
        self.active_target = None

    def load_targets(self) -> List[Dict]:
        """Load targets from file"""
        if self.targets_file.exists():
            try:
                with open(self.targets_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def save_targets(self):
        """Save targets to file"""
        if not self.config.get("targets.save_targets", True):
            return

        with open(self.targets_file, 'w') as f:
            json.dump(self.targets, f, indent=2)

    def add_target(self, host: str, ports: str = "", description: str = "",
                  tags: List[str] = None, metadata: Dict = None) -> str:
        """
        Add a new target

        Args:
            host: Target host (IP or domain)
            ports: Ports to target
            description: Target description
            tags: List of tags
            metadata: Additional metadata

        Returns:
            Target ID
        """
        target_id = str(uuid.uuid4())[:8]

        target = {
            "id": target_id,
            "host": host,
            "ports": ports,
            "description": description,
            "tags": tags or [],
            "metadata": metadata or {},
            "status": "pending",
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "findings": [],
            "notes": []
        }

        self.targets.append(target)
        self.save_targets()

        return target_id

    def remove_target(self, target_id: str) -> bool:
        """Remove a target"""
        original_length = len(self.targets)
        self.targets = [t for t in self.targets if t["id"] != target_id]

        if len(self.targets) < original_length:
            self.save_targets()
            if self.active_target and self.active_target["id"] == target_id:
                self.active_target = None
            return True

        return False

    def get_target(self, target_id: str) -> Optional[Dict]:
        """Get target by ID"""
        for target in self.targets:
            if target["id"] == target_id:
                return target
        return None

    def set_active_target(self, target_id: str) -> bool:
        """Set the active target"""
        target = self.get_target(target_id)
        if target:
            self.active_target = target
            return True
        return False

    def get_active_target(self) -> Optional[Dict]:
        """Get the currently active target"""
        return self.active_target

    def update_target(self, target_id: str, **kwargs) -> bool:
        """Update target attributes"""
        target = self.get_target(target_id)
        if not target:
            return False

        for key, value in kwargs.items():
            if key in ["host", "ports", "description", "tags", "metadata", "status"]:
                target[key] = value

        target["updated"] = datetime.now().isoformat()
        self.save_targets()

        return True

    def add_finding(self, target_id: str, title: str, description: str,
                   severity: str = "medium", cvss: str = "") -> bool:
        """Add a finding to a target"""
        target = self.get_target(target_id)
        if not target:
            return False

        finding = {
            "id": str(uuid.uuid4())[:8],
            "title": title,
            "description": description,
            "severity": severity,
            "cvss": cvss,
            "timestamp": datetime.now().isoformat()
        }

        target["findings"].append(finding)
        target["updated"] = datetime.now().isoformat()
        self.save_targets()

        return True

    def add_note(self, target_id: str, note: str) -> bool:
        """Add a note to a target"""
        target = self.get_target(target_id)
        if not target:
            return False

        note_entry = {
            "timestamp": datetime.now().isoformat(),
            "content": note
        }

        target["notes"].append(note_entry)
        target["updated"] = datetime.now().isoformat()
        self.save_targets()

        return True

    def list_targets(self, status: str = None, tag: str = None) -> List[Dict]:
        """
        List targets with optional filters

        Args:
            status: Filter by status
            tag: Filter by tag

        Returns:
            List of targets
        """
        filtered_targets = self.targets

        if status:
            filtered_targets = [t for t in filtered_targets if t.get("status") == status]

        if tag:
            filtered_targets = [t for t in filtered_targets if tag in t.get("tags", [])]

        return filtered_targets

    def search_targets(self, query: str) -> List[Dict]:
        """Search targets by host, description, or tags"""
        query_lower = query.lower()
        results = []

        for target in self.targets:
            if (query_lower in target.get("host", "").lower() or
                query_lower in target.get("description", "").lower() or
                any(query_lower in tag.lower() for tag in target.get("tags", []))):
                results.append(target)

        return results

    def get_target_statistics(self) -> Dict:
        """Get statistics about targets"""
        total = len(self.targets)
        by_status = {}

        for target in self.targets:
            status = target.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

        total_findings = sum(len(t.get("findings", [])) for t in self.targets)

        return {
            "total_targets": total,
            "by_status": by_status,
            "total_findings": total_findings,
            "active_target": self.active_target["id"] if self.active_target else None
        }

    def export_target(self, target_id: str, output_file: str):
        """Export a single target to JSON file"""
        target = self.get_target(target_id)
        if target:
            with open(output_file, 'w') as f:
                json.dump(target, f, indent=2)

    def import_target(self, input_file: str) -> Optional[str]:
        """Import a target from JSON file"""
        try:
            with open(input_file, 'r') as f:
                target_data = json.load(f)

            # Generate new ID
            target_data["id"] = str(uuid.uuid4())[:8]
            target_data["created"] = datetime.now().isoformat()
            target_data["updated"] = datetime.now().isoformat()

            self.targets.append(target_data)
            self.save_targets()

            return target_data["id"]
        except Exception as e:
            print(f"Error importing target: {e}")
            return None
