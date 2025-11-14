"""Team Collaboration Module"""

import json
import requests
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import hashlib

class CollaborationManager:
    """Manages team collaboration features"""

    def __init__(self, config_manager, history_manager):
        """Initialize collaboration manager"""
        self.config = config_manager
        self.history = history_manager
        self.collab_config = config_manager.get("collaboration", {})
        self.enabled = self.collab_config.get("enabled", False)
        self.server_url = self.collab_config.get("server_url", "")
        self.api_key = self.collab_config.get("api_key", "")
        self.share_logs = self.collab_config.get("share_logs", False)

        # Local collaboration data
        self.collab_dir = Path(config_manager.config_dir) / "collaboration"
        self.collab_dir.mkdir(parents=True, exist_ok=True)

        self.shared_sessions_file = self.collab_dir / "shared_sessions.json"
        self.team_members_file = self.collab_dir / "team_members.json"

        self.shared_sessions = self.load_shared_sessions()
        self.team_members = self.load_team_members()

    def load_shared_sessions(self) -> List[Dict]:
        """Load shared sessions from file"""
        if self.shared_sessions_file.exists():
            try:
                with open(self.shared_sessions_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def save_shared_sessions(self):
        """Save shared sessions to file"""
        with open(self.shared_sessions_file, 'w') as f:
            json.dump(self.shared_sessions, f, indent=2)

    def load_team_members(self) -> List[Dict]:
        """Load team members from file"""
        if self.team_members_file.exists():
            try:
                with open(self.team_members_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def save_team_members(self):
        """Save team members to file"""
        with open(self.team_members_file, 'w') as f:
            json.dump(self.team_members, f, indent=2)

    def create_session_share(self, session_name: str, description: str = "",
                            include_logs: bool = True) -> Dict:
        """
        Create a shareable session

        Args:
            session_name: Name for the session
            description: Session description
            include_logs: Include interaction logs

        Returns:
            Session share information
        """
        # Generate session ID
        session_id = hashlib.md5(f"{session_name}{datetime.now().isoformat()}".encode()).hexdigest()[:12]

        session_data = {
            "id": session_id,
            "name": session_name,
            "description": description,
            "created": datetime.now().isoformat(),
            "creator": "local",  # Would be username in full implementation
            "logs": [],
            "targets": [],
            "findings": []
        }

        # Include logs if requested
        if include_logs and self.share_logs:
            session_data["logs"] = self.history.interaction_logs[-50:]  # Last 50 interactions

        # Save locally
        session_file = self.collab_dir / f"session_{session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)

        # Add to shared sessions list
        self.shared_sessions.append({
            "id": session_id,
            "name": session_name,
            "created": session_data["created"],
            "file": str(session_file)
        })
        self.save_shared_sessions()

        return {
            "success": True,
            "session_id": session_id,
            "file": str(session_file),
            "message": f"Session '{session_name}' created with ID: {session_id}"
        }

    def export_session(self, session_id: str, output_file: str = None) -> str:
        """
        Export a session to a file for sharing

        Args:
            session_id: Session ID to export
            output_file: Output file path (optional)

        Returns:
            Path to exported file
        """
        session = next((s for s in self.shared_sessions if s["id"] == session_id), None)

        if not session:
            return None

        if output_file is None:
            output_file = f"session_{session_id}_export.json"

        session_file = Path(session["file"])
        if session_file.exists():
            with open(session_file, 'r') as f:
                session_data = json.load(f)

            with open(output_file, 'w') as f:
                json.dump(session_data, f, indent=2)

            return output_file

        return None

    def import_session(self, session_file: str) -> Optional[str]:
        """
        Import a shared session

        Args:
            session_file: Path to session file

        Returns:
            Session ID if successful
        """
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)

            session_id = session_data.get("id")
            session_name = session_data.get("name", "Imported Session")

            # Save to collaboration directory
            local_file = self.collab_dir / f"session_{session_id}.json"
            with open(local_file, 'w') as f:
                json.dump(session_data, f, indent=2)

            # Add to shared sessions
            self.shared_sessions.append({
                "id": session_id,
                "name": session_name,
                "created": session_data.get("created"),
                "file": str(local_file),
                "imported": datetime.now().isoformat()
            })
            self.save_shared_sessions()

            return session_id

        except Exception as e:
            print(f"Error importing session: {e}")
            return None

    def add_team_member(self, name: str, role: str = "member",
                       email: str = "", permissions: List[str] = None) -> bool:
        """
        Add a team member

        Args:
            name: Member name
            role: Role (admin, member, viewer)
            email: Email address
            permissions: List of permissions

        Returns:
            Success status
        """
        if permissions is None:
            permissions = ["view_logs", "execute_commands"]

        member = {
            "id": hashlib.md5(f"{name}{email}".encode()).hexdigest()[:8],
            "name": name,
            "role": role,
            "email": email,
            "permissions": permissions,
            "added": datetime.now().isoformat()
        }

        self.team_members.append(member)
        self.save_team_members()

        return True

    def remove_team_member(self, member_id: str) -> bool:
        """Remove a team member"""
        original_length = len(self.team_members)
        self.team_members = [m for m in self.team_members if m["id"] != member_id]

        if len(self.team_members) < original_length:
            self.save_team_members()
            return True

        return False

    def list_team_members(self) -> List[Dict]:
        """Get list of team members"""
        return self.team_members

    def get_shared_sessions(self) -> List[Dict]:
        """Get list of shared sessions"""
        return self.shared_sessions

    def sync_with_server(self) -> Dict:
        """
        Synchronize with collaboration server (if configured)

        Returns:
            Sync status
        """
        if not self.enabled or not self.server_url:
            return {
                "success": False,
                "error": "Collaboration server not configured"
            }

        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}

            # Upload recent logs if sharing is enabled
            if self.share_logs:
                recent_logs = self.history.interaction_logs[-10:]

                response = requests.post(
                    f"{self.server_url}/api/logs",
                    json={"logs": recent_logs},
                    headers=headers,
                    timeout=10
                )

                if response.status_code == 200:
                    return {
                        "success": True,
                        "message": "Logs synchronized successfully"
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Server returned status {response.status_code}"
                    }

        except Exception as e:
            return {
                "success": False,
                "error": f"Sync error: {str(e)}"
            }

    def get_team_activity(self) -> Dict:
        """
        Get team activity summary

        Returns:
            Activity statistics
        """
        return {
            "total_members": len(self.team_members),
            "shared_sessions": len(self.shared_sessions),
            "last_sync": "Not synced" if not self.enabled else "Unknown",
            "collaboration_enabled": self.enabled
        }

    def create_finding_note(self, finding: Dict, author: str = "local") -> str:
        """
        Create a shareable finding note

        Args:
            finding: Finding details
            author: Author name

        Returns:
            Note ID
        """
        note_id = hashlib.md5(f"{finding}{datetime.now().isoformat()}".encode()).hexdigest()[:8]

        note = {
            "id": note_id,
            "author": author,
            "created": datetime.now().isoformat(),
            "finding": finding
        }

        note_file = self.collab_dir / f"finding_{note_id}.json"
        with open(note_file, 'w') as f:
            json.dump(note, f, indent=2)

        return note_id

    def share_target_list(self, targets: List[Dict], share_name: str) -> str:
        """
        Share a list of targets with the team

        Args:
            targets: List of targets
            share_name: Name for the shared list

        Returns:
            Share ID
        """
        share_id = hashlib.md5(f"{share_name}{datetime.now().isoformat()}".encode()).hexdigest()[:8]

        share_data = {
            "id": share_id,
            "name": share_name,
            "created": datetime.now().isoformat(),
            "targets": targets
        }

        share_file = self.collab_dir / f"targets_{share_id}.json"
        with open(share_file, 'w') as f:
            json.dump(share_data, f, indent=2)

        return share_id
