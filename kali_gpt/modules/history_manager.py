"""Conversation History Management Module"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

class HistoryManager:
    """Manages conversation and interaction history"""

    def __init__(self, config_manager):
        """Initialize history manager"""
        self.config = config_manager
        self.history_dir = Path(config_manager.config_dir)
        self.conversation_file = self.history_dir / "conversation_history.json"
        self.interaction_file = self.history_dir / "interaction_logs.json"

        self.conversation_history = self.load_conversation_history()
        self.interaction_logs = self.load_interaction_logs()

    def load_conversation_history(self) -> List[Dict]:
        """Load conversation history from file"""
        if self.conversation_file.exists():
            try:
                with open(self.conversation_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def save_conversation_history(self):
        """Save conversation history to file"""
        if not self.config.get("save_history", True):
            return

        max_history = self.config.get("max_history", 10)
        # Keep only the most recent entries
        history_to_save = self.conversation_history[-max_history:]

        with open(self.conversation_file, 'w') as f:
            json.dump(history_to_save, f, indent=2)

    def add_conversation(self, user_input: str, ai_response: str, mode: str = "general"):
        """Add a conversation exchange to history"""
        self.conversation_history.append({
            "timestamp": datetime.now().isoformat(),
            "mode": mode,
            "user": user_input,
            "assistant": ai_response
        })

        self.save_conversation_history()

    def get_recent_conversations(self, limit: int = 5) -> List[Dict]:
        """Get recent conversation history"""
        return self.conversation_history[-limit:] if self.conversation_history else []

    def clear_conversation_history(self):
        """Clear conversation history"""
        self.conversation_history = []
        self.save_conversation_history()

    def load_interaction_logs(self) -> List[Dict]:
        """Load interaction logs from file"""
        if self.interaction_file.exists():
            try:
                with open(self.interaction_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def save_interaction_logs(self):
        """Save interaction logs to file"""
        with open(self.interaction_file, 'w') as f:
            json.dump(self.interaction_logs, f, indent=2)

    def log_interaction(self, user_input: str, ai_response: str,
                       command: Optional[str] = None,
                       command_output: Optional[str] = None,
                       mode: str = "general"):
        """
        Log a complete interaction

        Args:
            user_input: User's input
            ai_response: AI's response
            command: Command executed (if any)
            command_output: Command output (if any)
            mode: Current profile mode
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "mode": mode,
            "user_input": user_input,
            "ai_response": ai_response,
            "command": command,
            "command_output": command_output
        }

        self.interaction_logs.append(log_entry)
        self.save_interaction_logs()

    def get_logs_by_date(self, date: str) -> List[Dict]:
        """Get logs for a specific date (YYYY-MM-DD)"""
        return [
            log for log in self.interaction_logs
            if log["timestamp"].startswith(date)
        ]

    def get_logs_by_mode(self, mode: str) -> List[Dict]:
        """Get logs for a specific profile mode"""
        return [
            log for log in self.interaction_logs
            if log.get("mode") == mode
        ]

    def search_logs(self, query: str) -> List[Dict]:
        """Search logs for a query string"""
        results = []
        query_lower = query.lower()

        for log in self.interaction_logs:
            if (query_lower in log.get("user_input", "").lower() or
                query_lower in log.get("ai_response", "").lower() or
                query_lower in log.get("command", "").lower()):
                results.append(log)

        return results

    def export_logs(self, output_file: str, start_date: str = None, end_date: str = None):
        """
        Export logs to a file

        Args:
            output_file: Path to output file
            start_date: Start date filter (YYYY-MM-DD)
            end_date: End date filter (YYYY-MM-DD)
        """
        logs_to_export = self.interaction_logs

        if start_date:
            logs_to_export = [
                log for log in logs_to_export
                if log["timestamp"] >= start_date
            ]

        if end_date:
            logs_to_export = [
                log for log in logs_to_export
                if log["timestamp"] <= end_date
            ]

        with open(output_file, 'w') as f:
            json.dump(logs_to_export, f, indent=2)

    def get_statistics(self) -> Dict:
        """Get usage statistics"""
        total_interactions = len(self.interaction_logs)
        commands_executed = sum(1 for log in self.interaction_logs if log.get("command"))

        modes = {}
        for log in self.interaction_logs:
            mode = log.get("mode", "unknown")
            modes[mode] = modes.get(mode, 0) + 1

        return {
            "total_interactions": total_interactions,
            "commands_executed": commands_executed,
            "mode_usage": modes,
            "first_interaction": self.interaction_logs[0]["timestamp"] if self.interaction_logs else None,
            "last_interaction": self.interaction_logs[-1]["timestamp"] if self.interaction_logs else None
        }
