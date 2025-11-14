"""Report Generation Module"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import html

class ReportGenerator:
    """Generates penetration testing reports in various formats"""

    def __init__(self, config_manager, history_manager):
        """Initialize report generator"""
        self.config = config_manager
        self.history = history_manager
        self.reports_dir = Path(config_manager.get("reports.output_directory", "~/.kali-gpt/reports")).expanduser()
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(self, title: str = "Penetration Testing Report",
                           start_date: str = None, end_date: str = None,
                           include_commands: bool = True) -> str:
        """
        Generate HTML report

        Args:
            title: Report title
            start_date: Filter logs from this date
            end_date: Filter logs until this date
            include_commands: Include executed commands

        Returns:
            Path to generated report
        """
        # Get logs for the specified date range
        logs = self.history.interaction_logs

        if start_date:
            logs = [log for log in logs if log["timestamp"] >= start_date]
        if end_date:
            logs = [log for log in logs if log["timestamp"] <= end_date]

        # Generate HTML
        html_content = self._generate_html_template(title, logs, include_commands)

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"report_{timestamp}.html"

        with open(report_file, 'w') as f:
            f.write(html_content)

        return str(report_file)

    def _generate_html_template(self, title: str, logs: List[Dict], include_commands: bool) -> str:
        """Generate HTML template for report"""
        # Header
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .metadata {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .interaction {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        .mode-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            background-color: #667eea;
            color: white;
            font-size: 0.85em;
            margin-bottom: 10px;
        }}
        .user-input {{
            background: #e3f2fd;
            padding: 15px;
            border-left: 4px solid #2196f3;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .ai-response {{
            background: #f3e5f5;
            padding: 15px;
            border-left: 4px solid #9c27b0;
            margin: 10px 0;
            border-radius: 5px;
        }}
        .command {{
            background: #263238;
            color: #4caf50;
            padding: 15px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .output {{
            background: #37474f;
            color: #fff;
            padding: 15px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            border-radius: 5px;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{html.escape(title)}</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
"""

        # Statistics
        stats = self.history.get_statistics()
        html_content += f"""
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{len(logs)}</div>
            <div class="stat-label">Total Interactions</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{sum(1 for log in logs if log.get('command'))}</div>
            <div class="stat-label">Commands Executed</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(set(log.get('mode', 'general') for log in logs))}</div>
            <div class="stat-label">Profiles Used</div>
        </div>
    </div>
"""

        # Interactions
        html_content += """
    <h2>Detailed Interactions</h2>
"""

        for i, log in enumerate(logs, 1):
            timestamp = log.get("timestamp", "Unknown")
            mode = log.get("mode", "general")
            user_input = html.escape(log.get("user_input", ""))
            ai_response = html.escape(log.get("ai_response", ""))
            command = log.get("command", "")
            command_output = log.get("command_output", "")

            html_content += f"""
    <div class="interaction">
        <div class="timestamp">#{i} - {timestamp}</div>
        <span class="mode-badge">{html.escape(mode.upper())}</span>

        <div class="user-input">
            <strong>User:</strong><br>
            {user_input}
        </div>

        <div class="ai-response">
            <strong>AI Response:</strong><br>
            {ai_response}
        </div>
"""

            if include_commands and command:
                html_content += f"""
        <div class="command">
            <strong>$ </strong>{html.escape(command)}
        </div>
"""

            if include_commands and command_output:
                html_content += f"""
        <div class="output">
            {html.escape(command_output[:2000])}
            {'...(truncated)' if len(command_output) > 2000 else ''}
        </div>
"""

            html_content += """
    </div>
"""

        # Footer
        html_content += """
</body>
</html>
"""

        return html_content

    def generate_markdown_report(self, title: str = "Penetration Testing Report",
                                start_date: str = None, end_date: str = None) -> str:
        """Generate Markdown report"""
        logs = self.history.interaction_logs

        if start_date:
            logs = [log for log in logs if log["timestamp"] >= start_date]
        if end_date:
            logs = [log for log in logs if log["timestamp"] <= end_date]

        md_content = f"# {title}\n\n"
        md_content += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        # Statistics
        stats = self.history.get_statistics()
        md_content += "## Summary\n\n"
        md_content += f"- Total Interactions: {len(logs)}\n"
        md_content += f"- Commands Executed: {sum(1 for log in logs if log.get('command'))}\n"
        md_content += f"- Profiles Used: {len(set(log.get('mode', 'general') for log in logs))}\n\n"

        # Interactions
        md_content += "## Detailed Interactions\n\n"

        for i, log in enumerate(logs, 1):
            timestamp = log.get("timestamp", "Unknown")
            mode = log.get("mode", "general")
            user_input = log.get("user_input", "")
            ai_response = log.get("ai_response", "")
            command = log.get("command", "")

            md_content += f"### Interaction #{i} - {timestamp}\n\n"
            md_content += f"**Profile:** {mode}\n\n"
            md_content += f"**User Input:**\n```\n{user_input}\n```\n\n"
            md_content += f"**AI Response:**\n```\n{ai_response}\n```\n\n"

            if command:
                md_content += f"**Command Executed:**\n```bash\n{command}\n```\n\n"

            md_content += "---\n\n"

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"report_{timestamp}.md"

        with open(report_file, 'w') as f:
            f.write(md_content)

        return str(report_file)

    def generate_json_report(self, start_date: str = None, end_date: str = None) -> str:
        """Generate JSON report"""
        logs = self.history.interaction_logs

        if start_date:
            logs = [log for log in logs if log["timestamp"] >= start_date]
        if end_date:
            logs = [log for log in logs if log["timestamp"] <= end_date]

        report_data = {
            "generated": datetime.now().isoformat(),
            "statistics": self.history.get_statistics(),
            "interactions": logs
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"report_{timestamp}.json"

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        return str(report_file)
