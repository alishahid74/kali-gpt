"""Plugin Base Class"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any

class KaliGPTPlugin(ABC):
    """
    Base class for Kali GPT plugins

    Plugins can extend functionality by implementing these hooks:
    - on_init: Called when plugin is loaded
    - on_command_execute: Called before command execution
    - on_output_analysis: Called after command output is received
    - get_menu_items: Provide custom menu items
    - shutdown: Called when plugin is unloaded
    """

    def __init__(self):
        """Initialize plugin"""
        self.name = "Base Plugin"
        self.version = "1.0.0"
        self.description = "Base plugin class"
        self.author = "Unknown"
        self.enabled = True

    @abstractmethod
    def get_metadata(self) -> Dict[str, str]:
        """
        Get plugin metadata

        Returns:
            Dict with name, version, description, author
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author
        }

    def on_init(self, app) -> bool:
        """
        Called when plugin is initialized

        Args:
            app: Reference to main KaliGPTAdvanced instance

        Returns:
            True if initialization successful
        """
        return True

    def on_command_execute(self, command: str, context: Dict) -> Optional[str]:
        """
        Called before a command is executed
        Can modify the command or return None to prevent execution

        Args:
            command: Command to be executed
            context: Execution context (target, profile, etc.)

        Returns:
            Modified command or None to cancel execution
        """
        return command

    def on_output_analysis(self, command: str, output: str, context: Dict) -> Optional[Dict]:
        """
        Called after command output is received
        Can provide additional analysis or findings

        Args:
            command: Command that was executed
            output: Command output
            context: Execution context

        Returns:
            Analysis results or None
        """
        return None

    def get_menu_items(self) -> List[Dict]:
        """
        Provide custom menu items

        Returns:
            List of menu items with 'label' and 'callback' keys
        """
        return []

    def shutdown(self) -> bool:
        """
        Called when plugin is unloaded

        Returns:
            True if shutdown successful
        """
        return True

    def get_commands(self) -> List[Dict]:
        """
        Provide custom commands

        Returns:
            List of commands with 'name', 'description', and 'handler' keys
        """
        return []

    def on_scan_complete(self, scan_results: Dict) -> Optional[Dict]:
        """
        Called when a scan completes

        Args:
            scan_results: Scan results

        Returns:
            Additional analysis or None
        """
        return None

    def on_finding_added(self, target_id: str, finding: Dict) -> Optional[Dict]:
        """
        Called when a finding is added to a target

        Args:
            target_id: Target ID
            finding: Finding details

        Returns:
            Additional data or None
        """
        return None

    def on_report_generate(self, report_type: str, data: Dict) -> Optional[Dict]:
        """
        Called when a report is being generated
        Can add custom sections to the report

        Args:
            report_type: Type of report (html, pdf, markdown)
            data: Report data

        Returns:
            Additional report sections or None
        """
        return None

    def process_ai_response(self, response: str, context: Dict) -> str:
        """
        Process AI response before displaying to user
        Can modify or enhance the response

        Args:
            response: AI response
            context: Response context

        Returns:
            Processed response
        """
        return response

    def get_config_schema(self) -> Dict:
        """
        Get configuration schema for the plugin

        Returns:
            Configuration schema
        """
        return {}

    def configure(self, config: Dict) -> bool:
        """
        Configure the plugin

        Args:
            config: Configuration data

        Returns:
            True if configuration successful
        """
        return True

    def get_status(self) -> Dict:
        """
        Get plugin status

        Returns:
            Status information
        """
        return {
            "enabled": self.enabled,
            "name": self.name,
            "version": self.version
        }

    def enable(self):
        """Enable the plugin"""
        self.enabled = True

    def disable(self):
        """Disable the plugin"""
        self.enabled = False


class ExamplePlugin(KaliGPTPlugin):
    """Example plugin implementation"""

    def __init__(self):
        super().__init__()
        self.name = "Example Plugin"
        self.version = "1.0.0"
        self.description = "An example plugin demonstrating the plugin system"
        self.author = "Kali GPT Team"

    def get_metadata(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author
        }

    def on_init(self, app) -> bool:
        print(f"[Plugin] {self.name} initialized")
        return True

    def on_command_execute(self, command: str, context: Dict) -> Optional[str]:
        # Example: Log all commands
        print(f"[Plugin] Executing command: {command}")
        return command

    def get_menu_items(self) -> List[Dict]:
        return [
            {
                "label": "Example Plugin Action",
                "callback": self.example_action
            }
        ]

    def example_action(self):
        """Example menu action"""
        print("Example plugin action executed!")

    def shutdown(self) -> bool:
        print(f"[Plugin] {self.name} shutting down")
        return True
