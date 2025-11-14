"""Plugin Manager"""

import importlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from .plugin_base import KaliGPTPlugin

class PluginManager:
    """Manages loading and execution of plugins"""

    def __init__(self, config_manager):
        """Initialize plugin manager"""
        self.config = config_manager
        self.plugins_config = config_manager.get("plugins", {})
        self.enabled = self.plugins_config.get("enabled", True)
        self.auto_load = self.plugins_config.get("auto_load", True)

        # Plugin directory
        plugin_dir_config = self.plugins_config.get("plugin_directory", "~/.kali-gpt/plugins")
        self.plugins_dir = Path(plugin_dir_config).expanduser()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

        # Loaded plugins
        self.plugins: Dict[str, KaliGPTPlugin] = {}
        self.plugin_metadata = {}

        # Add plugins directory to Python path
        if str(self.plugins_dir) not in sys.path:
            sys.path.insert(0, str(self.plugins_dir))

        # Auto-load plugins if enabled
        if self.auto_load and self.enabled:
            self.discover_and_load_plugins()

    def discover_and_load_plugins(self):
        """Discover and load all plugins in the plugins directory"""
        # Look for Python files in plugins directory
        for plugin_file in self.plugins_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue

            plugin_name = plugin_file.stem
            self.load_plugin_from_file(plugin_name, plugin_file)

        # Look for plugin packages (directories with __init__.py)
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir() and (plugin_dir / "__init__.py").exists():
                plugin_name = plugin_dir.name
                self.load_plugin_from_module(plugin_name)

    def load_plugin_from_file(self, plugin_name: str, plugin_file: Path) -> bool:
        """
        Load a plugin from a Python file

        Args:
            plugin_name: Name of the plugin
            plugin_file: Path to plugin file

        Returns:
            True if loaded successfully
        """
        try:
            # Import the module
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Look for KaliGPTPlugin subclasses
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)

                    if (isinstance(attr, type) and
                        issubclass(attr, KaliGPTPlugin) and
                        attr is not KaliGPTPlugin):

                        # Instantiate the plugin
                        plugin_instance = attr()
                        return self.register_plugin(plugin_name, plugin_instance)

        except Exception as e:
            print(f"Error loading plugin {plugin_name}: {e}")
            return False

        return False

    def load_plugin_from_module(self, module_name: str) -> bool:
        """
        Load a plugin from a Python module/package

        Args:
            module_name: Name of the module

        Returns:
            True if loaded successfully
        """
        try:
            module = importlib.import_module(module_name)

            # Look for KaliGPTPlugin subclasses
            for attr_name in dir(module):
                attr = getattr(module, attr_name)

                if (isinstance(attr, type) and
                    issubclass(attr, KaliGPTPlugin) and
                    attr is not KaliGPTPlugin):

                    plugin_instance = attr()
                    return self.register_plugin(module_name, plugin_instance)

        except Exception as e:
            print(f"Error loading plugin module {module_name}: {e}")
            return False

        return False

    def register_plugin(self, plugin_id: str, plugin: KaliGPTPlugin) -> bool:
        """
        Register a plugin instance

        Args:
            plugin_id: Unique identifier for the plugin
            plugin: Plugin instance

        Returns:
            True if registered successfully
        """
        try:
            # Get metadata
            metadata = plugin.get_metadata()
            self.plugin_metadata[plugin_id] = metadata

            # Store plugin
            self.plugins[plugin_id] = plugin

            print(f"[PluginManager] Registered plugin: {metadata.get('name', plugin_id)} v{metadata.get('version', '?')}")
            return True

        except Exception as e:
            print(f"Error registering plugin {plugin_id}: {e}")
            return False

    def initialize_plugins(self, app):
        """
        Initialize all loaded plugins

        Args:
            app: Reference to main application
        """
        for plugin_id, plugin in self.plugins.items():
            try:
                if plugin.on_init(app):
                    print(f"[PluginManager] Initialized: {plugin_id}")
                else:
                    print(f"[PluginManager] Failed to initialize: {plugin_id}")
            except Exception as e:
                print(f"[PluginManager] Error initializing {plugin_id}: {e}")

    def unload_plugin(self, plugin_id: str) -> bool:
        """
        Unload a plugin

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if unloaded successfully
        """
        if plugin_id in self.plugins:
            try:
                plugin = self.plugins[plugin_id]
                plugin.shutdown()
                del self.plugins[plugin_id]
                del self.plugin_metadata[plugin_id]
                print(f"[PluginManager] Unloaded plugin: {plugin_id}")
                return True
            except Exception as e:
                print(f"Error unloading plugin {plugin_id}: {e}")
                return False

        return False

    def get_plugin(self, plugin_id: str) -> Optional[KaliGPTPlugin]:
        """Get a plugin by ID"""
        return self.plugins.get(plugin_id)

    def list_plugins(self) -> List[Dict]:
        """Get list of loaded plugins"""
        return [
            {
                "id": plugin_id,
                **metadata,
                "enabled": self.plugins[plugin_id].enabled
            }
            for plugin_id, metadata in self.plugin_metadata.items()
        ]

    def execute_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """
        Execute a hook on all enabled plugins

        Args:
            hook_name: Name of the hook method
            *args: Positional arguments for the hook
            **kwargs: Keyword arguments for the hook

        Returns:
            List of results from all plugins
        """
        results = []

        for plugin_id, plugin in self.plugins.items():
            if not plugin.enabled:
                continue

            if hasattr(plugin, hook_name):
                try:
                    hook_method = getattr(plugin, hook_name)
                    result = hook_method(*args, **kwargs)
                    if result is not None:
                        results.append({
                            "plugin_id": plugin_id,
                            "result": result
                        })
                except Exception as e:
                    print(f"Error executing hook {hook_name} on {plugin_id}: {e}")

        return results

    def on_command_execute(self, command: str, context: Dict) -> str:
        """
        Execute on_command_execute hook on all plugins
        Allows plugins to modify commands before execution

        Args:
            command: Original command
            context: Execution context

        Returns:
            Modified command
        """
        modified_command = command

        for plugin_id, plugin in self.plugins.items():
            if not plugin.enabled:
                continue

            try:
                result = plugin.on_command_execute(modified_command, context)
                if result is None:
                    print(f"[PluginManager] Command blocked by plugin: {plugin_id}")
                    return None
                modified_command = result
            except Exception as e:
                print(f"Error in plugin {plugin_id} on_command_execute: {e}")

        return modified_command

    def on_output_analysis(self, command: str, output: str, context: Dict) -> List[Dict]:
        """
        Execute on_output_analysis hook on all plugins

        Args:
            command: Executed command
            output: Command output
            context: Execution context

        Returns:
            List of analysis results from plugins
        """
        return self.execute_hook("on_output_analysis", command, output, context)

    def get_all_menu_items(self) -> List[Dict]:
        """Get menu items from all enabled plugins"""
        menu_items = []

        for plugin_id, plugin in self.plugins.items():
            if not plugin.enabled:
                continue

            try:
                items = plugin.get_menu_items()
                for item in items:
                    item["plugin_id"] = plugin_id
                    menu_items.append(item)
            except Exception as e:
                print(f"Error getting menu items from {plugin_id}: {e}")

        return menu_items

    def get_all_commands(self) -> Dict[str, Dict]:
        """Get custom commands from all enabled plugins"""
        commands = {}

        for plugin_id, plugin in self.plugins.items():
            if not plugin.enabled:
                continue

            try:
                plugin_commands = plugin.get_commands()
                for cmd in plugin_commands:
                    cmd_name = cmd.get("name")
                    if cmd_name:
                        commands[cmd_name] = {
                            **cmd,
                            "plugin_id": plugin_id
                        }
            except Exception as e:
                print(f"Error getting commands from {plugin_id}: {e}")

        return commands

    def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin"""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].enable()
            return True
        return False

    def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin"""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].disable()
            return True
        return False

    def reload_plugin(self, plugin_id: str) -> bool:
        """
        Reload a plugin

        Args:
            plugin_id: Plugin identifier

        Returns:
            True if reloaded successfully
        """
        # Unload first
        if not self.unload_plugin(plugin_id):
            return False

        # Try to reload
        plugin_file = self.plugins_dir / f"{plugin_id}.py"
        if plugin_file.exists():
            return self.load_plugin_from_file(plugin_id, plugin_file)
        else:
            return self.load_plugin_from_module(plugin_id)

    def shutdown_all(self):
        """Shutdown all plugins"""
        for plugin_id in list(self.plugins.keys()):
            self.unload_plugin(plugin_id)

    def create_plugin_template(self, plugin_name: str) -> str:
        """
        Create a plugin template file

        Args:
            plugin_name: Name for the new plugin

        Returns:
            Path to created template file
        """
        template = f'''"""
{plugin_name} Plugin for Kali GPT
"""

from kali_gpt.plugins.plugin_base import KaliGPTPlugin
from typing import Dict, List, Optional

class {plugin_name.replace("_", " ").title().replace(" ", "")}Plugin(KaliGPTPlugin):
    """Custom plugin: {plugin_name}"""

    def __init__(self):
        super().__init__()
        self.name = "{plugin_name}"
        self.version = "1.0.0"
        self.description = "Description of {plugin_name}"
        self.author = "Your Name"

    def get_metadata(self) -> Dict[str, str]:
        return {{
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author
        }}

    def on_init(self, app) -> bool:
        # Initialize your plugin here
        print(f"[{{self.name}}] Initialized")
        return True

    def on_command_execute(self, command: str, context: Dict) -> Optional[str]:
        # Modify or analyze commands before execution
        return command

    def on_output_analysis(self, command: str, output: str, context: Dict) -> Optional[Dict]:
        # Analyze command output
        return None

    def get_menu_items(self) -> List[Dict]:
        # Provide custom menu items
        return []

    def shutdown(self) -> bool:
        print(f"[{{self.name}}] Shutting down")
        return True
'''

        template_file = self.plugins_dir / f"{plugin_name}.py"
        with open(template_file, 'w') as f:
            f.write(template)

        return str(template_file)
