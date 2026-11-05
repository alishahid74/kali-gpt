"""Command Execution Module"""

import subprocess
import shlex
import shutil
from typing import Dict, List, Optional
from ..utils.validators import CommandValidator

class CommandExecutor:
    """Handles safe command execution"""

    def __init__(self, config_manager):
        """Initialize command executor"""
        self.config = config_manager
        self.validator = CommandValidator()

    def execute_argv(self, args: List[str], timeout: Optional[int] = None,
                     check_tool: bool = True) -> Dict:
        """
        Execute a command given as an argv list, with shell=False.

        SECURITY (CWE-78): Prefer this over execute() for any command built from
        user- or AI-controlled values. Passing a list with shell=False hands the
        arguments straight to execve(), so shell metacharacters in any element
        (; | & ` $() newlines) are treated as literal data and can never start a
        new command. Callers are responsible for validating individual values
        (e.g. via kali_gpt.utils.input_validator) before building the list.

        Args:
            args: Command as a list, e.g. ["nmap", "-sV", target]
            timeout: Execution timeout in seconds
            check_tool: Verify the binary exists on PATH before running

        Returns:
            Dict with success, output, error, and return_code
        """
        if timeout is None:
            timeout = self.config.get("default_timeout", 30)

        if not args:
            return {'success': False, 'output': '', 'error': 'Empty command', 'return_code': -1}

        if check_tool and not shutil.which(args[0]):
            return {'success': False, 'output': '',
                    'error': f'Tool not found: {args[0]}', 'return_code': -1}

        try:
            result = subprocess.run(
                args,
                shell=False,  # SECURITY: never shell-interpret external input
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '',
                    'error': f'Command timed out after {timeout} seconds', 'return_code': -1}
        except Exception as e:
            return {'success': False, 'output': '',
                    'error': f'Execution error: {str(e)}', 'return_code': -1}

    def execute(self, command: str, timeout: Optional[int] = None,
                skip_validation: bool = False, require_confirmation: bool = None) -> Dict:
        """
        Execute a shell command safely

        Args:
            command: Command to execute
            timeout: Execution timeout in seconds
            skip_validation: Skip safety validation
            require_confirmation: Override config setting for confirmation

        Returns:
            Dict with success, output, error, and return_code
        """
        # Use config timeout if not specified
        if timeout is None:
            timeout = self.config.get("default_timeout", 30)

        # Use config confirmation setting if not specified
        if require_confirmation is None:
            require_confirmation = self.config.get("require_confirmation", True)

        # Validate command safety
        if not skip_validation:
            is_dangerous, reason = self.validator.is_dangerous(command)
            if is_dangerous:
                if require_confirmation:
                    print(f"\n[WARNING] Dangerous command detected: {reason}")
                    confirm = input("Do you want to proceed? (yes/no): ").lower()
                    if confirm != 'yes':
                        return {
                            'success': False,
                            'output': '',
                            'error': 'Command execution cancelled by user',
                            'return_code': -1
                        }
                else:
                    return {
                        'success': False,
                        'output': '',
                        'error': f'Dangerous command blocked: {reason}',
                        'return_code': -1
                    }

        try:
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': f'Command timed out after {timeout} seconds',
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': f'Execution error: {str(e)}',
                'return_code': -1
            }

    def execute_async(self, command: str) -> subprocess.Popen:
        """
        Execute a command asynchronously

        Args:
            command: Command to execute

        Returns:
            Popen object for the running process
        """
        return subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    def execute_with_input(self, command: str, stdin_input: str,
                          timeout: Optional[int] = None) -> Dict:
        """
        Execute a command with stdin input

        Args:
            command: Command to execute
            stdin_input: Input to send to stdin
            timeout: Execution timeout

        Returns:
            Dict with execution results
        """
        if timeout is None:
            timeout = self.config.get("default_timeout", 30)

        try:
            result = subprocess.run(
                command,
                shell=True,
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': f'Command timed out after {timeout} seconds',
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': f'Execution error: {str(e)}',
                'return_code': -1
            }
