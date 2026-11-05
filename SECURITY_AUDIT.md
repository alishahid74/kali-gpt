# Command-Injection Audit (CWE-78)

**Date:** 2026-11-05
**Scope:** All `subprocess(..., shell=True)` and f-string command construction in the repo
**Trigger:** Issue #12 (MCP server command injection)

This document is an honest status of the whole codebase, not a claim that every
file is fixed. It records exactly what has been remediated, what remains, and the
trust boundary of each remaining sink so the risk can be judged correctly.

---

## Status summary

| Area | File | Exposure | Status |
|------|------|----------|--------|
| MCP tool execution | `kali_gpt/tools/mcp_server.py` | **Network / no confirmation** | ✅ FIXED in place (validated argv, `shell=False`) |
| MCP raw command endpoint | `kali_gpt/tools/mcp_server.py` `/api/command` | **Network / arbitrary RCE by design** | ✅ Disabled by default, opt-in env var, `shell=False` + `shlex` |
| Input validation library | `kali_gpt/utils/input_validator.py` | n/a | ✅ Added |
| Secure reference server | `kali_gpt/tools/mcp_server_secure.py` | n/a | ✅ Added earlier (now redundant with the in-place fix) |
| Regression tests | `tests/test_security.py` | n/a | ✅ Added (12 tests, passing) |
| Scanner integration | `kali_gpt/integrations/scanner.py` | Enhanced CLI (operator/AI input) | ⏳ Not yet fixed |
| Metasploit integration | `kali_gpt/integrations/metasploit.py` | Enhanced CLI | ⏳ Not yet fixed |
| Core executor | `kali_gpt/modules/command_executor.py` | Interactive CLI, has validator + confirm | ⏳ Partially mitigated (see note) |
| Exploit engine | `kali_gpt/exploit_engine.py` | Autonomous/CLI | ⏳ Not yet fixed |
| v4 agents | `kali_gpt/agents/agents_v4.py` | Autonomous | ⏳ Not yet fixed |
| Autonomous script | `kali-gpt-autonomous.py` | Autonomous CLI (AI-composed commands) | ⏳ Not yet fixed |
| Bug bounty scripts | `bug_bounty_hunter.py`, `kali_gpt/bug_bounty_hunter.py` | CLI | ⏳ Not yet fixed |
| Multi-agent script | `multi_agent.py` | CLI | ⏳ Not yet fixed |
| Advanced CLI | `kali-gpt-advanced.py` (line ~182) | Interactive, user confirms | ⏳ Low risk (user-typed, confirmed) |

---

## What was actually fixed (Issue #12)

The reported file, `kali_gpt/tools/mcp_server.py`, was patched **in place**:

- `execute_tool()` now calls `_build_command()`, which validates every
  user-controllable parameter through `kali_gpt/utils/input_validator.py`
  (allowlist-based) and returns an **argv list**.
- Execution goes through `_run_argv()`, which calls
  `subprocess.run(cmd, shell=False, ...)`. With a list and `shell=False`,
  arguments reach `execve()` directly, so `; | & \` $() \n` in any argument are
  literal data and cannot start a new command.
- The `/api/command` endpoint (arbitrary command execution behind a trivial
  blocklist) is now **disabled unless** `KALI_GPT_ALLOW_RAW_COMMAND=1`, and even
  then uses `shlex.split()` + `shell=False`.

> Note: an earlier pass added `mcp_server_secure.py` as a *separate* file but left
> the vulnerable `mcp_server.py` in place. That gap is now closed — the reported
> file itself is fixed. `mcp_server_secure.py` is kept as a reference and can be
> removed in a later cleanup.

Verified by `tests/test_security.py` (run: `python3 tests/test_security.py`):
injection payloads in `target`/`domain`/`url`/`ports`/`wordlist` are rejected,
legitimate inputs pass, and `_build_command` always returns a list.

---

## Remaining work and remediation pattern

The remaining files follow the **same** vulnerable pattern (f-string →
`shell=True`). They were **not** auto-rewritten because each tool's flags have
semantics that must be preserved, and a blind rewrite risks breaking real scans.
They should be migrated file-by-file using this pattern:

```python
# BEFORE
command = f"nmap {options} {target}"
subprocess.run(command, shell=True, ...)

# AFTER
from kali_gpt.utils.input_validator import validator
target = validator.validate_target(target)          # validate every input
cmd = ["nmap", *shlex.split(options_from_allowlist), target]  # argv list
subprocess.run(cmd, shell=False, ...)               # no shell
```

Key rules:
1. Validate every externally-influenced value (`target`, `ports`, `url`,
   `domain`, `wordlist`, `options`) with the allowlist validators.
2. Build an **argv list**; never interpolate into a shell string.
3. Call `subprocess.run(..., shell=False)` (the default).
4. For operator-supplied free-form options, parse with `shlex.split` and/or an
   allowlist of permitted flags rather than passing the raw string.

### Trust-boundary note on `command_executor.py`

`CommandExecutor.execute()` takes a full command string, screens it with
`CommandValidator.is_dangerous()`, and prompts for confirmation before running.
It is the **interactive** path (a local operator typing/approving commands, often
with intentional pipes/redirects), which is a materially different trust boundary
than the unauthenticated network MCP endpoint. It remains `shell=True` so that
legitimate interactive pipelines keep working; hardening it means adding a
validated **argv** execution method and routing programmatic callers (scanner,
metasploit, agents) through that instead of string building. Tracked as follow-up.

---

## Recommended next steps

1. Migrate `scanner.py` and `metasploit.py` (enhanced-mode integrations) first —
   they take target/port/option input and run under the enhanced CLI.
2. Add a `execute_argv(cmd: list)` method to `CommandExecutor` and route the
   integrations through it.
3. Migrate the autonomous and bug-bounty scripts.
4. Remove the now-redundant `mcp_server_secure.py` after confirming parity.
5. Add CI that fails on new `shell=True` with an f-string (a lint rule).
