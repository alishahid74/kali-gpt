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
| Scanner integration | `kali_gpt/integrations/scanner.py` | Enhanced CLI (operator/AI input) | ✅ FIXED (validated argv via `execute_argv`, `shell=False`) |
| Metasploit integration | `kali_gpt/integrations/metasploit.py` | Enhanced CLI | ✅ FIXED (validated argv, `shell=False`, msf-input allowlists) |
| Core executor | `kali_gpt/modules/command_executor.py` | Interactive CLI, has validator + confirm | ✅ Added `execute_argv()` (safe argv API); string `execute()` kept for interactive use (see note) |
| Exploit engine | `kali_gpt/exploit_engine.py` | Autonomous/CLI | ✅ FIXED (CVE search → argv; template values validated, no shell metachars) |
| v4 agents | `kali_gpt/agents/agents_v4.py` | Autonomous (AI-composed) | ✅ FIXED (AI command → `shlex.split` + `shell=False`) |
| Autonomous script | `kali-gpt-autonomous.py` | Autonomous CLI (AI-composed commands) | ✅ FIXED (central `execute()` → argv; forensic inputs guarded at source; several helpers → argv) |
| Bug bounty scripts | `bug_bounty_hunter.py`, `kali_gpt/bug_bounty_hunter.py` | CLI | ✅ FIXED (root target validated at `recon()` entry; downstream assets are DNS/crawl-derived) |
| Multi-agent script | `multi_agent.py` | CLI | ✅ FIXED (AI commands → argv via `_run_ai_command`; interactive filepath/target guarded) |
| Advanced CLI | `kali-gpt-advanced.py` (line ~182) | Interactive, user confirms + dangerous-cmd detection | ⏳ Low risk (user-typed, confirmed) — left as-is |

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

1. ~~Migrate `scanner.py` and `metasploit.py`~~ — ✅ done (validated argv + `shell=False`).
2. ~~Add `execute_argv()` to `CommandExecutor`~~ — ✅ done; integrations route through it.
3. ~~Migrate autonomous, bug-bounty, multi-agent, agents_v4, exploit_engine~~ —
   ✅ done (see progress log).
4. Remove the now-redundant `mcp_server_secure.py` after confirming parity.
5. Add CI that fails on new `shell=True` with an f-string (a lint rule).

## Approach notes for the AI/CLI scripts

- **AI-composed commands** (agents_v4, multi_agent, autonomous `execute()`): the
  model's command string is `shlex.split` into an argv list and run with
  `shell=False`. Shell operators in model output become literal arguments and
  cannot chain a second command. (Trade-off: shell pipes/redirects in a single
  AI command no longer function — acceptable for safety.)
- **Interactive forensic/OSINT pipelines** that legitimately use pipes
  (`strings | grep | head`): the user-controlled value (filepath/url/target/
  image/path/wordlist) is rejected at its input source if it contains shell
  metacharacters, so it cannot break out of the pipeline. Where easy, individual
  calls were also converted to argv (e.g. steghide, john).
- **Exploit templates** (exploit_engine): the template is trusted (code-defined);
  substituted values are validated to contain no shell metacharacters.
- **Bug bounty**: the root target is validated at the `recon()` entry; downstream
  assets are DNS/crawl-derived hostnames/URLs.

## Progress log

- 2026-11-05: `mcp_server.py` fixed in place; validator + tests added.
- 2026-11-05: `scanner.py`, `metasploit.py` migrated to validated argv;
  `CommandExecutor.execute_argv()` added; test suite extended to 16 tests.
- 2026-11-05: `exploit_engine.py`, `agents_v4.py`, `multi_agent.py`,
  `kali-gpt-autonomous.py`, and both `bug_bounty_hunter.py` files hardened
  (argv for AI/command paths; input guards at source for interactive pipelines).
  Test suite now 17 tests, all passing. Remaining residual: a set of local,
  interactive forensic pipelines whose inputs are now guarded at the source.
