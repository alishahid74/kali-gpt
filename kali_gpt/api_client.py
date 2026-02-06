#!/usr/bin/env python3
"""
Kali-GPT API Client

Command-line interface for interacting with the Kali-GPT API server.

Usage:
    python3 api_client.py --help
    python3 api_client.py targets list
    python3 api_client.py scans create --target-id <id> --type full
    python3 api_client.py findings list --severity high
"""

import os
import sys
import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("requests not installed. Run: pip install requests")
    sys.exit(1)


class KaliGPTClient:
    """Client for Kali-GPT API"""
    
    def __init__(self, base_url: str = None, api_key: str = None):
        self.base_url = base_url or os.getenv("KALI_GPT_API_URL", "http://localhost:8000")
        self.api_key = api_key or os.getenv("KALI_GPT_API_KEY", "")
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers["X-API-Key"] = self.api_key
    
    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make API request"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            resp = self.session.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        except requests.exceptions.ConnectionError:
            print(f"❌ Cannot connect to API at {self.base_url}")
            print("   Is the server running? Start with: python3 api_server.py")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            try:
                error = resp.json()
                print(f"❌ API Error: {error.get('detail', str(e))}")
            except:
                print(f"❌ HTTP Error: {e}")
            sys.exit(1)
    
    # ----- Health -----
    
    def health(self) -> dict:
        """Check API health"""
        return self._request("GET", "/health")
    
    def stats(self) -> dict:
        """Get statistics"""
        return self._request("GET", "/stats")
    
    def tools(self) -> list:
        """List available tools"""
        return self._request("GET", "/tools")
    
    # ----- Targets -----
    
    def create_target(self, name: str, host: str, description: str = None,
                      tags: list = None, scope: list = None) -> dict:
        """Create a new target"""
        data = {
            "name": name,
            "host": host,
            "description": description or "",
            "tags": tags or [],
            "scope": scope or [host],
            "out_of_scope": []
        }
        return self._request("POST", "/targets", json=data)
    
    def list_targets(self, limit: int = 50) -> list:
        """List all targets"""
        return self._request("GET", f"/targets?limit={limit}")
    
    def get_target(self, target_id: str) -> dict:
        """Get a specific target"""
        return self._request("GET", f"/targets/{target_id}")
    
    def delete_target(self, target_id: str) -> dict:
        """Delete a target"""
        return self._request("DELETE", f"/targets/{target_id}")
    
    # ----- Scans -----
    
    def create_scan(self, target_id: str, scan_type: str = "standard",
                    tools: list = None, options: dict = None) -> dict:
        """Create and start a scan"""
        data = {
            "target_id": target_id,
            "scan_type": scan_type,
            "tools": tools or [],
            "options": options or {}
        }
        return self._request("POST", "/scans", json=data)
    
    def list_scans(self, target_id: str = None, status: str = None,
                   limit: int = 50) -> list:
        """List scans"""
        params = [f"limit={limit}"]
        if target_id:
            params.append(f"target_id={target_id}")
        if status:
            params.append(f"status={status}")
        
        return self._request("GET", f"/scans?{'&'.join(params)}")
    
    def get_scan(self, scan_id: str) -> dict:
        """Get a specific scan"""
        return self._request("GET", f"/scans/{scan_id}")
    
    def start_scan(self, scan_id: str) -> dict:
        """Start a pending scan"""
        return self._request("POST", f"/scans/{scan_id}/start")
    
    def cancel_scan(self, scan_id: str) -> dict:
        """Cancel a running scan"""
        return self._request("POST", f"/scans/{scan_id}/cancel")
    
    def get_scan_logs(self, scan_id: str, limit: int = 100) -> dict:
        """Get scan logs"""
        return self._request("GET", f"/scans/{scan_id}/logs?limit={limit}")
    
    # ----- Findings -----
    
    def list_findings(self, target_id: str = None, scan_id: str = None,
                      severity: str = None, status: str = None,
                      limit: int = 50) -> list:
        """List findings"""
        params = [f"limit={limit}"]
        if target_id:
            params.append(f"target_id={target_id}")
        if scan_id:
            params.append(f"scan_id={scan_id}")
        if severity:
            params.append(f"severity={severity}")
        if status:
            params.append(f"status={status}")
        
        return self._request("GET", f"/findings?{'&'.join(params)}")
    
    def get_finding(self, finding_id: str) -> dict:
        """Get a specific finding"""
        return self._request("GET", f"/findings/{finding_id}")
    
    def update_finding(self, finding_id: str, **updates) -> dict:
        """Update a finding"""
        return self._request("PATCH", f"/findings/{finding_id}", json=updates)
    
    def delete_finding(self, finding_id: str) -> dict:
        """Delete a finding"""
        return self._request("DELETE", f"/findings/{finding_id}")
    
    # ----- API Keys -----
    
    def create_api_key(self, name: str, permissions: list = None,
                       expires_in_days: int = None) -> dict:
        """Create a new API key"""
        data = {
            "name": name,
            "permissions": permissions or ["read", "write"],
            "expires_in_days": expires_in_days
        }
        return self._request("POST", "/api-keys", json=data)
    
    def list_api_keys(self) -> list:
        """List all API keys"""
        return self._request("GET", "/api-keys")
    
    def revoke_api_key(self, key_id: str) -> dict:
        """Revoke an API key"""
        return self._request("DELETE", f"/api-keys/{key_id}")


# =============================================================================
# CLI HELPERS
# =============================================================================

def print_table(data: list, columns: list, title: str = None):
    """Print data as a table"""
    if not data:
        print("  No results found")
        return
    
    if title:
        print(f"\n{title}")
        print("=" * 60)
    
    # Calculate column widths
    widths = {}
    for col in columns:
        widths[col] = max(
            len(col),
            max(len(str(row.get(col, ""))[:30]) for row in data)
        )
    
    # Header
    header = " | ".join(col.ljust(widths[col]) for col in columns)
    print(header)
    print("-" * len(header))
    
    # Rows
    for row in data:
        line = " | ".join(
            str(row.get(col, ""))[:30].ljust(widths[col])
            for col in columns
        )
        print(line)
    
    print()


def print_json(data, indent: int = 2):
    """Print data as formatted JSON"""
    print(json.dumps(data, indent=indent, default=str))


def severity_color(severity: str) -> str:
    """Get color code for severity"""
    colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[92m',       # Green
        'info': '\033[90m',      # Gray
    }
    reset = '\033[0m'
    return f"{colors.get(severity, '')}{severity}{reset}"


# =============================================================================
# CLI COMMANDS
# =============================================================================

def cmd_health(client: KaliGPTClient, args):
    """Check API health"""
    health = client.health()
    print(f"\n🏥 API Health: {health['status'].upper()}")
    print(f"   Version:      {health['version']}")
    print(f"   Uptime:       {health['uptime_seconds']} seconds")
    print(f"   Database:     {health['database']}")
    print(f"   AI Service:   {health['ai_service']}")
    print(f"   Active Scans: {health['active_scans']}")
    print(f"   System Load:  {health['system_load']:.2f}")
    print()


def cmd_stats(client: KaliGPTClient, args):
    """Show statistics"""
    stats = client.stats()
    print(f"\n📊 Statistics")
    print("=" * 40)
    print(f"   Targets:  {stats['total_targets']}")
    print(f"   Scans:    {stats['total_scans']}")
    print(f"   Findings: {stats['total_findings']}")
    print()
    
    if stats['findings_by_severity']:
        print("   Findings by Severity:")
        for sev, count in stats['findings_by_severity'].items():
            print(f"      {severity_color(sev)}: {count}")
    print()


def cmd_tools(client: KaliGPTClient, args):
    """List available tools"""
    tools = client.tools()
    print_table(tools, ['name', 'category', 'installed', 'description'], "🔧 Available Tools")


def cmd_targets_list(client: KaliGPTClient, args):
    """List targets"""
    targets = client.list_targets(limit=args.limit)
    print_table(targets, ['id', 'name', 'host', 'scan_count', 'finding_count'], "🎯 Targets")


def cmd_targets_create(client: KaliGPTClient, args):
    """Create a target"""
    target = client.create_target(
        name=args.name,
        host=args.host,
        description=args.description,
        tags=args.tags.split(',') if args.tags else []
    )
    print(f"\n✅ Target created!")
    print(f"   ID:   {target['id']}")
    print(f"   Name: {target['name']}")
    print(f"   Host: {target['host']}")
    print()


def cmd_targets_delete(client: KaliGPTClient, args):
    """Delete a target"""
    result = client.delete_target(args.id)
    print(f"✅ Target {args.id} deleted")


def cmd_scans_list(client: KaliGPTClient, args):
    """List scans"""
    scans = client.list_scans(
        target_id=args.target_id,
        status=args.status,
        limit=args.limit
    )
    print_table(scans, ['id', 'target_name', 'scan_type', 'status', 'progress', 'finding_count'], "🔍 Scans")


def cmd_scans_create(client: KaliGPTClient, args):
    """Create and start a scan"""
    scan = client.create_scan(
        target_id=args.target_id,
        scan_type=args.type,
        tools=args.tools.split(',') if args.tools else []
    )
    print(f"\n🚀 Scan created and starting!")
    print(f"   ID:     {scan['id']}")
    print(f"   Target: {scan['target_name']} ({scan['target_host']})")
    print(f"   Type:   {scan['scan_type']}")
    print(f"   Status: {scan['status']}")
    print()
    print(f"   Monitor: python3 api_client.py scans get {scan['id']}")
    print()


def cmd_scans_get(client: KaliGPTClient, args):
    """Get scan details"""
    scan = client.get_scan(args.id)
    print(f"\n🔍 Scan: {scan['id']}")
    print("=" * 60)
    print(f"   Target:   {scan['target_name']} ({scan['target_host']})")
    print(f"   Type:     {scan['scan_type']}")
    print(f"   Status:   {scan['status']}")
    print(f"   Progress: {scan['progress']}%")
    if scan['current_tool']:
        print(f"   Current:  {scan['current_tool']}")
    print(f"   Findings: {scan['finding_count']}")
    if scan['started_at']:
        print(f"   Started:  {scan['started_at']}")
    if scan['completed_at']:
        print(f"   Completed: {scan['completed_at']}")
    if scan['error']:
        print(f"   Error:    {scan['error']}")
    print()


def cmd_scans_cancel(client: KaliGPTClient, args):
    """Cancel a scan"""
    result = client.cancel_scan(args.id)
    print(f"✅ Scan {args.id} cancelled")


def cmd_scans_logs(client: KaliGPTClient, args):
    """Get scan logs"""
    result = client.get_scan_logs(args.id, limit=args.limit)
    logs = result.get('logs', [])
    
    print(f"\n📋 Logs for scan {args.id}")
    print("=" * 60)
    
    for log in logs:
        level = log.get('level', 'info').upper()
        tool = log.get('tool', '')
        msg = log.get('message', '')
        ts = log.get('timestamp', '')
        
        level_color = {
            'ERROR': '\033[91m',
            'WARNING': '\033[93m',
            'INFO': '\033[0m',
        }.get(level, '\033[0m')
        
        print(f"{level_color}[{level}]{tool:>10} {msg}\033[0m")
    print()


def cmd_findings_list(client: KaliGPTClient, args):
    """List findings"""
    findings = client.list_findings(
        target_id=args.target_id,
        scan_id=args.scan_id,
        severity=args.severity,
        status=args.status,
        limit=args.limit
    )
    
    print(f"\n🐛 Findings ({len(findings)} total)")
    print("=" * 80)
    
    for f in findings:
        sev = severity_color(f['severity'])
        print(f"[{sev:>8}] {f['title'][:60]}")
        print(f"           ID: {f['id']} | Status: {f['status']} | Category: {f['category']}")
        if f.get('affected_hosts'):
            print(f"           Hosts: {', '.join(f['affected_hosts'][:3])}")
        print()


def cmd_findings_get(client: KaliGPTClient, args):
    """Get finding details"""
    f = client.get_finding(args.id)
    
    print(f"\n🐛 Finding: {f['title']}")
    print("=" * 60)
    print(f"   ID:       {f['id']}")
    print(f"   Severity: {severity_color(f['severity'])}")
    print(f"   Status:   {f['status']}")
    print(f"   Category: {f['category']}")
    if f.get('cvss_score'):
        print(f"   CVSS:     {f['cvss_score']}")
    if f.get('cve_ids'):
        print(f"   CVEs:     {', '.join(f['cve_ids'])}")
    print()
    print("   Description:")
    print(f"   {f['description'][:500]}")
    print()
    if f.get('remediation'):
        print("   Remediation:")
        print(f"   {f['remediation'][:500]}")
        print()


def cmd_apikeys_list(client: KaliGPTClient, args):
    """List API keys"""
    keys = client.list_api_keys()
    print_table(keys, ['id', 'name', 'key_prefix', 'permissions', 'is_active'], "🔑 API Keys")


def cmd_apikeys_create(client: KaliGPTClient, args):
    """Create API key"""
    perms = args.permissions.split(',') if args.permissions else ['read', 'write']
    result = client.create_api_key(
        name=args.name,
        permissions=perms,
        expires_in_days=args.expires
    )
    
    print(f"\n🔑 API Key Created!")
    print("=" * 60)
    print(f"   Key: {result['key']}")
    print("=" * 60)
    print("   ⚠️  Save this key! It won't be shown again.")
    print()


def cmd_apikeys_revoke(client: KaliGPTClient, args):
    """Revoke API key"""
    result = client.revoke_api_key(args.id)
    print(f"✅ API key {args.id} revoked")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Kali-GPT API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s health
  %(prog)s targets list
  %(prog)s targets create --name "Test" --host 10.10.10.5
  %(prog)s scans create --target-id <id> --type full
  %(prog)s findings list --severity critical
        """
    )
    
    parser.add_argument("--url", default=os.getenv("KALI_GPT_API_URL", "http://localhost:8000"),
                        help="API base URL")
    parser.add_argument("--api-key", default=os.getenv("KALI_GPT_API_KEY", ""),
                        help="API key")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Health
    subparsers.add_parser("health", help="Check API health")
    subparsers.add_parser("stats", help="Show statistics")
    subparsers.add_parser("tools", help="List available tools")
    
    # Targets
    targets_parser = subparsers.add_parser("targets", help="Target management")
    targets_sub = targets_parser.add_subparsers(dest="subcommand")
    
    targets_list = targets_sub.add_parser("list", help="List targets")
    targets_list.add_argument("--limit", type=int, default=50)
    
    targets_create = targets_sub.add_parser("create", help="Create target")
    targets_create.add_argument("--name", required=True)
    targets_create.add_argument("--host", required=True)
    targets_create.add_argument("--description", default="")
    targets_create.add_argument("--tags", default="")
    
    targets_delete = targets_sub.add_parser("delete", help="Delete target")
    targets_delete.add_argument("id")
    
    # Scans
    scans_parser = subparsers.add_parser("scans", help="Scan management")
    scans_sub = scans_parser.add_subparsers(dest="subcommand")
    
    scans_list = scans_sub.add_parser("list", help="List scans")
    scans_list.add_argument("--target-id")
    scans_list.add_argument("--status")
    scans_list.add_argument("--limit", type=int, default=50)
    
    scans_create = scans_sub.add_parser("create", help="Create and start scan")
    scans_create.add_argument("--target-id", required=True)
    scans_create.add_argument("--type", default="standard",
                              choices=["quick", "standard", "full", "stealth", "web", "network"])
    scans_create.add_argument("--tools", help="Comma-separated tool list")
    
    scans_get = scans_sub.add_parser("get", help="Get scan details")
    scans_get.add_argument("id")
    
    scans_cancel = scans_sub.add_parser("cancel", help="Cancel scan")
    scans_cancel.add_argument("id")
    
    scans_logs = scans_sub.add_parser("logs", help="Get scan logs")
    scans_logs.add_argument("id")
    scans_logs.add_argument("--limit", type=int, default=50)
    
    # Findings
    findings_parser = subparsers.add_parser("findings", help="Finding management")
    findings_sub = findings_parser.add_subparsers(dest="subcommand")
    
    findings_list = findings_sub.add_parser("list", help="List findings")
    findings_list.add_argument("--target-id")
    findings_list.add_argument("--scan-id")
    findings_list.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
    findings_list.add_argument("--status")
    findings_list.add_argument("--limit", type=int, default=50)
    
    findings_get = findings_sub.add_parser("get", help="Get finding details")
    findings_get.add_argument("id")
    
    # API Keys
    keys_parser = subparsers.add_parser("api-keys", help="API key management")
    keys_sub = keys_parser.add_subparsers(dest="subcommand")
    
    keys_list = keys_sub.add_parser("list", help="List API keys")
    
    keys_create = keys_sub.add_parser("create", help="Create API key")
    keys_create.add_argument("--name", required=True)
    keys_create.add_argument("--permissions", default="read,write")
    keys_create.add_argument("--expires", type=int, help="Days until expiry")
    
    keys_revoke = keys_sub.add_parser("revoke", help="Revoke API key")
    keys_revoke.add_argument("id")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Create client
    client = KaliGPTClient(base_url=args.url, api_key=args.api_key)
    
    # Route commands
    commands = {
        ("health", None): cmd_health,
        ("stats", None): cmd_stats,
        ("tools", None): cmd_tools,
        ("targets", "list"): cmd_targets_list,
        ("targets", "create"): cmd_targets_create,
        ("targets", "delete"): cmd_targets_delete,
        ("scans", "list"): cmd_scans_list,
        ("scans", "create"): cmd_scans_create,
        ("scans", "get"): cmd_scans_get,
        ("scans", "cancel"): cmd_scans_cancel,
        ("scans", "logs"): cmd_scans_logs,
        ("findings", "list"): cmd_findings_list,
        ("findings", "get"): cmd_findings_get,
        ("api-keys", "list"): cmd_apikeys_list,
        ("api-keys", "create"): cmd_apikeys_create,
        ("api-keys", "revoke"): cmd_apikeys_revoke,
    }
    
    subcommand = getattr(args, 'subcommand', None)
    handler = commands.get((args.command, subcommand))
    
    if handler:
        handler(client, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
