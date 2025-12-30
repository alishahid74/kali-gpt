"""
Report Generator

Generates professional penetration testing reports in multiple formats:
- HTML (interactive with charts)
- Markdown (for documentation)
- JSON (for integrations)
- PDF (via HTML conversion)
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import json
from jinja2 import Template


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    title: str = "Penetration Test Report"
    author: str = "Kali-GPT v3"
    company: str = ""
    classification: str = "CONFIDENTIAL"
    logo_path: Optional[str] = None
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_mitre_mapping: bool = True
    include_recommendations: bool = True


class ReportGenerator:
    """
    Professional penetration test report generator
    """
    
    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
    
    def generate_html(
        self,
        context,  # EnhancedEngagementContext
        output_path: str
    ) -> str:
        """Generate HTML report"""
        
        template = Template(self._get_html_template())
        
        # Prepare data
        data = self._prepare_report_data(context)
        
        # Render template
        html = template.render(
            config=self.config,
            data=data,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Write to file
        Path(output_path).write_text(html)
        
        return output_path
    
    def generate_markdown(
        self,
        context,
        output_path: str
    ) -> str:
        """Generate Markdown report"""
        
        data = self._prepare_report_data(context)
        
        md_lines = [
            f"# {self.config.title}",
            "",
            f"**Classification:** {self.config.classification}",
            f"**Author:** {self.config.author}",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "---",
            "",
        ]
        
        # Executive Summary
        if self.config.include_executive_summary:
            md_lines.extend([
                "## Executive Summary",
                "",
                f"Target: **{data['target']}**",
                "",
                f"| Metric | Value |",
                f"|--------|-------|",
                f"| Services Discovered | {data['stats']['services_count']} |",
                f"| Vulnerabilities Found | {data['stats']['vulns_count']} |",
                f"| Critical Vulnerabilities | {data['stats']['critical_vulns']} |",
                f"| High Vulnerabilities | {data['stats']['high_vulns']} |",
                f"| Actions Executed | {data['stats']['actions_count']} |",
                "",
            ])
        
        # Discovered Services
        md_lines.extend([
            "## Discovered Services",
            "",
            "| Host | Port | Service | Version |",
            "|------|------|---------|---------|",
        ])
        
        for svc in data['services'][:20]:
            md_lines.append(
                f"| {svc['host']} | {svc['port']} | {svc['service']} | {svc.get('version', 'N/A')} |"
            )
        
        md_lines.append("")
        
        # Vulnerabilities
        if data['vulnerabilities']:
            md_lines.extend([
                "## Vulnerabilities",
                "",
            ])
            
            for vuln in data['vulnerabilities']:
                severity = vuln.get('severity', 'unknown').upper()
                md_lines.extend([
                    f"### {vuln.get('type', 'Unknown Vulnerability')}",
                    "",
                    f"**Severity:** {severity}",
                    f"**Target:** {vuln.get('target', 'N/A')}",
                    "",
                    vuln.get('description', 'No description available.'),
                    "",
                ])
        
        # MITRE ATT&CK Mapping
        if self.config.include_mitre_mapping and data.get('mitre_coverage'):
            md_lines.extend([
                "## MITRE ATT&CK Mapping",
                "",
                f"**Tactics Covered:** {', '.join(data['mitre_coverage'].get('tactics_covered', []))}",
                f"**Techniques Used:** {data['mitre_coverage'].get('techniques_used', 0)}",
                "",
            ])
            
            for tactic, techniques in data['mitre_coverage'].get('techniques_by_tactic', {}).items():
                md_lines.append(f"### {tactic.replace('_', ' ').title()}")
                md_lines.append("")
                for tech in techniques:
                    md_lines.append(f"- **{tech['id']}**: {tech['name']}")
                md_lines.append("")
        
        # Attack Path
        md_lines.extend([
            "## Attack Path",
            "",
            "| # | Tool | Command | Status | Technique |",
            "|---|------|---------|--------|-----------|",
        ])
        
        for i, step in enumerate(data['attack_path'][:30], 1):
            technique = step.get('mitre', {})
            tech_str = f"{technique.get('technique_id', '')} - {technique.get('technique_name', '')}" if technique else "N/A"
            cmd_short = step.get('command', '')[:40] + "..." if len(step.get('command', '')) > 40 else step.get('command', '')
            md_lines.append(
                f"| {i} | {step.get('tool', 'N/A')} | `{cmd_short}` | {step.get('status', 'N/A')} | {tech_str} |"
            )
        
        md_lines.append("")
        
        # Recommendations
        if self.config.include_recommendations:
            md_lines.extend([
                "## Recommendations",
                "",
            ])
            
            for rec in data.get('recommendations', []):
                md_lines.extend([
                    f"### {rec['title']}",
                    "",
                    f"**Priority:** {rec['priority']}",
                    "",
                    rec['description'],
                    "",
                ])
        
        # Footer
        md_lines.extend([
            "---",
            "",
            f"*Report generated by {self.config.author}*",
        ])
        
        # Write to file
        content = "\n".join(md_lines)
        Path(output_path).write_text(content)
        
        return output_path
    
    def generate_json(
        self,
        context,
        output_path: str
    ) -> str:
        """Generate JSON report for integrations"""
        
        data = self._prepare_report_data(context)
        
        report = {
            "metadata": {
                "title": self.config.title,
                "author": self.config.author,
                "classification": self.config.classification,
                "generated_at": datetime.now().isoformat()
            },
            "target": data['target'],
            "scope": data.get('scope', []),
            "statistics": data['stats'],
            "services": data['services'],
            "vulnerabilities": data['vulnerabilities'],
            "credentials": data.get('credentials', []),
            "attack_path": data['attack_path'],
            "mitre_coverage": data.get('mitre_coverage', {}),
            "findings": data.get('findings', {}),
            "recommendations": data.get('recommendations', [])
        }
        
        Path(output_path).write_text(json.dumps(report, indent=2))
        
        return output_path
    
    def _prepare_report_data(self, context) -> Dict[str, Any]:
        """Prepare data for report templates"""
        
        # Count vulnerability severities
        vulns = context.discovered_vulnerabilities
        critical_count = sum(1 for v in vulns if v.get('severity', '').lower() == 'critical')
        high_count = sum(1 for v in vulns if v.get('severity', '').lower() == 'high')
        
        # Get services from context
        services = []
        for svc in getattr(context, 'discovered_services', []):
            services.append({
                'host': svc.host if hasattr(svc, 'host') else svc.get('host', ''),
                'port': svc.port if hasattr(svc, 'port') else svc.get('port', ''),
                'service': svc.service.value if hasattr(svc, 'service') else svc.get('service', ''),
                'version': svc.version if hasattr(svc, 'version') else svc.get('version', '')
            })
        
        # Also include from discovered_hosts if services empty
        if not services:
            for host in context.discovered_hosts:
                services.append({
                    'host': host.get('host', context.target),
                    'port': host.get('port', ''),
                    'service': host.get('service', ''),
                    'version': host.get('version', '')
                })
        
        # Build attack path
        attack_path = []
        for action in context.actions_taken:
            if isinstance(action, dict):
                attack_path.append(action)
            else:
                attack_path.append({
                    'tool': getattr(action, 'tool', str(action)),
                    'command': getattr(action, 'command', ''),
                    'status': 'executed'
                })
        
        # Get MITRE coverage if available
        mitre_coverage = {}
        if hasattr(context, 'techniques_used'):
            mitre_coverage = {
                'tactics_covered': list(set([
                    t.split('.')[0] for t in context.techniques_used
                ])) if context.techniques_used else [],
                'techniques_used': len(context.techniques_used),
                'techniques_by_tactic': {}
            }
        
        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(context)
        
        return {
            'target': context.target,
            'scope': context.scope,
            'stats': {
                'services_count': len(services),
                'vulns_count': len(vulns),
                'critical_vulns': critical_count,
                'high_vulns': high_count,
                'actions_count': len(context.actions_taken),
                'credentials_found': len(context.credentials_found)
            },
            'services': services,
            'vulnerabilities': vulns,
            'credentials': context.credentials_found,
            'attack_path': attack_path,
            'mitre_coverage': mitre_coverage,
            'findings': getattr(context, 'findings', {}),
            'recommendations': recommendations
        }
    
    def _generate_recommendations(self, context) -> List[Dict[str, str]]:
        """Generate recommendations based on findings"""
        
        recommendations = []
        
        # Check for common issues
        vulns = context.discovered_vulnerabilities
        
        # SQL Injection
        if any('sql' in str(v).lower() for v in vulns):
            recommendations.append({
                'title': 'SQL Injection Remediation',
                'priority': 'CRITICAL',
                'description': 'Implement parameterized queries or prepared statements for all database interactions. Use ORM frameworks where possible. Apply input validation and output encoding.'
            })
        
        # XSS
        if any('xss' in str(v).lower() or 'cross-site' in str(v).lower() for v in vulns):
            recommendations.append({
                'title': 'Cross-Site Scripting (XSS) Remediation',
                'priority': 'HIGH',
                'description': 'Implement Content Security Policy (CSP) headers. Use output encoding for all user-controlled data. Consider using frameworks with built-in XSS protection.'
            })
        
        # Open ports
        services = getattr(context, 'discovered_services', [])
        if len(services) > 10:
            recommendations.append({
                'title': 'Reduce Attack Surface',
                'priority': 'MEDIUM',
                'description': f'Review the {len(services)} exposed services and disable unnecessary ones. Implement firewall rules to restrict access to essential services only.'
            })
        
        # Default credentials
        if context.credentials_found:
            recommendations.append({
                'title': 'Credential Security',
                'priority': 'CRITICAL',
                'description': 'Change all default and discovered credentials immediately. Implement strong password policies and multi-factor authentication where possible.'
            })
        
        # SSL/TLS
        findings = getattr(context, 'findings', {})
        if 'ssl_vulnerabilities' in findings:
            recommendations.append({
                'title': 'SSL/TLS Configuration',
                'priority': 'HIGH',
                'description': 'Update SSL/TLS configuration to disable weak protocols (SSLv3, TLS 1.0, 1.1) and cipher suites. Ensure proper certificate management.'
            })
        
        # Always add general recommendations
        recommendations.extend([
            {
                'title': 'Regular Security Assessments',
                'priority': 'MEDIUM',
                'description': 'Conduct regular penetration testing and vulnerability assessments. Consider implementing a bug bounty program for continuous security feedback.'
            },
            {
                'title': 'Security Monitoring',
                'priority': 'MEDIUM',
                'description': 'Implement comprehensive logging and monitoring. Set up alerts for suspicious activities and failed authentication attempts.'
            }
        ])
        
        return recommendations
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ config.title }}</title>
    <style>
        :root {
            --primary: #1e3a5f;
            --secondary: #2ecc71;
            --danger: #e74c3c;
            --warning: #f39c12;
            --info: #3498db;
            --dark: #2c3e50;
            --light: #ecf0f1;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--dark);
            background: var(--light);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: var(--primary);
            color: white;
            padding: 40px 20px;
            text-align: center;
        }
        
        header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .classification {
            display: inline-block;
            background: var(--danger);
            color: white;
            padding: 5px 20px;
            border-radius: 3px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            color: var(--primary);
            font-size: 2rem;
        }
        
        .stat-card.critical h3 {
            color: var(--danger);
        }
        
        .stat-card.warning h3 {
            color: var(--warning);
        }
        
        section {
            background: white;
            padding: 30px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        section h2 {
            color: var(--primary);
            border-bottom: 2px solid var(--secondary);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background: var(--primary);
            color: white;
        }
        
        tr:hover {
            background: #f5f5f5;
        }
        
        .severity {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: bold;
            color: white;
        }
        
        .severity.critical { background: #c0392b; }
        .severity.high { background: var(--danger); }
        .severity.medium { background: var(--warning); }
        .severity.low { background: var(--info); }
        .severity.info { background: #95a5a6; }
        
        .vuln-card {
            border-left: 4px solid var(--danger);
            padding: 15px;
            margin: 15px 0;
            background: #fff9f9;
        }
        
        .vuln-card.high {
            border-color: var(--danger);
            background: #fff5f5;
        }
        
        .vuln-card.medium {
            border-color: var(--warning);
            background: #fffbf0;
        }
        
        .recommendation {
            border-left: 4px solid var(--secondary);
            padding: 15px;
            margin: 15px 0;
            background: #f0fff4;
        }
        
        .mitre-tag {
            display: inline-block;
            background: var(--info);
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.75rem;
            margin: 2px;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #666;
        }
        
        @media print {
            body {
                background: white;
            }
            
            section {
                box-shadow: none;
                border: 1px solid #ddd;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>{{ config.title }}</h1>
        <div class="classification">{{ config.classification }}</div>
        <p>Generated: {{ generated_at }}</p>
        <p>Author: {{ config.author }}</p>
    </header>
    
    <div class="container">
        <!-- Executive Summary -->
        <section>
            <h2>Executive Summary</h2>
            <p><strong>Target:</strong> {{ data.target }}</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{{ data.stats.services_count }}</h3>
                    <p>Services Discovered</p>
                </div>
                <div class="stat-card critical">
                    <h3>{{ data.stats.vulns_count }}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
                <div class="stat-card critical">
                    <h3>{{ data.stats.critical_vulns }}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-card warning">
                    <h3>{{ data.stats.high_vulns }}</h3>
                    <p>High</p>
                </div>
                <div class="stat-card">
                    <h3>{{ data.stats.actions_count }}</h3>
                    <p>Actions Executed</p>
                </div>
            </div>
        </section>
        
        <!-- Discovered Services -->
        <section>
            <h2>Discovered Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {% for svc in data.services[:30] %}
                    <tr>
                        <td>{{ svc.host }}</td>
                        <td>{{ svc.port }}</td>
                        <td>{{ svc.service }}</td>
                        <td>{{ svc.version or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        
        <!-- Vulnerabilities -->
        {% if data.vulnerabilities %}
        <section>
            <h2>Vulnerabilities</h2>
            {% for vuln in data.vulnerabilities %}
            <div class="vuln-card {{ vuln.severity|default('medium')|lower }}">
                <h3>{{ vuln.type|default('Unknown Vulnerability') }}</h3>
                <span class="severity {{ vuln.severity|default('medium')|lower }}">
                    {{ vuln.severity|default('MEDIUM')|upper }}
                </span>
                <p><strong>Target:</strong> {{ vuln.target|default(data.target) }}</p>
                <p>{{ vuln.description|default('No description available.') }}</p>
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        <!-- MITRE ATT&CK Coverage -->
        {% if data.mitre_coverage %}
        <section>
            <h2>MITRE ATT&CK Coverage</h2>
            <p><strong>Tactics Covered:</strong></p>
            {% for tactic in data.mitre_coverage.tactics_covered %}
            <span class="mitre-tag">{{ tactic }}</span>
            {% endfor %}
            <p style="margin-top: 15px;"><strong>Techniques Used:</strong> {{ data.mitre_coverage.techniques_used }}</p>
        </section>
        {% endif %}
        
        <!-- Attack Path -->
        <section>
            <h2>Attack Path</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Tool</th>
                        <th>Status</th>
                        <th>MITRE Technique</th>
                    </tr>
                </thead>
                <tbody>
                    {% for step in data.attack_path[:30] %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td>{{ step.tool }}</td>
                        <td>{{ step.status }}</td>
                        <td>
                            {% if step.mitre %}
                            <span class="mitre-tag">{{ step.mitre.technique_id }}</span>
                            {{ step.mitre.technique_name or '' }}
                            {% else %}
                            N/A
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        
        <!-- Recommendations -->
        {% if data.recommendations %}
        <section>
            <h2>Recommendations</h2>
            {% for rec in data.recommendations %}
            <div class="recommendation">
                <h3>{{ rec.title }}</h3>
                <span class="severity {{ rec.priority|lower }}">{{ rec.priority }}</span>
                <p>{{ rec.description }}</p>
            </div>
            {% endfor %}
        </section>
        {% endif %}
    </div>
    
    <footer>
        <p>Report generated by {{ config.author }}</p>
        <p>{{ generated_at }}</p>
    </footer>
</body>
</html>'''
