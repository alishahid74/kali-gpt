"""
Kali-GPT v4.1 - Professional Report Generator

Generates client-ready penetration testing reports in:
- PDF format (executive + technical)
- HTML format (interactive)
- Markdown format
- JSON format (for integrations)

Author: Kali-GPT Team
Version: 4.1
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import html
import base64

# Try to import PDF library
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel
from rich.table import Table as RichTable
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()


# =============================================================================
# DATA CLASSES
# =============================================================================

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """A vulnerability finding"""
    title: str
    severity: str
    description: str
    affected: str  # Affected host/service
    evidence: str = ""
    remediation: str = ""
    cvss: float = 0.0
    cve: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Generic finding"""
    type: str  # port, service, vulnerability, credential, info
    value: str
    severity: str = "info"
    host: str = ""
    details: Dict = field(default_factory=dict)


@dataclass 
class EngagementInfo:
    """Engagement metadata"""
    title: str = "Penetration Test Report"
    client: str = "Client Name"
    assessor: str = "Kali-GPT"
    start_date: str = ""
    end_date: str = ""
    scope: List[str] = field(default_factory=list)
    methodology: str = "OWASP/PTES"
    classification: str = "CONFIDENTIAL"


@dataclass
class ReportData:
    """Complete report data"""
    engagement: EngagementInfo
    executive_summary: str = ""
    findings: List[Finding] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "engagement": asdict(self.engagement),
            "executive_summary": self.executive_summary,
            "findings": [asdict(f) if hasattr(f, '__dataclass_fields__') else f for f in self.findings],
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "recommendations": self.recommendations,
            "tools_used": self.tools_used,
            "timeline": self.timeline
        }


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """
    Professional penetration testing report generator.
    
    Supports multiple output formats:
    - PDF (requires reportlab)
    - HTML (standalone, no dependencies)
    - Markdown
    - JSON
    """
    
    def __init__(self):
        self.data: Optional[ReportData] = None
        self.output_dir = os.path.expanduser("~/kali-gpt-reports")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def create_report(self, 
                      findings: List[Finding],
                      target: str,
                      engagement_info: Optional[EngagementInfo] = None,
                      ai_service=None) -> ReportData:
        """
        Create report data from findings.
        
        Args:
            findings: List of findings from the engagement
            target: Primary target
            engagement_info: Optional engagement metadata
            ai_service: Optional AI service for generating summaries
        """
        if not engagement_info:
            engagement_info = EngagementInfo(
                title=f"Penetration Test Report - {target}",
                start_date=datetime.now().strftime("%Y-%m-%d"),
                end_date=datetime.now().strftime("%Y-%m-%d"),
                scope=[target]
            )
        
        # Convert findings to vulnerabilities
        vulnerabilities = self._findings_to_vulnerabilities(findings)
        
        # Generate executive summary
        if ai_service:
            exec_summary = self._generate_executive_summary(ai_service, findings, target)
        else:
            exec_summary = self._default_executive_summary(findings, target)
        
        # Generate recommendations
        if ai_service:
            recommendations = self._generate_recommendations(ai_service, vulnerabilities)
        else:
            recommendations = self._default_recommendations(vulnerabilities)
        
        # Extract tools used
        tools_used = list(set([f.details.get('source', 'Unknown') for f in findings if f.details.get('source')]))
        
        self.data = ReportData(
            engagement=engagement_info,
            executive_summary=exec_summary,
            findings=findings,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            tools_used=tools_used or ['nmap', 'gobuster', 'nikto', 'nuclei']
        )
        
        return self.data
    
    def _findings_to_vulnerabilities(self, findings: List[Finding]) -> List[Vulnerability]:
        """Convert findings to vulnerability objects"""
        vulnerabilities = []
        
        severity_findings = [f for f in findings if f.severity in ['critical', 'high', 'medium']]
        
        for f in severity_findings:
            vuln = Vulnerability(
                title=f.value[:100],
                severity=f.severity,
                description=f"Found {f.type}: {f.value}",
                affected=f.host or "Target",
                evidence=str(f.details),
                remediation=self._get_remediation(f)
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_remediation(self, finding: Finding) -> str:
        """Get remediation advice for a finding"""
        remediations = {
            "port": "Review if this port needs to be exposed. Consider firewall rules.",
            "vulnerability": "Apply vendor patches and updates. Review security configuration.",
            "credential": "Change compromised credentials immediately. Implement MFA.",
            "directory": "Review access controls. Remove sensitive files from web root.",
            "service": "Update to latest version. Disable unnecessary features.",
        }
        return remediations.get(finding.type, "Review and remediate based on best practices.")
    
    def _generate_executive_summary(self, ai_service, findings: List[Finding], target: str) -> str:
        """Generate AI-powered executive summary"""
        # Count by severity
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        prompt = f"""Write a professional executive summary for a penetration test report.

Target: {target}
Findings Summary:
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}
- Informational: {severity_counts.get('info', 0)}

Total Findings: {len(findings)}

Write 2-3 paragraphs covering:
1. Scope and objectives
2. Key findings and risk level
3. Overall security posture assessment

Be professional and concise."""

        return ai_service.ask(prompt)
    
    def _default_executive_summary(self, findings: List[Finding], target: str) -> str:
        """Generate default executive summary"""
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        
        risk_level = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM"
        
        return f"""
This report presents the findings from a penetration test conducted against {target}.

During the assessment, a total of {len(findings)} findings were identified, including {critical} critical and {high} high severity issues. The overall security posture is assessed as {risk_level} risk.

Key areas of concern include open ports and services, potential vulnerabilities in web applications, and configuration weaknesses. Immediate attention is recommended for all critical and high severity findings.

Detailed remediation guidance is provided for each finding in the technical sections of this report.
"""
    
    def _generate_recommendations(self, ai_service, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate AI-powered recommendations"""
        if not vulnerabilities:
            return ["Continue regular security assessments", "Maintain security awareness training"]
        
        vuln_summary = "\n".join([f"- [{v.severity}] {v.title}" for v in vulnerabilities[:10]])
        
        prompt = f"""Based on these penetration test findings, provide 5-7 prioritized security recommendations:

{vuln_summary}

Format as a numbered list. Be specific and actionable."""

        response = ai_service.ask(prompt)
        
        # Parse recommendations
        recommendations = []
        for line in response.split('\n'):
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-')):
                # Remove numbering
                clean = line.lstrip('0123456789.-) ').strip()
                if clean:
                    recommendations.append(clean)
        
        return recommendations or ["Patch all identified vulnerabilities", "Implement network segmentation"]
    
    def _default_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate default recommendations"""
        recommendations = [
            "Patch and update all systems to address known vulnerabilities",
            "Implement network segmentation to limit lateral movement",
            "Enable multi-factor authentication on all critical systems",
            "Conduct regular vulnerability assessments",
            "Implement a Web Application Firewall (WAF)",
            "Review and strengthen access controls",
            "Establish security monitoring and alerting"
        ]
        return recommendations
    
    # =========================================================================
    # HTML REPORT
    # =========================================================================
    
    def generate_html(self, output_path: Optional[str] = None) -> str:
        """Generate HTML report"""
        if not self.data:
            raise ValueError("No report data. Call create_report() first.")
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
        
        html_content = self._build_html()
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path
    
    def _build_html(self) -> str:
        """Build HTML report content"""
        d = self.data
        
        # Count findings by severity
        severity_counts = {}
        for f in d.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        # Build vulnerability rows
        vuln_rows = ""
        for i, v in enumerate(d.vulnerabilities, 1):
            color = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'info': '#17a2b8'
            }.get(v.severity, '#6c757d')
            
            vuln_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="severity-badge" style="background-color: {color}">{v.severity.upper()}</span></td>
                <td>{html.escape(v.title)}</td>
                <td>{html.escape(v.affected)}</td>
            </tr>
            """
        
        # Build finding details
        finding_details = ""
        for i, v in enumerate(d.vulnerabilities, 1):
            finding_details += f"""
            <div class="finding-card">
                <h4>Finding #{i}: {html.escape(v.title)}</h4>
                <p><strong>Severity:</strong> {v.severity.upper()}</p>
                <p><strong>Affected:</strong> {html.escape(v.affected)}</p>
                <p><strong>Description:</strong> {html.escape(v.description)}</p>
                <p><strong>Remediation:</strong> {html.escape(v.remediation)}</p>
            </div>
            """
        
        # Build recommendations
        rec_items = "".join([f"<li>{html.escape(r)}</li>" for r in d.recommendations])
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(d.engagement.title)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 10px;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .classification {{
            background: #dc3545;
            display: inline-block;
            padding: 5px 20px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 15px;
        }}
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .meta-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .meta-card h4 {{ color: #666; font-size: 0.9em; margin-bottom: 5px; }}
        .meta-card p {{ font-size: 1.1em; font-weight: 600; }}
        .section {{
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #1a1a2e;
            border-bottom: 3px solid #0d6efd;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .severity-summary {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }}
        .severity-box {{
            padding: 15px 25px;
            border-radius: 10px;
            color: white;
            text-align: center;
            min-width: 100px;
        }}
        .severity-box .count {{ font-size: 2em; font-weight: bold; }}
        .severity-box .label {{ font-size: 0.9em; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .finding-card {{
            border-left: 4px solid #0d6efd;
            padding: 20px;
            margin-bottom: 20px;
            background: #f8f9fa;
            border-radius: 0 10px 10px 0;
        }}
        .finding-card h4 {{ color: #1a1a2e; margin-bottom: 15px; }}
        .finding-card p {{ margin-bottom: 10px; }}
        ul {{ padding-left: 20px; }}
        li {{ margin-bottom: 10px; }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        @media print {{
            .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .severity-box {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 {html.escape(d.engagement.title)}</h1>
            <p>Prepared for: {html.escape(d.engagement.client)}</p>
            <span class="classification">{html.escape(d.engagement.classification)}</span>
        </div>
        
        <div class="meta-info">
            <div class="meta-card">
                <h4>Assessment Date</h4>
                <p>{d.engagement.start_date} - {d.engagement.end_date}</p>
            </div>
            <div class="meta-card">
                <h4>Assessor</h4>
                <p>{html.escape(d.engagement.assessor)}</p>
            </div>
            <div class="meta-card">
                <h4>Methodology</h4>
                <p>{html.escape(d.engagement.methodology)}</p>
            </div>
            <div class="meta-card">
                <h4>Total Findings</h4>
                <p>{len(d.findings)}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p>{html.escape(d.executive_summary).replace(chr(10), '<br>')}</p>
        </div>
        
        <div class="section">
            <h2>📈 Findings Overview</h2>
            <div class="severity-summary">
                <div class="severity-box critical">
                    <div class="count">{severity_counts.get('critical', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="severity-box high">
                    <div class="count">{severity_counts.get('high', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="severity-box medium">
                    <div class="count">{severity_counts.get('medium', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="severity-box low">
                    <div class="count">{severity_counts.get('low', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="severity-box info">
                    <div class="count">{severity_counts.get('info', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>Affected</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
            {finding_details if finding_details else '<p>No critical or high severity findings.</p>'}
        </div>
        
        <div class="section">
            <h2>✅ Recommendations</h2>
            <ol>
                {rec_items}
            </ol>
        </div>
        
        <div class="section">
            <h2>🛠️ Tools Used</h2>
            <p>{', '.join(d.tools_used) if d.tools_used else 'Various security tools'}</p>
        </div>
        
        <div class="section">
            <h2>📋 Scope</h2>
            <ul>
                {''.join([f'<li>{html.escape(s)}</li>' for s in d.engagement.scope]) if d.engagement.scope else '<li>As defined in engagement agreement</li>'}
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Kali-GPT v4.1 | {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
            <p>This report is confidential and intended for authorized recipients only.</p>
        </div>
    </div>
</body>
</html>"""
    
    # =========================================================================
    # PDF REPORT
    # =========================================================================
    
    def generate_pdf(self, output_path: Optional[str] = None) -> str:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab not installed. Install with: pip install reportlab")
        
        if not self.data:
            raise ValueError("No report data. Call create_report() first.")
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"report_{timestamp}.pdf")
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a1a2e')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#0d6efd')
        )
        
        # Title
        story.append(Paragraph(f"🔐 {self.data.engagement.title}", title_style))
        story.append(Paragraph(f"Client: {self.data.engagement.client}", styles['Normal']))
        story.append(Paragraph(f"Date: {self.data.engagement.start_date}", styles['Normal']))
        story.append(Paragraph(f"Classification: {self.data.engagement.classification}", styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(self.data.executive_summary, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Findings Summary Table
        story.append(Paragraph("Findings Summary", heading_style))
        
        severity_counts = {}
        for f in self.data.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        summary_data = [
            ['Severity', 'Count'],
            ['Critical', str(severity_counts.get('critical', 0))],
            ['High', str(severity_counts.get('high', 0))],
            ['Medium', str(severity_counts.get('medium', 0))],
            ['Low', str(severity_counts.get('low', 0))],
            ['Info', str(severity_counts.get('info', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        
        for i, v in enumerate(self.data.vulnerabilities, 1):
            story.append(Paragraph(f"<b>Finding #{i}:</b> {v.title}", styles['Normal']))
            story.append(Paragraph(f"<b>Severity:</b> {v.severity.upper()}", styles['Normal']))
            story.append(Paragraph(f"<b>Affected:</b> {v.affected}", styles['Normal']))
            story.append(Paragraph(f"<b>Description:</b> {v.description}", styles['Normal']))
            story.append(Paragraph(f"<b>Remediation:</b> {v.remediation}", styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", heading_style))
        
        rec_items = []
        for r in self.data.recommendations:
            rec_items.append(ListItem(Paragraph(r, styles['Normal'])))
        
        story.append(ListFlowable(rec_items, bulletType='1'))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    # =========================================================================
    # MARKDOWN REPORT
    # =========================================================================
    
    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """Generate Markdown report"""
        if not self.data:
            raise ValueError("No report data. Call create_report() first.")
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"report_{timestamp}.md")
        
        d = self.data
        
        # Count findings
        severity_counts = {}
        for f in d.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        md = f"""# 🔐 {d.engagement.title}

**Client:** {d.engagement.client}  
**Assessor:** {d.engagement.assessor}  
**Date:** {d.engagement.start_date} - {d.engagement.end_date}  
**Classification:** {d.engagement.classification}

---

## 📊 Executive Summary

{d.executive_summary}

---

## 📈 Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts.get('critical', 0)} |
| 🟠 High | {severity_counts.get('high', 0)} |
| 🟡 Medium | {severity_counts.get('medium', 0)} |
| 🟢 Low | {severity_counts.get('low', 0)} |
| 🔵 Info | {severity_counts.get('info', 0)} |

**Total Findings:** {len(d.findings)}

---

## 🔍 Detailed Findings

"""
        
        for i, v in enumerate(d.vulnerabilities, 1):
            md += f"""### Finding #{i}: {v.title}

- **Severity:** {v.severity.upper()}
- **Affected:** {v.affected}
- **Description:** {v.description}
- **Remediation:** {v.remediation}

---

"""
        
        md += """## ✅ Recommendations

"""
        for i, r in enumerate(d.recommendations, 1):
            md += f"{i}. {r}\n"
        
        md += f"""

---

## 🛠️ Tools Used

{', '.join(d.tools_used) if d.tools_used else 'Various security tools'}

---

## 📋 Scope

"""
        for s in d.engagement.scope:
            md += f"- {s}\n"
        
        md += f"""

---

*Generated by Kali-GPT v4.1 | {datetime.now().strftime("%Y-%m-%d %H:%M")}*
"""
        
        with open(output_path, 'w') as f:
            f.write(md)
        
        return output_path
    
    # =========================================================================
    # JSON EXPORT
    # =========================================================================
    
    def generate_json(self, output_path: Optional[str] = None) -> str:
        """Generate JSON export"""
        if not self.data:
            raise ValueError("No report data. Call create_report() first.")
        
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.output_dir, f"report_{timestamp}.json")
        
        with open(output_path, 'w') as f:
            json.dump(self.data.to_dict(), f, indent=2, default=str)
        
        return output_path


# =============================================================================
# INTERACTIVE MENU
# =============================================================================

async def report_menu(ai_service, findings: List = None, target: str = None):
    """Interactive report generation menu"""
    
    console.print(Panel(
        "[bold green]📊 REPORT GENERATOR[/bold green]\n\n"
        "Generate professional penetration test reports:\n"
        "  📄 PDF - Client-ready format\n"
        "  🌐 HTML - Interactive web report\n"
        "  📝 Markdown - Documentation format\n"
        "  📦 JSON - Integration export\n\n"
        "[dim]Reports include executive summary, findings, and recommendations[/dim]",
        title="Report Generator",
        border_style="green"
    ))
    
    if not findings:
        console.print("[yellow]No findings loaded. Enter engagement details manually.[/yellow]\n")
    else:
        console.print(f"[green]✓ {len(findings)} findings ready for report[/green]\n")
    
    # Get engagement info
    console.print("[bold]Engagement Information:[/bold]")
    
    title = Prompt.ask("Report title", default=f"Penetration Test Report - {target or 'Target'}")
    client = Prompt.ask("Client name", default="Client")
    
    engagement = EngagementInfo(
        title=title,
        client=client,
        assessor="Kali-GPT",
        start_date=datetime.now().strftime("%Y-%m-%d"),
        end_date=datetime.now().strftime("%Y-%m-%d"),
        scope=[target] if target else ["As defined"]
    )
    
    # Create report
    generator = ReportGenerator()
    
    # Convert findings if from autonomous engine
    if findings:
        converted_findings = []
        for f in findings:
            if hasattr(f, 'value'):
                converted_findings.append(Finding(
                    type=f.type,
                    value=f.value,
                    severity=f.severity,
                    host=getattr(f, 'host', target or ''),
                    details={'source': f.source}
                ))
            elif isinstance(f, dict):
                converted_findings.append(Finding(**f))
        findings = converted_findings
    else:
        findings = []
    
    console.print("\n[cyan]Generating report...[/cyan]")
    
    report_data = generator.create_report(
        findings=findings,
        target=target or "Target",
        engagement_info=engagement,
        ai_service=ai_service
    )
    
    # Output format selection
    table = RichTable(show_header=False, box=box.ROUNDED)
    table.add_row("1", "📄 Generate PDF")
    table.add_row("2", "🌐 Generate HTML")
    table.add_row("3", "📝 Generate Markdown")
    table.add_row("4", "📦 Generate JSON")
    table.add_row("5", "🎯 Generate All")
    table.add_row("b", "⬅️  Back")
    console.print(table)
    
    choice = Prompt.ask("\nSelect format", default="5")
    
    outputs = []
    
    try:
        if choice in ['1', '5']:
            if REPORTLAB_AVAILABLE:
                pdf_path = generator.generate_pdf()
                outputs.append(f"PDF: {pdf_path}")
                console.print(f"[green]✓ PDF saved: {pdf_path}[/green]")
            else:
                console.print("[yellow]⚠ PDF requires reportlab: pip install reportlab[/yellow]")
        
        if choice in ['2', '5']:
            html_path = generator.generate_html()
            outputs.append(f"HTML: {html_path}")
            console.print(f"[green]✓ HTML saved: {html_path}[/green]")
        
        if choice in ['3', '5']:
            md_path = generator.generate_markdown()
            outputs.append(f"Markdown: {md_path}")
            console.print(f"[green]✓ Markdown saved: {md_path}[/green]")
        
        if choice in ['4', '5']:
            json_path = generator.generate_json()
            outputs.append(f"JSON: {json_path}")
            console.print(f"[green]✓ JSON saved: {json_path}[/green]")
        
        if outputs:
            console.print(Panel(
                "\n".join(outputs),
                title="📁 Reports Generated",
                border_style="green"
            ))
    
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
    
    Prompt.ask("\nPress Enter to continue")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("Report Generator module loaded")
    print(f"PDF support: {'✓' if REPORTLAB_AVAILABLE else '✗ (pip install reportlab)'}")
