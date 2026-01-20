"""
Kali-GPT Attack Tree Module

Tracks and visualizes the attack path during penetration testing.
Supports ASCII terminal view and HTML interactive export.
"""

import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import html


class NodeType(Enum):
    """Type of node in attack tree"""
    ROOT = "root"           # Target
    DISCOVERY = "discovery" # Found something (port, service, etc)
    ACTION = "action"       # Tool executed
    FINDING = "finding"     # Vulnerability or interesting result
    CREDENTIAL = "credential"  # Found creds
    ACCESS = "access"       # Gained access
    PIVOT = "pivot"         # Lateral movement


class NodeStatus(Enum):
    """Status of node"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"


@dataclass
class AttackNode:
    """Single node in the attack tree"""
    id: str
    label: str
    node_type: NodeType
    status: NodeStatus = NodeStatus.SUCCESS
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    command: str = ""
    output_summary: str = ""
    children: List['AttackNode'] = field(default_factory=list)
    parent_id: Optional[str] = None
    mitre_technique: str = ""
    risk_level: str = "low"
    
    def add_child(self, child: 'AttackNode'):
        """Add a child node"""
        child.parent_id = self.id
        self.children.append(child)
        return child
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type.value,
            "status": self.status.value,
            "details": self.details,
            "timestamp": self.timestamp,
            "command": self.command,
            "output_summary": self.output_summary,
            "mitre_technique": self.mitre_technique,
            "risk_level": self.risk_level,
            "children": [c.to_dict() for c in self.children]
        }


class AttackTree:
    """
    Attack Tree - tracks the full attack path
    
    Usage:
        tree = AttackTree("192.168.1.100")
        
        # Add discoveries
        port_node = tree.add_discovery("Port 80 (HTTP)", parent=tree.root)
        
        # Add actions
        scan_node = tree.add_action("whatweb", "whatweb http://target", parent=port_node)
        
        # Add findings
        tree.add_finding("WordPress 5.9 detected", parent=scan_node, risk="medium")
        
        # Visualize
        print(tree.to_ascii())
        tree.export_html("attack_tree.html")
    """
    
    def __init__(self, target: str):
        self.target = target
        self.root = AttackNode(
            id="root",
            label=f"🎯 {target}",
            node_type=NodeType.ROOT,
            details=f"Target: {target}"
        )
        self.nodes: Dict[str, AttackNode] = {"root": self.root}
        self.node_counter = 0
        self.start_time = datetime.now()
    
    def _generate_id(self) -> str:
        """Generate unique node ID"""
        self.node_counter += 1
        return f"node_{self.node_counter}"
    
    def add_discovery(self, label: str, details: str = "", parent: AttackNode = None) -> AttackNode:
        """Add a discovery node (port, service, etc)"""
        node = AttackNode(
            id=self._generate_id(),
            label=f"🔍 {label}",
            node_type=NodeType.DISCOVERY,
            details=details
        )
        parent = parent or self.root
        parent.add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_action(self, tool: str, command: str, parent: AttackNode = None, 
                   status: NodeStatus = NodeStatus.SUCCESS, output: str = "") -> AttackNode:
        """Add an action node (tool execution)"""
        # Truncate output for summary
        output_summary = output[:200] + "..." if len(output) > 200 else output
        
        icon = "✓" if status == NodeStatus.SUCCESS else "✗"
        node = AttackNode(
            id=self._generate_id(),
            label=f"{icon} {tool}",
            node_type=NodeType.ACTION,
            status=status,
            command=command,
            output_summary=output_summary,
            details=f"Command: {command}"
        )
        parent = parent or self.root
        parent.add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_finding(self, label: str, parent: AttackNode = None, risk: str = "low",
                    mitre: str = "", details: str = "") -> AttackNode:
        """Add a finding node (vulnerability, interesting result)"""
        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
        icon = icons.get(risk, "🔵")
        
        node = AttackNode(
            id=self._generate_id(),
            label=f"{icon} {label}",
            node_type=NodeType.FINDING,
            risk_level=risk,
            mitre_technique=mitre,
            details=details
        )
        parent = parent or self.root
        parent.add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_credential(self, label: str, parent: AttackNode = None, details: str = "") -> AttackNode:
        """Add a credential node"""
        node = AttackNode(
            id=self._generate_id(),
            label=f"🔑 {label}",
            node_type=NodeType.CREDENTIAL,
            risk_level="critical",
            details=details
        )
        parent = parent or self.root
        parent.add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_access(self, label: str, parent: AttackNode = None, details: str = "") -> AttackNode:
        """Add an access node (shell, login, etc)"""
        node = AttackNode(
            id=self._generate_id(),
            label=f"💻 {label}",
            node_type=NodeType.ACCESS,
            risk_level="critical",
            details=details
        )
        parent = parent or self.root
        parent.add_child(node)
        self.nodes[node.id] = node
        return node
    
    def get_node(self, node_id: str) -> Optional[AttackNode]:
        """Get node by ID"""
        return self.nodes.get(node_id)
    
    def to_ascii(self, use_color: bool = True) -> str:
        """Generate ASCII tree visualization"""
        lines = []
        lines.append("")
        lines.append("╔══════════════════════════════════════════════════════════════╗")
        lines.append("║                    ATTACK TREE                               ║")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        lines.append("")
        
        def render_node(node: AttackNode, prefix: str = "", is_last: bool = True):
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{node.label}")
            
            if node.command:
                child_prefix = prefix + ("    " if is_last else "│   ")
                cmd_short = node.command[:50] + "..." if len(node.command) > 50 else node.command
                lines.append(f"{child_prefix}[dim]$ {cmd_short}[/dim]")
            
            child_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(node.children):
                is_last_child = (i == len(node.children) - 1)
                render_node(child, child_prefix, is_last_child)
        
        # Start from root
        lines.append(f"🎯 {self.target}")
        for i, child in enumerate(self.root.children):
            is_last = (i == len(self.root.children) - 1)
            render_node(child, "", is_last)
        
        lines.append("")
        
        # Stats
        total_nodes = len(self.nodes)
        findings = sum(1 for n in self.nodes.values() if n.node_type == NodeType.FINDING)
        actions = sum(1 for n in self.nodes.values() if n.node_type == NodeType.ACTION)
        
        lines.append(f"─" * 50)
        lines.append(f"Actions: {actions} | Findings: {findings} | Total: {total_nodes}")
        lines.append("")
        
        return "\n".join(lines)
    
    def to_dict(self) -> Dict:
        """Convert entire tree to dictionary"""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "total_nodes": len(self.nodes),
            "tree": self.root.to_dict()
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Export as JSON"""
        return json.dumps(self.to_dict(), indent=indent)
    
    def export_html(self, filepath: str = "attack_tree.html"):
        """Export interactive HTML visualization"""
        
        # Convert tree to vis.js format
        nodes_data = []
        edges_data = []
        
        def process_node(node: AttackNode, level: int = 0):
            # Node colors based on type
            colors = {
                NodeType.ROOT: "#e74c3c",
                NodeType.DISCOVERY: "#3498db",
                NodeType.ACTION: "#2ecc71",
                NodeType.FINDING: "#f39c12",
                NodeType.CREDENTIAL: "#9b59b6",
                NodeType.ACCESS: "#e74c3c",
                NodeType.PIVOT: "#1abc9c"
            }
            
            # Risk colors for findings
            risk_colors = {
                "critical": "#e74c3c",
                "high": "#e67e22",
                "medium": "#f1c40f",
                "low": "#2ecc71",
                "info": "#3498db"
            }
            
            color = colors.get(node.node_type, "#95a5a6")
            if node.node_type == NodeType.FINDING:
                color = risk_colors.get(node.risk_level, "#f39c12")
            
            # Clean label for HTML
            label = node.label.encode('ascii', 'ignore').decode()
            
            nodes_data.append({
                "id": node.id,
                "label": label,
                "level": level,
                "color": {"background": color, "border": color},
                "title": html.escape(node.details or node.command or ""),
                "shape": "box" if node.node_type == NodeType.ACTION else "ellipse"
            })
            
            for child in node.children:
                edges_data.append({
                    "from": node.id,
                    "to": child.id,
                    "arrows": "to"
                })
                process_node(child, level + 1)
        
        process_node(self.root)
        
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Attack Tree - {html.escape(self.target)}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/vis-network.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #1a1a2e; 
            color: #eee;
        }}
        .header {{
            background: #16213e;
            padding: 20px;
            border-bottom: 3px solid #e74c3c;
        }}
        .header h1 {{
            color: #e74c3c;
            font-size: 24px;
        }}
        .header .target {{
            color: #3498db;
            font-size: 18px;
            margin-top: 5px;
        }}
        .header .stats {{
            margin-top: 10px;
            font-size: 14px;
            color: #888;
        }}
        .header .stats span {{
            margin-right: 20px;
            padding: 5px 10px;
            background: #1a1a2e;
            border-radius: 4px;
        }}
        #network {{
            width: 100%;
            height: calc(100vh - 150px);
            background: #1a1a2e;
        }}
        .legend {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #16213e;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #333;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
            font-size: 12px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        .controls {{
            position: fixed;
            top: 100px;
            right: 20px;
            background: #16213e;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #333;
        }}
        .controls button {{
            display: block;
            width: 100%;
            padding: 8px 15px;
            margin: 5px 0;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }}
        .controls button:hover {{
            background: #2980b9;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 ATTACK TREE</h1>
        <div class="target">Target: {html.escape(self.target)}</div>
        <div class="stats">
            <span>🔍 Discoveries: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.DISCOVERY)}</span>
            <span>⚡ Actions: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.ACTION)}</span>
            <span>⚠️ Findings: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.FINDING)}</span>
            <span>🔑 Credentials: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.CREDENTIAL)}</span>
        </div>
    </div>
    
    <div id="network"></div>
    
    <div class="legend">
        <strong>Legend</strong>
        <div class="legend-item"><div class="legend-color" style="background:#e74c3c"></div>Target/Access</div>
        <div class="legend-item"><div class="legend-color" style="background:#3498db"></div>Discovery</div>
        <div class="legend-item"><div class="legend-color" style="background:#2ecc71"></div>Action</div>
        <div class="legend-item"><div class="legend-color" style="background:#f39c12"></div>Finding</div>
        <div class="legend-item"><div class="legend-color" style="background:#9b59b6"></div>Credential</div>
    </div>
    
    <div class="controls">
        <button onclick="network.fit()">🔍 Fit View</button>
        <button onclick="exportPNG()">📷 Export PNG</button>
        <button onclick="toggleLayout()">🔄 Toggle Layout</button>
    </div>

    <script>
        var nodes = new vis.DataSet({json.dumps(nodes_data)});
        var edges = new vis.DataSet({json.dumps(edges_data)});
        
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        
        var options = {{
            layout: {{
                hierarchical: {{
                    direction: 'UD',
                    sortMethod: 'directed',
                    levelSeparation: 100,
                    nodeSpacing: 150
                }}
            }},
            nodes: {{
                font: {{ color: '#fff', size: 14 }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                color: {{ color: '#555', highlight: '#e74c3c' }},
                width: 2,
                smooth: {{ type: 'cubicBezier' }}
            }},
            physics: false,
            interaction: {{
                hover: true,
                tooltipDelay: 100
            }}
        }};
        
        var network = new vis.Network(container, data, options);
        var hierarchical = true;
        
        function toggleLayout() {{
            hierarchical = !hierarchical;
            if (hierarchical) {{
                options.layout.hierarchical = {{
                    direction: 'UD',
                    sortMethod: 'directed',
                    levelSeparation: 100,
                    nodeSpacing: 150
                }};
            }} else {{
                options.layout.hierarchical = false;
                options.physics = {{ enabled: true, stabilization: true }};
            }}
            network.setOptions(options);
        }}
        
        function exportPNG() {{
            var canvas = container.getElementsByTagName('canvas')[0];
            var link = document.createElement('a');
            link.download = 'attack_tree.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
        }}
        
        // Click handler
        network.on('click', function(params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var node = nodes.get(nodeId);
                if (node.title) {{
                    alert(node.label + '\\n\\n' + node.title);
                }}
            }}
        }});
    </script>
</body>
</html>'''
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def export_mermaid(self) -> str:
        """Export as Mermaid diagram"""
        lines = ["graph TD"]
        
        def process_node(node: AttackNode):
            # Clean label
            label = node.label.replace('"', "'").replace("[", "(").replace("]", ")")
            
            for child in node.children:
                child_label = child.label.replace('"', "'").replace("[", "(").replace("]", ")")
                lines.append(f'    {node.id}["{label}"] --> {child.id}["{child_label}"]')
                process_node(child)
        
        process_node(self.root)
        return "\n".join(lines)


# Convenience function for quick tree creation
def create_attack_tree(target: str) -> AttackTree:
    """Create a new attack tree"""
    return AttackTree(target)


# Example usage and testing
if __name__ == "__main__":
    # Demo
    tree = AttackTree("192.168.1.100")
    
    # Simulate attack flow
    port80 = tree.add_discovery("Port 80 (HTTP)", "Open port discovered by nmap")
    port443 = tree.add_discovery("Port 443 (HTTPS)", "Open port discovered by nmap")
    port22 = tree.add_discovery("Port 22 (SSH)", "Open port discovered by nmap")
    
    # HTTP branch
    whatweb = tree.add_action("whatweb", "whatweb http://192.168.1.100", parent=port80)
    tree.add_finding("WordPress 5.9.3 detected", parent=whatweb, risk="medium")
    tree.add_finding("PHP 7.4", parent=whatweb, risk="info")
    
    wpscan = tree.add_action("wpscan", "wpscan --url http://192.168.1.100", parent=port80)
    tree.add_finding("User enumeration: admin, editor", parent=wpscan, risk="medium")
    tree.add_finding("Outdated plugin: contact-form-7", parent=wpscan, risk="high")
    
    gobuster = tree.add_action("gobuster", "gobuster dir -u http://192.168.1.100 -w common.txt", parent=port80)
    tree.add_finding("/wp-admin found", parent=gobuster, risk="info")
    tree.add_finding("/backup.zip found", parent=gobuster, risk="high")
    
    # Exploit backup
    backup = tree.add_action("wget", "wget http://192.168.1.100/backup.zip", parent=gobuster)
    tree.add_credential("DB creds in wp-config.php", parent=backup, details="root:password123")
    
    # HTTPS branch
    sslscan = tree.add_action("sslscan", "sslscan 192.168.1.100", parent=port443)
    tree.add_finding("TLS 1.0 enabled", parent=sslscan, risk="medium")
    tree.add_finding("Weak cipher suites", parent=sslscan, risk="medium")
    
    # SSH branch
    ssh_audit = tree.add_action("ssh-audit", "ssh-audit 192.168.1.100", parent=port22)
    tree.add_finding("SSH password auth enabled", parent=ssh_audit, risk="low")
    
    # Print ASCII tree
    print(tree.to_ascii())
    
    # Export HTML
    tree.export_html("demo_attack_tree.html")
    print("Exported: demo_attack_tree.html")
    
    # Export JSON
    print("\nJSON Preview:")
    print(tree.to_json()[:500] + "...")
