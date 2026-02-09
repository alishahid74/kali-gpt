#!/usr/bin/env python3
"""
Kali-GPT v4.1 - Network Mapping & Topology Visualization

Features:
- Parse nmap scan results into network topology
- Interactive D3.js force-directed graph
- Service categorization and port grouping
- Export to multiple formats (JSON, GraphML, PNG)
- Integration with API server

Usage:
    from network_mapper import NetworkMapper
    
    mapper = NetworkMapper()
    mapper.parse_nmap_output(nmap_result)
    mapper.generate_html("topology.html")
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
import xml.etree.ElementTree as ET


class NodeType(Enum):
    """Types of nodes in the network map"""
    GATEWAY = "gateway"
    HOST = "host"
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    FIREWALL = "firewall"
    DATABASE = "database"
    WEBSERVER = "webserver"
    UNKNOWN = "unknown"


class ServiceCategory(Enum):
    """Service categories for grouping"""
    WEB = "web"
    DATABASE = "database"
    MAIL = "mail"
    FILE = "file"
    REMOTE = "remote"
    SECURITY = "security"
    NETWORK = "network"
    OTHER = "other"


@dataclass
class Port:
    """Represents an open port on a host"""
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""
    
    @property
    def category(self) -> ServiceCategory:
        """Categorize the service"""
        web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000}
        db_ports = {3306, 5432, 1433, 1521, 27017, 6379, 5984}
        mail_ports = {25, 110, 143, 465, 587, 993, 995}
        file_ports = {21, 22, 69, 111, 139, 445, 2049}
        remote_ports = {22, 23, 3389, 5900, 5901}
        
        if self.number in web_ports or 'http' in self.service.lower():
            return ServiceCategory.WEB
        elif self.number in db_ports or any(x in self.service.lower() for x in ['mysql', 'postgres', 'mongo', 'redis']):
            return ServiceCategory.DATABASE
        elif self.number in mail_ports or any(x in self.service.lower() for x in ['smtp', 'pop', 'imap']):
            return ServiceCategory.MAIL
        elif self.number in file_ports or any(x in self.service.lower() for x in ['ftp', 'smb', 'nfs']):
            return ServiceCategory.FILE
        elif self.number in remote_ports or any(x in self.service.lower() for x in ['ssh', 'telnet', 'rdp', 'vnc']):
            return ServiceCategory.REMOTE
        return ServiceCategory.OTHER


@dataclass
class Host:
    """Represents a host in the network"""
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os: str = ""
    os_accuracy: int = 0
    status: str = "up"
    ports: List[Port] = field(default_factory=list)
    node_type: NodeType = NodeType.UNKNOWN
    notes: str = ""
    first_seen: str = ""
    last_seen: str = ""
    
    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self._infer_node_type()
    
    def _infer_node_type(self):
        """Infer the node type based on open ports and services"""
        if not self.ports:
            return
        
        port_nums = {p.number for p in self.ports}
        services = {p.service.lower() for p in self.ports}
        
        # Check for specific service types
        if any(x in services for x in ['mysql', 'postgresql', 'mongodb', 'redis', 'oracle']):
            self.node_type = NodeType.DATABASE
        elif 80 in port_nums or 443 in port_nums or 'http' in services or 'https' in services:
            self.node_type = NodeType.WEBSERVER
        elif 22 in port_nums and len(port_nums) < 5:
            self.node_type = NodeType.SERVER
        elif '.1' in self.ip.split('.')[-1] or 'router' in self.os.lower():
            self.node_type = NodeType.GATEWAY
        else:
            self.node_type = NodeType.HOST
    
    @property
    def id(self) -> str:
        """Unique identifier for the host"""
        return hashlib.md5(self.ip.encode()).hexdigest()[:8]
    
    @property
    def label(self) -> str:
        """Display label for the host"""
        if self.hostname:
            return f"{self.hostname}\n{self.ip}"
        return self.ip
    
    @property
    def risk_score(self) -> int:
        """Calculate risk score based on open ports"""
        score = 0
        high_risk_ports = {21, 23, 445, 1433, 3389}
        medium_risk_ports = {22, 25, 80, 110, 143, 443, 3306, 5432}
        
        for port in self.ports:
            if port.number in high_risk_ports:
                score += 30
            elif port.number in medium_risk_ports:
                score += 10
            else:
                score += 5
        
        return min(score, 100)


@dataclass
class NetworkSegment:
    """Represents a network segment (subnet)"""
    cidr: str
    hosts: List[Host] = field(default_factory=list)
    name: str = ""
    description: str = ""
    
    @property
    def id(self) -> str:
        return hashlib.md5(self.cidr.encode()).hexdigest()[:8]


@dataclass 
class Connection:
    """Represents a connection between hosts"""
    source_ip: str
    target_ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    
    @property
    def id(self) -> str:
        return f"{self.source_ip}-{self.target_ip}-{self.port}"


class NetworkMapper:
    """
    Network topology mapper and visualizer.
    
    Parses scan results and generates interactive network maps.
    """
    
    def __init__(self):
        self.hosts: Dict[str, Host] = {}
        self.segments: Dict[str, NetworkSegment] = {}
        self.connections: List[Connection] = []
        self.scan_info: Dict = {}
    
    def parse_nmap_output(self, output: str, scan_type: str = "text") -> int:
        """
        Parse nmap output and extract hosts/ports.
        
        Args:
            output: Raw nmap output (text or XML)
            scan_type: "text" or "xml"
            
        Returns:
            Number of hosts discovered
        """
        if scan_type == "xml" or output.strip().startswith('<?xml'):
            return self._parse_nmap_xml(output)
        return self._parse_nmap_text(output)
    
    def _parse_nmap_text(self, output: str) -> int:
        """Parse text-based nmap output"""
        hosts_found = 0
        current_host = None
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Match host line: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
            host_match = re.match(r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?', line)
            if host_match:
                hostname = host_match.group(1) or ""
                ip = host_match.group(2)
                
                if ip not in self.hosts:
                    current_host = Host(ip=ip, hostname=hostname)
                    self.hosts[ip] = current_host
                    hosts_found += 1
                else:
                    current_host = self.hosts[ip]
                    if hostname and not current_host.hostname:
                        current_host.hostname = hostname
                continue
            
            # Match MAC address
            mac_match = re.match(r'MAC Address: ([0-9A-F:]+) \((.+)\)', line, re.IGNORECASE)
            if mac_match and current_host:
                current_host.mac = mac_match.group(1)
                current_host.vendor = mac_match.group(2)
                continue
            
            # Match port line: "PORT     STATE SERVICE VERSION"
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?', line)
            if port_match and current_host:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5) or ""
                
                if state in ['open', 'open|filtered']:
                    port = Port(
                        number=port_num,
                        protocol=protocol,
                        state=state,
                        service=service,
                        version=version
                    )
                    current_host.ports.append(port)
                continue
            
            # Match OS detection
            os_match = re.match(r'OS details?: (.+)', line)
            if os_match and current_host:
                current_host.os = os_match.group(1)
                continue
            
            # Match aggressive OS guess
            os_guess = re.match(r'Aggressive OS guesses?: (.+)', line)
            if os_guess and current_host:
                current_host.os = os_guess.group(1).split(',')[0]
                continue
        
        # Update node types after parsing
        for host in self.hosts.values():
            host._infer_node_type()
        
        # Organize into segments
        self._organize_segments()
        
        return hosts_found
    
    def _parse_nmap_xml(self, xml_content: str) -> int:
        """Parse XML-based nmap output"""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return self._parse_nmap_text(xml_content)
        
        hosts_found = 0
        
        for host_elem in root.findall('.//host'):
            # Get status
            status_elem = host_elem.find('status')
            if status_elem is not None and status_elem.get('state') != 'up':
                continue
            
            # Get IP address
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                continue
            
            ip = addr_elem.get('addr')
            
            # Create host
            host = Host(ip=ip)
            
            # Get MAC if available
            mac_elem = host_elem.find("address[@addrtype='mac']")
            if mac_elem is not None:
                host.mac = mac_elem.get('addr', '')
                host.vendor = mac_elem.get('vendor', '')
            
            # Get hostname
            hostname_elem = host_elem.find('.//hostname')
            if hostname_elem is not None:
                host.hostname = hostname_elem.get('name', '')
            
            # Get OS
            os_elem = host_elem.find('.//osmatch')
            if os_elem is not None:
                host.os = os_elem.get('name', '')
                host.os_accuracy = int(os_elem.get('accuracy', 0))
            
            # Get ports
            for port_elem in host_elem.findall('.//port'):
                state_elem = port_elem.find('state')
                if state_elem is None or state_elem.get('state') not in ['open', 'open|filtered']:
                    continue
                
                service_elem = port_elem.find('service')
                
                port = Port(
                    number=int(port_elem.get('portid')),
                    protocol=port_elem.get('protocol', 'tcp'),
                    state=state_elem.get('state'),
                    service=service_elem.get('name', '') if service_elem is not None else '',
                    version=service_elem.get('version', '') if service_elem is not None else '',
                    banner=service_elem.get('product', '') if service_elem is not None else ''
                )
                host.ports.append(port)
            
            host._infer_node_type()
            self.hosts[ip] = host
            hosts_found += 1
        
        self._organize_segments()
        return hosts_found
    
    def _organize_segments(self):
        """Organize hosts into network segments"""
        for ip, host in self.hosts.items():
            # Extract /24 network
            parts = ip.split('.')
            if len(parts) == 4:
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                
                if network not in self.segments:
                    self.segments[network] = NetworkSegment(cidr=network)
                
                if host not in self.segments[network].hosts:
                    self.segments[network].hosts.append(host)
    
    def add_host(self, ip: str, hostname: str = "", ports: List[Dict] = None) -> Host:
        """Manually add a host to the map"""
        host = Host(ip=ip, hostname=hostname)
        
        if ports:
            for p in ports:
                port = Port(
                    number=p.get('number', 0),
                    protocol=p.get('protocol', 'tcp'),
                    service=p.get('service', ''),
                    version=p.get('version', '')
                )
                host.ports.append(port)
        
        host._infer_node_type()
        self.hosts[ip] = host
        self._organize_segments()
        return host
    
    def add_connection(self, source_ip: str, target_ip: str, port: int, 
                       protocol: str = "tcp", service: str = "") -> Connection:
        """Add a connection between hosts"""
        conn = Connection(
            source_ip=source_ip,
            target_ip=target_ip,
            port=port,
            protocol=protocol,
            service=service
        )
        self.connections.append(conn)
        return conn
    
    def get_statistics(self) -> Dict:
        """Get network statistics"""
        total_ports = sum(len(h.ports) for h in self.hosts.values())
        
        # Count by service category
        category_counts = {}
        for host in self.hosts.values():
            for port in host.ports:
                cat = port.category.value
                category_counts[cat] = category_counts.get(cat, 0) + 1
        
        # Count by node type
        type_counts = {}
        for host in self.hosts.values():
            t = host.node_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
        
        # Risk distribution
        risk_levels = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for host in self.hosts.values():
            score = host.risk_score
            if score < 25:
                risk_levels['low'] += 1
            elif score < 50:
                risk_levels['medium'] += 1
            elif score < 75:
                risk_levels['high'] += 1
            else:
                risk_levels['critical'] += 1
        
        return {
            'total_hosts': len(self.hosts),
            'total_segments': len(self.segments),
            'total_ports': total_ports,
            'total_connections': len(self.connections),
            'services_by_category': category_counts,
            'hosts_by_type': type_counts,
            'risk_distribution': risk_levels
        }
    
    def to_json(self) -> str:
        """Export network map to JSON"""
        data = {
            'nodes': [],
            'links': [],
            'segments': [],
            'statistics': self.get_statistics(),
            'generated_at': datetime.now().isoformat()
        }
        
        # Add hosts as nodes
        for ip, host in self.hosts.items():
            node = {
                'id': host.id,
                'ip': host.ip,
                'hostname': host.hostname,
                'label': host.label,
                'type': host.node_type.value,
                'os': host.os,
                'mac': host.mac,
                'vendor': host.vendor,
                'risk_score': host.risk_score,
                'ports': [
                    {
                        'number': p.number,
                        'protocol': p.protocol,
                        'service': p.service,
                        'version': p.version,
                        'category': p.category.value
                    }
                    for p in host.ports
                ]
            }
            data['nodes'].append(node)
        
        # Add connections as links
        for conn in self.connections:
            link = {
                'source': self.hosts[conn.source_ip].id if conn.source_ip in self.hosts else conn.source_ip,
                'target': self.hosts[conn.target_ip].id if conn.target_ip in self.hosts else conn.target_ip,
                'port': conn.port,
                'service': conn.service
            }
            data['links'].append(link)
        
        # Add segments
        for cidr, segment in self.segments.items():
            seg_data = {
                'id': segment.id,
                'cidr': segment.cidr,
                'name': segment.name or cidr,
                'host_count': len(segment.hosts),
                'host_ids': [h.id for h in segment.hosts]
            }
            data['segments'].append(seg_data)
        
        return json.dumps(data, indent=2)
    
    def to_graphml(self) -> str:
        """Export network map to GraphML format"""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="ip" for="node" attr.name="ip" attr.type="string"/>',
            '  <key id="ports" for="node" attr.name="ports" attr.type="string"/>',
            '  <key id="port" for="edge" attr.name="port" attr.type="int"/>',
            '  <graph id="network" edgedefault="directed">'
        ]
        
        # Add nodes
        for ip, host in self.hosts.items():
            ports_str = ','.join(str(p.number) for p in host.ports)
            lines.append(f'    <node id="{host.id}">')
            lines.append(f'      <data key="label">{host.label}</data>')
            lines.append(f'      <data key="type">{host.node_type.value}</data>')
            lines.append(f'      <data key="ip">{host.ip}</data>')
            lines.append(f'      <data key="ports">{ports_str}</data>')
            lines.append('    </node>')
        
        # Add edges
        for i, conn in enumerate(self.connections):
            src_id = self.hosts[conn.source_ip].id if conn.source_ip in self.hosts else conn.source_ip
            tgt_id = self.hosts[conn.target_ip].id if conn.target_ip in self.hosts else conn.target_ip
            lines.append(f'    <edge id="e{i}" source="{src_id}" target="{tgt_id}">')
            lines.append(f'      <data key="port">{conn.port}</data>')
            lines.append('    </edge>')
        
        lines.append('  </graph>')
        lines.append('</graphml>')
        
        return '\n'.join(lines)
    
    def generate_html(self, output_path: str = None) -> str:
        """
        Generate interactive HTML visualization.
        
        Args:
            output_path: Path to save HTML file (optional)
            
        Returns:
            HTML content as string
        """
        network_data = self.to_json()
        stats = self.get_statistics()
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali-GPT Network Map</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0a0e14;
            --bg-secondary: #0d1117;
            --bg-card: #1a1f26;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
            --accent-cyan: #39c5cf;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            overflow: hidden;
        }}
        
        .container {{
            display: flex;
            height: 100vh;
        }}
        
        .sidebar {{
            width: 300px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            padding: 20px;
            overflow-y: auto;
        }}
        
        .logo {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 20px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent-cyan);
        }}
        
        .stat-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        
        .section-title {{
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
            margin: 20px 0 10px;
        }}
        
        .host-list {{
            max-height: 300px;
            overflow-y: auto;
        }}
        
        .host-item {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .host-item:hover {{
            border-color: var(--accent-blue);
            transform: translateX(4px);
        }}
        
        .host-item.selected {{
            border-color: var(--accent-cyan);
            background: rgba(57, 197, 207, 0.1);
        }}
        
        .host-ip {{
            font-family: monospace;
            font-weight: 600;
        }}
        
        .host-meta {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        
        .host-ports {{
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 8px;
        }}
        
        .port-badge {{
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 4px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
        }}
        
        .port-badge.web {{ border-color: var(--accent-green); color: var(--accent-green); }}
        .port-badge.database {{ border-color: var(--accent-purple); color: var(--accent-purple); }}
        .port-badge.remote {{ border-color: var(--accent-blue); color: var(--accent-blue); }}
        .port-badge.file {{ border-color: var(--accent-yellow); color: var(--accent-yellow); }}
        
        .map-container {{
            flex: 1;
            position: relative;
        }}
        
        #network-map {{
            width: 100%;
            height: 100%;
        }}
        
        .node {{
            cursor: pointer;
        }}
        
        .node circle {{
            stroke-width: 2px;
            transition: all 0.2s;
        }}
        
        .node:hover circle {{
            stroke-width: 4px;
            filter: brightness(1.2);
        }}
        
        .node.selected circle {{
            stroke: var(--accent-cyan);
            stroke-width: 4px;
        }}
        
        .node-label {{
            font-size: 10px;
            fill: var(--text-primary);
            text-anchor: middle;
            pointer-events: none;
        }}
        
        .link {{
            stroke: var(--border-color);
            stroke-opacity: 0.6;
            stroke-width: 1.5px;
        }}
        
        .link:hover {{
            stroke: var(--accent-blue);
            stroke-opacity: 1;
        }}
        
        .tooltip {{
            position: absolute;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            max-width: 300px;
            z-index: 1000;
        }}
        
        .tooltip.visible {{
            opacity: 1;
        }}
        
        .tooltip-title {{
            font-weight: 600;
            margin-bottom: 8px;
        }}
        
        .tooltip-row {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 4px;
        }}
        
        .tooltip-row span:first-child {{
            color: var(--text-secondary);
        }}
        
        .controls {{
            position: absolute;
            top: 20px;
            right: 20px;
            display: flex;
            gap: 8px;
        }}
        
        .btn {{
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: var(--bg-card);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }}
        
        .btn:hover {{
            border-color: var(--accent-blue);
            background: var(--bg-secondary);
        }}
        
        .legend {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
        }}
        
        .legend-title {{
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--text-secondary);
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.8rem;
            margin-bottom: 4px;
        }}
        
        .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        
        .risk-bar {{
            height: 4px;
            border-radius: 2px;
            background: var(--bg-secondary);
            margin-top: 8px;
            overflow: hidden;
        }}
        
        .risk-fill {{
            height: 100%;
            border-radius: 2px;
            transition: width 0.3s;
        }}
        
        .risk-low {{ background: var(--accent-green); }}
        .risk-medium {{ background: var(--accent-yellow); }}
        .risk-high {{ background: var(--accent-red); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="logo">🗺️ KALI-GPT Network Map</div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="stat-hosts">{stats['total_hosts']}</div>
                    <div class="stat-label">Hosts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-ports">{stats['total_ports']}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-segments">{stats['total_segments']}</div>
                    <div class="stat-label">Segments</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-connections">{stats['total_connections']}</div>
                    <div class="stat-label">Connections</div>
                </div>
            </div>
            
            <div class="section-title">Discovered Hosts</div>
            <div class="host-list" id="host-list"></div>
        </div>
        
        <div class="map-container">
            <svg id="network-map"></svg>
            
            <div class="controls">
                <button class="btn" onclick="resetZoom()">Reset View</button>
                <button class="btn" onclick="toggleLabels()">Toggle Labels</button>
                <button class="btn" onclick="exportPNG()">Export PNG</button>
            </div>
            
            <div class="legend">
                <div class="legend-title">NODE TYPES</div>
                <div class="legend-item">
                    <div class="legend-dot" style="background: #58a6ff;"></div>
                    <span>Server</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot" style="background: #3fb950;"></div>
                    <span>Web Server</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot" style="background: #a371f7;"></div>
                    <span>Database</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot" style="background: #d29922;"></div>
                    <span>Gateway</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot" style="background: #8b949e;"></div>
                    <span>Unknown</span>
                </div>
            </div>
            
            <div class="tooltip" id="tooltip"></div>
        </div>
    </div>
    
    <script>
        // Network data
        const networkData = {network_data};
        
        // Color mapping
        const nodeColors = {{
            'server': '#58a6ff',
            'webserver': '#3fb950',
            'database': '#a371f7',
            'gateway': '#d29922',
            'router': '#d29922',
            'host': '#39c5cf',
            'workstation': '#39c5cf',
            'unknown': '#8b949e'
        }};
        
        // SVG setup
        const svg = d3.select('#network-map');
        const width = svg.node().getBoundingClientRect().width;
        const height = svg.node().getBoundingClientRect().height;
        
        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {{
                g.attr('transform', event.transform);
            }});
        
        svg.call(zoom);
        
        const g = svg.append('g');
        
        // Create simulation
        const simulation = d3.forceSimulation(networkData.nodes)
            .force('link', d3.forceLink(networkData.links)
                .id(d => d.id)
                .distance(150))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(50));
        
        // Create links
        const link = g.append('g')
            .selectAll('line')
            .data(networkData.links)
            .join('line')
            .attr('class', 'link');
        
        // Create nodes
        const node = g.append('g')
            .selectAll('g')
            .data(networkData.nodes)
            .join('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Node circles
        node.append('circle')
            .attr('r', d => 15 + d.ports.length * 2)
            .attr('fill', d => nodeColors[d.type] || nodeColors.unknown)
            .attr('stroke', d => d3.color(nodeColors[d.type] || nodeColors.unknown).darker(1));
        
        // Node labels
        let showLabels = true;
        const labels = node.append('text')
            .attr('class', 'node-label')
            .attr('dy', d => 25 + d.ports.length * 2)
            .text(d => d.ip);
        
        // Tooltip
        const tooltip = d3.select('#tooltip');
        
        node.on('mouseover', (event, d) => {{
            const portsHtml = d.ports.map(p => 
                `<span class="port-badge ${{p.category}}">${{p.number}}/${{p.service}}</span>`
            ).join(' ');
            
            tooltip.html(`
                <div class="tooltip-title">${{d.hostname || d.ip}}</div>
                <div class="tooltip-row"><span>IP:</span><span>${{d.ip}}</span></div>
                <div class="tooltip-row"><span>Type:</span><span>${{d.type}}</span></div>
                <div class="tooltip-row"><span>OS:</span><span>${{d.os || 'Unknown'}}</span></div>
                <div class="tooltip-row"><span>Risk:</span><span>${{d.risk_score}}%</span></div>
                <div class="risk-bar">
                    <div class="risk-fill ${{d.risk_score < 30 ? 'risk-low' : d.risk_score < 60 ? 'risk-medium' : 'risk-high'}}" 
                         style="width: ${{d.risk_score}}%"></div>
                </div>
                <div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-secondary);">Ports:</div>
                <div class="host-ports">${{portsHtml}}</div>
            `)
            .style('left', (event.pageX + 15) + 'px')
            .style('top', (event.pageY - 15) + 'px')
            .classed('visible', true);
        }})
        .on('mouseout', () => {{
            tooltip.classed('visible', false);
        }})
        .on('click', (event, d) => {{
            selectHost(d.id);
        }});
        
        // Update positions
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // Drag functions
        function dragstarted(event) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }}
        
        function dragged(event) {{
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }}
        
        function dragended(event) {{
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }}
        
        // Populate host list
        const hostList = document.getElementById('host-list');
        networkData.nodes.forEach(host => {{
            const div = document.createElement('div');
            div.className = 'host-item';
            div.dataset.id = host.id;
            div.innerHTML = `
                <div class="host-ip">${{host.ip}}</div>
                <div class="host-meta">${{host.hostname || host.type}} • ${{host.ports.length}} ports</div>
                <div class="host-ports">
                    ${{host.ports.slice(0, 5).map(p => 
                        `<span class="port-badge ${{p.category}}">${{p.number}}</span>`
                    ).join('')}}
                    ${{host.ports.length > 5 ? `<span class="port-badge">+${{host.ports.length - 5}}</span>` : ''}}
                </div>
            `;
            div.onclick = () => selectHost(host.id);
            hostList.appendChild(div);
        }});
        
        // Select host
        function selectHost(id) {{
            // Update sidebar
            document.querySelectorAll('.host-item').forEach(el => {{
                el.classList.toggle('selected', el.dataset.id === id);
            }});
            
            // Update nodes
            node.classed('selected', d => d.id === id);
            
            // Center on selected node
            const selectedNode = networkData.nodes.find(n => n.id === id);
            if (selectedNode) {{
                svg.transition().duration(500).call(
                    zoom.transform,
                    d3.zoomIdentity
                        .translate(width / 2, height / 2)
                        .scale(1.5)
                        .translate(-selectedNode.x, -selectedNode.y)
                );
            }}
        }}
        
        // Control functions
        function resetZoom() {{
            svg.transition().duration(500).call(
                zoom.transform,
                d3.zoomIdentity
            );
        }}
        
        function toggleLabels() {{
            showLabels = !showLabels;
            labels.style('opacity', showLabels ? 1 : 0);
        }}
        
        function exportPNG() {{
            // Create canvas
            const canvas = document.createElement('canvas');
            canvas.width = width * 2;
            canvas.height = height * 2;
            const ctx = canvas.getContext('2d');
            
            // Draw background
            ctx.fillStyle = '#0a0e14';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            // Serialize SVG
            const svgData = new XMLSerializer().serializeToString(svg.node());
            const img = new Image();
            img.onload = function() {{
                ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                
                // Download
                const link = document.createElement('a');
                link.download = 'network-map.png';
                link.href = canvas.toDataURL('image/png');
                link.click();
            }};
            img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
        }}
    </script>
</body>
</html>'''
        
        if output_path:
            Path(output_path).write_text(html)
        
        return html


# Integration with API Server
def create_network_map_routes(app, db):
    """
    Add network mapping routes to FastAPI app.
    
    Usage in api_server.py:
        from network_mapper import create_network_map_routes
        create_network_map_routes(app, db)
    """
    from fastapi import APIRouter, HTTPException
    from fastapi.responses import HTMLResponse
    
    router = APIRouter(prefix="/network", tags=["Network Mapping"])
    mapper = NetworkMapper()
    
    @router.get("/map", response_class=HTMLResponse)
    async def get_network_map():
        """Generate interactive network map from all scans"""
        # Get all findings with host/port data
        findings = db.list_findings(limit=1000)
        
        # Extract hosts from findings
        for finding in findings:
            hosts = finding.get('affected_hosts', [])
            ports = finding.get('affected_ports', [])
            
            for host in hosts:
                if host not in mapper.hosts:
                    mapper.add_host(host)
                
                # Add ports
                for port in ports:
                    if isinstance(port, int):
                        port_obj = Port(number=port)
                        if port_obj not in mapper.hosts[host].ports:
                            mapper.hosts[host].ports.append(port_obj)
        
        return HTMLResponse(content=mapper.generate_html())
    
    @router.get("/data")
    async def get_network_data():
        """Get network map data as JSON"""
        return json.loads(mapper.to_json())
    
    @router.post("/parse")
    async def parse_scan_output(output: str, scan_type: str = "text"):
        """Parse nmap output and update network map"""
        hosts_found = mapper.parse_nmap_output(output, scan_type)
        return {
            "hosts_found": hosts_found,
            "total_hosts": len(mapper.hosts),
            "statistics": mapper.get_statistics()
        }
    
    @router.get("/export/{format}")
    async def export_network_map(format: str):
        """Export network map to different formats"""
        if format == "json":
            return json.loads(mapper.to_json())
        elif format == "graphml":
            return mapper.to_graphml()
        elif format == "html":
            return HTMLResponse(content=mapper.generate_html())
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format}")
    
    app.include_router(router)
    return router


# CLI for standalone usage
if __name__ == "__main__":
    import sys
    
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           KALI-GPT NETWORK MAPPER v4.1                           ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Usage:                                                          ║
║    python3 network_mapper.py <nmap_output_file> [output.html]    ║
║                                                                  ║
║  Or import in Python:                                            ║
║    from network_mapper import NetworkMapper                      ║
║    mapper = NetworkMapper()                                      ║
║    mapper.parse_nmap_output(nmap_result)                         ║
║    mapper.generate_html("map.html")                              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    if len(sys.argv) < 2:
        # Demo mode with sample data
        print("Running demo with sample data...\n")
        
        mapper = NetworkMapper()
        
        # Add sample hosts
        mapper.add_host("192.168.1.1", "gateway", [
            {"number": 22, "service": "ssh"},
            {"number": 80, "service": "http"}
        ])
        
        mapper.add_host("192.168.1.10", "web-server", [
            {"number": 80, "service": "http"},
            {"number": 443, "service": "https"},
            {"number": 3306, "service": "mysql"}
        ])
        
        mapper.add_host("192.168.1.20", "db-server", [
            {"number": 5432, "service": "postgresql"},
            {"number": 22, "service": "ssh"}
        ])
        
        mapper.add_host("192.168.1.30", "file-server", [
            {"number": 445, "service": "microsoft-ds"},
            {"number": 139, "service": "netbios-ssn"},
            {"number": 22, "service": "ssh"}
        ])
        
        # Add connections
        mapper.add_connection("192.168.1.10", "192.168.1.20", 5432, "tcp", "postgresql")
        mapper.add_connection("192.168.1.1", "192.168.1.10", 80, "tcp", "http")
        
        # Generate output
        output_file = "network_map_demo.html"
        mapper.generate_html(output_file)
        
        stats = mapper.get_statistics()
        print(f"✓ Generated: {output_file}")
        print(f"  Hosts: {stats['total_hosts']}")
        print(f"  Ports: {stats['total_ports']}")
        print(f"  Segments: {stats['total_segments']}")
        print(f"\nOpen in browser: file://{Path(output_file).absolute()}")
        
    else:
        # Parse provided file
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else "network_map.html"
        
        if not Path(input_file).exists():
            print(f"Error: File not found: {input_file}")
            sys.exit(1)
        
        content = Path(input_file).read_text()
        
        mapper = NetworkMapper()
        hosts_found = mapper.parse_nmap_output(content)
        
        mapper.generate_html(output_file)
        
        stats = mapper.get_statistics()
        print(f"✓ Parsed {hosts_found} hosts from {input_file}")
        print(f"✓ Generated: {output_file}")
        print(f"  Total Ports: {stats['total_ports']}")
        print(f"  Segments: {stats['total_segments']}")
