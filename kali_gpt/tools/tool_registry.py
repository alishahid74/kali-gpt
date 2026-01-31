"""
Kali-GPT Tool Registry v2.0 - 150+ Security Tools

Comprehensive registry organized by category:
- Reconnaissance (25+)
- Web Application (40+)
- Password/Auth (15+)
- Cloud Security (20+)
- Container/K8s (15+)
- Binary Analysis (25+)
- CTF/Forensics (25+)
- OSINT (20+)
- Exploitation (15+)
- Wireless (10+)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class Category(Enum):
    RECON = "recon"
    WEB = "web"
    PASSWORD = "password"
    CLOUD = "cloud"
    CONTAINER = "container"
    BINARY = "binary"
    CTF = "ctf"
    OSINT = "osint"
    EXPLOIT = "exploit"
    WIRELESS = "wireless"
    NETWORK = "network"


@dataclass
class Tool:
    name: str
    category: Category
    description: str
    cmd: str
    install: str = ""
    timeout: int = 300
    risk: str = "low"


# ═══════════════════════════════════════════════════════════════════════════
# TOOL DEFINITIONS - 150+ Tools
# ═══════════════════════════════════════════════════════════════════════════

TOOLS: Dict[str, Tool] = {
    
    # ─────────────────────────────────────────────────────────────────────────
    # RECONNAISSANCE (25+)
    # ─────────────────────────────────────────────────────────────────────────
    "nmap": Tool("nmap", Category.RECON, "Network scanner", "nmap {opts} {target}"),
    "masscan": Tool("masscan", Category.RECON, "Fast port scanner", "masscan {target} -p{ports} --rate={rate}"),
    "rustscan": Tool("rustscan", Category.RECON, "Ultra-fast scanner", "rustscan -a {target} -- -sV"),
    "autorecon": Tool("autorecon", Category.RECON, "Auto reconnaissance", "autorecon {target}"),
    "enum4linux": Tool("enum4linux", Category.RECON, "SMB enumeration", "enum4linux -a {target}"),
    "enum4linux-ng": Tool("enum4linux-ng", Category.RECON, "SMB enum (new)", "enum4linux-ng -A {target}"),
    "smbclient": Tool("smbclient", Category.RECON, "SMB client", "smbclient -L //{target} -N"),
    "smbmap": Tool("smbmap", Category.RECON, "SMB share enum", "smbmap -H {target}"),
    "rpcclient": Tool("rpcclient", Category.RECON, "RPC client", "rpcclient -U '' -N {target}"),
    "ldapsearch": Tool("ldapsearch", Category.RECON, "LDAP search", "ldapsearch -x -H ldap://{target}"),
    "snmpwalk": Tool("snmpwalk", Category.RECON, "SNMP walker", "snmpwalk -v2c -c public {target}"),
    "onesixtyone": Tool("onesixtyone", Category.RECON, "SNMP scanner", "onesixtyone -c community.txt {target}"),
    "dnsrecon": Tool("dnsrecon", Category.RECON, "DNS recon", "dnsrecon -d {domain}"),
    "dnsenum": Tool("dnsenum", Category.RECON, "DNS enum", "dnsenum {domain}"),
    "fierce": Tool("fierce", Category.RECON, "DNS scanner", "fierce --domain {domain}"),
    "dig": Tool("dig", Category.RECON, "DNS lookup", "dig {type} {domain}"),
    "host": Tool("host", Category.RECON, "DNS lookup", "host {domain}"),
    "whois": Tool("whois", Category.RECON, "Domain info", "whois {domain}"),
    "traceroute": Tool("traceroute", Category.RECON, "Path trace", "traceroute {target}"),
    "arp-scan": Tool("arp-scan", Category.RECON, "ARP scanner", "arp-scan -l"),
    "netdiscover": Tool("netdiscover", Category.RECON, "Network discovery", "netdiscover -r {range}"),
    "nbtscan": Tool("nbtscan", Category.RECON, "NetBIOS scan", "nbtscan {target}"),
    "responder": Tool("responder", Category.RECON, "LLMNR poisoner", "responder -I {iface}", risk="high"),
    "crackmapexec": Tool("crackmapexec", Category.RECON, "Network swiss knife", "crackmapexec {proto} {target}"),
    "netexec": Tool("netexec", Category.RECON, "Network exec", "netexec {proto} {target}"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # WEB APPLICATION (40+)
    # ─────────────────────────────────────────────────────────────────────────
    "gobuster": Tool("gobuster", Category.WEB, "Dir brute-force", "gobuster dir -u {url} -w {wordlist}"),
    "feroxbuster": Tool("feroxbuster", Category.WEB, "Recursive scan", "feroxbuster -u {url}"),
    "ffuf": Tool("ffuf", Category.WEB, "Fast fuzzer", "ffuf -u {url}/FUZZ -w {wordlist}"),
    "dirsearch": Tool("dirsearch", Category.WEB, "Path scanner", "dirsearch -u {url}"),
    "dirb": Tool("dirb", Category.WEB, "Web scanner", "dirb {url} {wordlist}"),
    "wfuzz": Tool("wfuzz", Category.WEB, "Web fuzzer", "wfuzz -c -w {wordlist} {url}/FUZZ"),
    "nikto": Tool("nikto", Category.WEB, "Vuln scanner", "nikto -h {target}"),
    "nuclei": Tool("nuclei", Category.WEB, "Template scanner", "nuclei -u {url} -t {templates}"),
    "whatweb": Tool("whatweb", Category.WEB, "Tech fingerprint", "whatweb {url}"),
    "wpscan": Tool("wpscan", Category.WEB, "WordPress scan", "wpscan --url {url}"),
    "joomscan": Tool("joomscan", Category.WEB, "Joomla scan", "joomscan -u {url}"),
    "droopescan": Tool("droopescan", Category.WEB, "CMS scanner", "droopescan scan {cms} -u {url}"),
    "sqlmap": Tool("sqlmap", Category.WEB, "SQL injection", "sqlmap -u '{url}' --batch", risk="high"),
    "commix": Tool("commix", Category.WEB, "Command inject", "commix -u '{url}' --batch", risk="high"),
    "xsstrike": Tool("xsstrike", Category.WEB, "XSS scanner", "xsstrike -u '{url}'"),
    "dalfox": Tool("dalfox", Category.WEB, "XSS finder", "dalfox url '{url}'"),
    "arjun": Tool("arjun", Category.WEB, "Param discovery", "arjun -u {url}"),
    "paramspider": Tool("paramspider", Category.WEB, "Param mining", "paramspider -d {domain}"),
    "httpx": Tool("httpx", Category.WEB, "HTTP toolkit", "httpx -u {url} -title -tech-detect"),
    "katana": Tool("katana", Category.WEB, "Web crawler", "katana -u {url}"),
    "hakrawler": Tool("hakrawler", Category.WEB, "Fast crawler", "echo {url} | hakrawler"),
    "gau": Tool("gau", Category.WEB, "Get all URLs", "gau {domain}"),
    "waybackurls": Tool("waybackurls", Category.WEB, "Wayback URLs", "waybackurls {domain}"),
    "wafw00f": Tool("wafw00f", Category.WEB, "WAF detect", "wafw00f {url}"),
    "sslscan": Tool("sslscan", Category.WEB, "SSL scanner", "sslscan {target}"),
    "sslyze": Tool("sslyze", Category.WEB, "SSL analyzer", "sslyze {target}"),
    "testssl": Tool("testssl.sh", Category.WEB, "SSL tester", "testssl.sh {target}"),
    "jwt_tool": Tool("jwt_tool", Category.WEB, "JWT tester", "jwt_tool {token}"),
    "nosqlmap": Tool("nosqlmap", Category.WEB, "NoSQL inject", "nosqlmap -u {url}", risk="high"),
    "tplmap": Tool("tplmap", Category.WEB, "SSTI exploit", "tplmap -u '{url}'", risk="high"),
    "graphqlmap": Tool("graphqlmap", Category.WEB, "GraphQL test", "graphqlmap -u {url}"),
    "cors-scanner": Tool("cors-scanner", Category.WEB, "CORS check", "python cors_scan.py -u {url}"),
    "smuggler": Tool("smuggler", Category.WEB, "Request smuggle", "python smuggler.py -u {url}"),
    "crlfuzz": Tool("crlfuzz", Category.WEB, "CRLF scanner", "crlfuzz -u {url}"),
    "kiterunner": Tool("kr", Category.WEB, "API scanner", "kr scan {url} -w routes.kite"),
    "subfinder": Tool("subfinder", Category.WEB, "Subdomain finder", "subfinder -d {domain}"),
    "amass": Tool("amass", Category.WEB, "Asset discovery", "amass enum -d {domain}"),
    "sublist3r": Tool("sublist3r", Category.WEB, "Subdomain enum", "sublist3r -d {domain}"),
    "assetfinder": Tool("assetfinder", Category.WEB, "Find assets", "assetfinder {domain}"),
    "aquatone": Tool("aquatone", Category.WEB, "Screenshot", "cat urls.txt | aquatone"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # PASSWORD & AUTH (15+)
    # ─────────────────────────────────────────────────────────────────────────
    "hydra": Tool("hydra", Category.PASSWORD, "Login cracker", "hydra -l {user} -P {wordlist} {target} {service}", risk="high"),
    "medusa": Tool("medusa", Category.PASSWORD, "Parallel cracker", "medusa -h {target} -u {user} -P {wordlist} -M {module}"),
    "ncrack": Tool("ncrack", Category.PASSWORD, "Network cracker", "ncrack -U {users} -P {wordlist} {target}"),
    "john": Tool("john", Category.PASSWORD, "Hash cracker", "john --wordlist={wordlist} {hashfile}"),
    "hashcat": Tool("hashcat", Category.PASSWORD, "GPU cracker", "hashcat -m {mode} {hashfile} {wordlist}"),
    "evil-winrm": Tool("evil-winrm", Category.PASSWORD, "WinRM shell", "evil-winrm -i {target} -u {user} -p {pass}", risk="high"),
    "impacket-secretsdump": Tool("secretsdump.py", Category.PASSWORD, "Dump secrets", "secretsdump.py {domain}/{user}:{pass}@{target}", risk="high"),
    "impacket-psexec": Tool("psexec.py", Category.PASSWORD, "Remote exec", "psexec.py {domain}/{user}:{pass}@{target}", risk="high"),
    "impacket-wmiexec": Tool("wmiexec.py", Category.PASSWORD, "WMI exec", "wmiexec.py {domain}/{user}:{pass}@{target}", risk="high"),
    "impacket-smbexec": Tool("smbexec.py", Category.PASSWORD, "SMB exec", "smbexec.py {domain}/{user}:{pass}@{target}", risk="high"),
    "kerbrute": Tool("kerbrute", Category.PASSWORD, "Kerberos brute", "kerbrute userenum -d {domain} {wordlist}"),
    "hashid": Tool("hashid", Category.PASSWORD, "Hash identifier", "hashid {hash}"),
    "hash-identifier": Tool("hash-identifier", Category.PASSWORD, "Identify hash", "hash-identifier"),
    "cewl": Tool("cewl", Category.PASSWORD, "Wordlist gen", "cewl {url} -w output.txt"),
    "cupp": Tool("cupp", Category.PASSWORD, "Password profiler", "cupp -i"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # CLOUD SECURITY (20+)
    # ─────────────────────────────────────────────────────────────────────────
    "prowler": Tool("prowler", Category.CLOUD, "Cloud security", "prowler {provider}"),
    "scout-suite": Tool("scout", Category.CLOUD, "Multi-cloud audit", "scout {provider}"),
    "pacu": Tool("pacu", Category.CLOUD, "AWS exploit", "pacu", risk="high"),
    "cloudsploit": Tool("cloudsploit", Category.CLOUD, "Cloud scanner", "cloudsploit scan"),
    "cloudmapper": Tool("cloudmapper", Category.CLOUD, "AWS map", "cloudmapper collect"),
    "aws-cli": Tool("aws", Category.CLOUD, "AWS CLI", "aws {service} {cmd}"),
    "azure-cli": Tool("az", Category.CLOUD, "Azure CLI", "az {service} {cmd}"),
    "gcloud": Tool("gcloud", Category.CLOUD, "GCP CLI", "gcloud {service} {cmd}"),
    "s3scanner": Tool("s3scanner", Category.CLOUD, "S3 scanner", "s3scanner scan -b {bucket}"),
    "bucket-finder": Tool("bucket_finder", Category.CLOUD, "Bucket finder", "bucket_finder.rb {wordlist}"),
    "gcpbucketbrute": Tool("gcpbucketbrute", Category.CLOUD, "GCP buckets", "gcpbucketbrute.py -k {keyword}"),
    "enumerate-iam": Tool("enumerate-iam", Category.CLOUD, "IAM enum", "enumerate-iam.py --access-key {key}"),
    "trufflehog": Tool("trufflehog", Category.CLOUD, "Secret scanner", "trufflehog git {repo}"),
    "gitleaks": Tool("gitleaks", Category.CLOUD, "Git secrets", "gitleaks detect --source {path}"),
    "cloudenum": Tool("cloud_enum", Category.CLOUD, "Cloud enum", "cloud_enum -k {keyword}"),
    "azurehound": Tool("azurehound", Category.CLOUD, "Azure recon", "azurehound -d {domain}"),
    "roadrecon": Tool("roadrecon", Category.CLOUD, "Azure AD recon", "roadrecon gather"),
    "awscli-s3": Tool("aws-s3", Category.CLOUD, "S3 ops", "aws s3 ls s3://{bucket}"),
    "cloudbrute": Tool("cloudbrute", Category.CLOUD, "Cloud brute", "cloudbrute -d {domain}"),
    "cf-check": Tool("cf-check", Category.CLOUD, "Cloudflare check", "cf-check {domain}"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # CONTAINER & K8S (15+)
    # ─────────────────────────────────────────────────────────────────────────
    "trivy": Tool("trivy", Category.CONTAINER, "Vuln scanner", "trivy image {image}"),
    "grype": Tool("grype", Category.CONTAINER, "Image scanner", "grype {image}"),
    "clair": Tool("clair", Category.CONTAINER, "Container scan", "clairctl analyze {image}"),
    "docker-bench": Tool("docker-bench-security", Category.CONTAINER, "Docker CIS", "docker-bench-security.sh"),
    "kube-hunter": Tool("kube-hunter", Category.CONTAINER, "K8s pentest", "kube-hunter --remote {target}"),
    "kube-bench": Tool("kube-bench", Category.CONTAINER, "K8s CIS", "kube-bench run"),
    "kubeaudit": Tool("kubeaudit", Category.CONTAINER, "K8s audit", "kubeaudit all"),
    "kubectl": Tool("kubectl", Category.CONTAINER, "K8s CLI", "kubectl {cmd}"),
    "kubeletctl": Tool("kubeletctl", Category.CONTAINER, "Kubelet exploit", "kubeletctl scan rce --server {target}", risk="high"),
    "peirates": Tool("peirates", Category.CONTAINER, "K8s pentest kit", "peirates"),
    "falco": Tool("falco", Category.CONTAINER, "Runtime security", "falco"),
    "checkov": Tool("checkov", Category.CONTAINER, "IaC scanner", "checkov -d {dir}"),
    "terrascan": Tool("terrascan", Category.CONTAINER, "IaC scanner", "terrascan scan -d {dir}"),
    "hadolint": Tool("hadolint", Category.CONTAINER, "Dockerfile lint", "hadolint {dockerfile}"),
    "dive": Tool("dive", Category.CONTAINER, "Image explorer", "dive {image}"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # BINARY ANALYSIS (25+)
    # ─────────────────────────────────────────────────────────────────────────
    "gdb": Tool("gdb", Category.BINARY, "GNU debugger", "gdb {binary}"),
    "gdb-peda": Tool("gdb-peda", Category.BINARY, "GDB PEDA", "gdb -q {binary}"),
    "gdb-gef": Tool("gdb-gef", Category.BINARY, "GDB GEF", "gdb -q {binary}"),
    "gdb-pwndbg": Tool("gdb-pwndbg", Category.BINARY, "GDB pwndbg", "gdb -q {binary}"),
    "radare2": Tool("r2", Category.BINARY, "RE framework", "r2 {binary}"),
    "ghidra": Tool("ghidra", Category.BINARY, "NSA RE tool", "ghidra"),
    "ghidra-headless": Tool("analyzeHeadless", Category.BINARY, "Headless Ghidra", "analyzeHeadless {project} {folder} -import {binary}"),
    "ida": Tool("ida", Category.BINARY, "IDA Pro", "ida {binary}"),
    "objdump": Tool("objdump", Category.BINARY, "Object dump", "objdump -d {binary}"),
    "readelf": Tool("readelf", Category.BINARY, "ELF reader", "readelf -a {binary}"),
    "strings": Tool("strings", Category.BINARY, "Extract strings", "strings {binary}"),
    "ltrace": Tool("ltrace", Category.BINARY, "Library trace", "ltrace {binary}"),
    "strace": Tool("strace", Category.BINARY, "System trace", "strace {binary}"),
    "checksec": Tool("checksec", Category.BINARY, "Security check", "checksec --file={binary}"),
    "ropper": Tool("ropper", Category.BINARY, "ROP gadgets", "ropper --file {binary}"),
    "ropgadget": Tool("ROPgadget", Category.BINARY, "ROP finder", "ROPgadget --binary {binary}"),
    "one_gadget": Tool("one_gadget", Category.BINARY, "One-shot RCE", "one_gadget {libc}"),
    "pwntools": Tool("pwn", Category.BINARY, "CTF framework", "python -c 'from pwn import *'"),
    "angr": Tool("angr", Category.BINARY, "Binary analysis", "python -c 'import angr'"),
    "binwalk": Tool("binwalk", Category.BINARY, "Firmware analysis", "binwalk {file}"),
    "upx": Tool("upx", Category.BINARY, "Packer/unpacker", "upx -d {binary}"),
    "msfvenom": Tool("msfvenom", Category.BINARY, "Payload gen", "msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt}", risk="high"),
    "capstone": Tool("capstone", Category.BINARY, "Disassembler", "python -c 'from capstone import *'"),
    "keystone": Tool("keystone", Category.BINARY, "Assembler", "python -c 'from keystone import *'"),
    "unicorn": Tool("unicorn", Category.BINARY, "CPU emulator", "python -c 'from unicorn import *'"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # CTF & FORENSICS (25+)
    # ─────────────────────────────────────────────────────────────────────────
    "volatility": Tool("volatility", Category.CTF, "Memory forensics", "volatility -f {dump} {plugin}"),
    "volatility3": Tool("vol", Category.CTF, "Memory forensics v3", "vol -f {dump} {plugin}"),
    "foremost": Tool("foremost", Category.CTF, "File carving", "foremost -i {input} -o {output}"),
    "photorec": Tool("photorec", Category.CTF, "File recovery", "photorec {device}"),
    "testdisk": Tool("testdisk", Category.CTF, "Partition recovery", "testdisk {device}"),
    "scalpel": Tool("scalpel", Category.CTF, "File carving", "scalpel -o {output} {input}"),
    "bulk_extractor": Tool("bulk_extractor", Category.CTF, "Bulk extraction", "bulk_extractor -o {output} {input}"),
    "autopsy": Tool("autopsy", Category.CTF, "Forensic browser", "autopsy"),
    "sleuthkit": Tool("sleuthkit", Category.CTF, "Forensic toolkit", "fls {image}"),
    "steghide": Tool("steghide", Category.CTF, "Steganography", "steghide extract -sf {file}"),
    "stegsolve": Tool("stegsolve", Category.CTF, "Stego analysis", "java -jar stegsolve.jar"),
    "zsteg": Tool("zsteg", Category.CTF, "PNG/BMP stego", "zsteg {file}"),
    "stegseek": Tool("stegseek", Category.CTF, "Steghide cracker", "stegseek {file} {wordlist}"),
    "outguess": Tool("outguess", Category.CTF, "JPEG stego", "outguess -r {file} {output}"),
    "exiftool": Tool("exiftool", Category.CTF, "Metadata", "exiftool {file}"),
    "pngcheck": Tool("pngcheck", Category.CTF, "PNG checker", "pngcheck -v {file}"),
    "xxd": Tool("xxd", Category.CTF, "Hex dump", "xxd {file}"),
    "hexdump": Tool("hexdump", Category.CTF, "Hex viewer", "hexdump -C {file}"),
    "file": Tool("file", Category.CTF, "File type", "file {file}"),
    "binwalk-ctf": Tool("binwalk", Category.CTF, "Extract files", "binwalk -e {file}"),
    "rsactftool": Tool("RsaCtfTool", Category.CTF, "RSA attacks", "RsaCtfTool.py -n {n} -e {e}"),
    "hashpump": Tool("hashpump", Category.CTF, "Hash extension", "hashpump -s {sig} -d {data} -k {len} -a {append}"),
    "cyberchef": Tool("cyberchef", Category.CTF, "Data analysis", "cyberchef"),
    "dcode": Tool("dcode", Category.CTF, "Cipher decoder", "dcode"),
    "fcrackzip": Tool("fcrackzip", Category.CTF, "ZIP cracker", "fcrackzip -D -p {wordlist} {file}"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # OSINT (20+)
    # ─────────────────────────────────────────────────────────────────────────
    "theharvester": Tool("theHarvester", Category.OSINT, "Email harvester", "theHarvester -d {domain} -b all"),
    "sherlock": Tool("sherlock", Category.OSINT, "Username search", "sherlock {username}"),
    "socialscan": Tool("socialscan", Category.OSINT, "Social scanner", "socialscan {target}"),
    "holehe": Tool("holehe", Category.OSINT, "Email checker", "holehe {email}"),
    "maigret": Tool("maigret", Category.OSINT, "Username OSINT", "maigret {username}"),
    "recon-ng": Tool("recon-ng", Category.OSINT, "Recon framework", "recon-ng"),
    "spiderfoot": Tool("spiderfoot", Category.OSINT, "OSINT automation", "spiderfoot -s {target}"),
    "maltego": Tool("maltego", Category.OSINT, "Link analysis", "maltego"),
    "shodan": Tool("shodan", Category.OSINT, "Device search", "shodan search {query}"),
    "censys": Tool("censys", Category.OSINT, "Internet search", "censys search '{query}'"),
    "photon": Tool("photon", Category.OSINT, "OSINT crawler", "photon -u {url}"),
    "metagoofil": Tool("metagoofil", Category.OSINT, "Metadata extract", "metagoofil -d {domain} -t {types}"),
    "h8mail": Tool("h8mail", Category.OSINT, "Breach hunter", "h8mail -t {email}"),
    "ghunt": Tool("ghunt", Category.OSINT, "Google OSINT", "ghunt {email}"),
    "instaloader": Tool("instaloader", Category.OSINT, "Instagram OSINT", "instaloader {profile}"),
    "twint": Tool("twint", Category.OSINT, "Twitter OSINT", "twint -u {username}"),
    "email2phonenumber": Tool("email2phonenumber", Category.OSINT, "Email to phone", "email2phonenumber {email}"),
    "phoneinfoga": Tool("phoneinfoga", Category.OSINT, "Phone OSINT", "phoneinfoga scan -n {number}"),
    "osintgram": Tool("osintgram", Category.OSINT, "Instagram OSINT", "osintgram {target}"),
    "linkedint": Tool("linkedint", Category.OSINT, "LinkedIn OSINT", "linkedint -e {company}"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # EXPLOITATION (15+)
    # ─────────────────────────────────────────────────────────────────────────
    "metasploit": Tool("msfconsole", Category.EXPLOIT, "Metasploit", "msfconsole", risk="high"),
    "searchsploit": Tool("searchsploit", Category.EXPLOIT, "Exploit search", "searchsploit {query}"),
    "msfvenom-exploit": Tool("msfvenom", Category.EXPLOIT, "Payload gen", "msfvenom -p {payload} -f {format}", risk="high"),
    "beef": Tool("beef-xss", Category.EXPLOIT, "Browser exploit", "beef-xss", risk="high"),
    "setoolkit": Tool("setoolkit", Category.EXPLOIT, "Social eng", "setoolkit", risk="high"),
    "veil": Tool("veil", Category.EXPLOIT, "AV evasion", "veil", risk="high"),
    "shellter": Tool("shellter", Category.EXPLOIT, "PE injector", "shellter", risk="high"),
    "unicorn-exploit": Tool("unicorn", Category.EXPLOIT, "PS attack", "unicorn.py", risk="high"),
    "empire": Tool("empire", Category.EXPLOIT, "Post-exploit", "empire", risk="high"),
    "covenant": Tool("covenant", Category.EXPLOIT, "C2 framework", "covenant", risk="high"),
    "sliver": Tool("sliver", Category.EXPLOIT, "C2 framework", "sliver", risk="high"),
    "cobalt-strike": Tool("cobaltstrike", Category.EXPLOIT, "C2 platform", "cobaltstrike", risk="high"),
    "pupy": Tool("pupy", Category.EXPLOIT, "RAT", "pupy", risk="high"),
    "merlin": Tool("merlin", Category.EXPLOIT, "C2 server", "merlin", risk="high"),
    "villain": Tool("villain", Category.EXPLOIT, "C2 generator", "villain", risk="high"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # WIRELESS (10+)
    # ─────────────────────────────────────────────────────────────────────────
    "aircrack-ng": Tool("aircrack-ng", Category.WIRELESS, "WiFi cracker", "aircrack-ng {capture}"),
    "airodump-ng": Tool("airodump-ng", Category.WIRELESS, "WiFi sniffer", "airodump-ng {iface}"),
    "aireplay-ng": Tool("aireplay-ng", Category.WIRELESS, "Packet inject", "aireplay-ng {opts} {iface}", risk="high"),
    "wifite": Tool("wifite", Category.WIRELESS, "Auto WiFi audit", "wifite", risk="high"),
    "reaver": Tool("reaver", Category.WIRELESS, "WPS cracker", "reaver -i {iface} -b {bssid}", risk="high"),
    "bully": Tool("bully", Category.WIRELESS, "WPS brute", "bully {iface} -b {bssid}", risk="high"),
    "fluxion": Tool("fluxion", Category.WIRELESS, "WiFi phishing", "fluxion", risk="high"),
    "kismet": Tool("kismet", Category.WIRELESS, "WiFi detector", "kismet"),
    "bettercap": Tool("bettercap", Category.WIRELESS, "Network attack", "bettercap -iface {iface}", risk="high"),
    "hostapd-wpe": Tool("hostapd-wpe", Category.WIRELESS, "Evil twin", "hostapd-wpe {conf}", risk="high"),
    
    # ─────────────────────────────────────────────────────────────────────────
    # NETWORK UTILITIES
    # ─────────────────────────────────────────────────────────────────────────
    "netcat": Tool("nc", Category.NETWORK, "Network utility", "nc {opts} {target} {port}"),
    "socat": Tool("socat", Category.NETWORK, "Socket relay", "socat {opts}"),
    "tcpdump": Tool("tcpdump", Category.NETWORK, "Packet capture", "tcpdump -i {iface}"),
    "wireshark": Tool("wireshark", Category.NETWORK, "Protocol analyzer", "wireshark"),
    "tshark": Tool("tshark", Category.NETWORK, "CLI Wireshark", "tshark -i {iface}"),
    "ngrep": Tool("ngrep", Category.NETWORK, "Network grep", "ngrep -q '{pattern}'"),
    "hping3": Tool("hping3", Category.NETWORK, "Packet crafter", "hping3 {target}"),
    "proxychains": Tool("proxychains", Category.NETWORK, "Proxy chains", "proxychains {cmd}"),
    "chisel": Tool("chisel", Category.NETWORK, "TCP tunneling", "chisel server -p {port}"),
    "ligolo-ng": Tool("ligolo-ng", Category.NETWORK, "Tunneling", "ligolo-ng"),
}


def get_tool(name: str) -> Optional[Tool]:
    """Get tool by name"""
    return TOOLS.get(name.lower()) or TOOLS.get(name)


def get_by_category(cat: Category) -> List[Tool]:
    """Get all tools in category"""
    return [t for t in TOOLS.values() if t.category == cat]


def count() -> int:
    """Total tool count"""
    return len(TOOLS)


def stats() -> Dict[str, int]:
    """Category statistics"""
    s = {}
    for t in TOOLS.values():
        c = t.category.value
        s[c] = s.get(c, 0) + 1
    return s


if __name__ == "__main__":
    print(f"\n🛠️  Kali-GPT Tool Registry v2.0")
    print(f"{'═'*40}")
    print(f"📊 Total Tools: {count()}")
    print(f"\n📁 By Category:")
    for cat, cnt in sorted(stats().items(), key=lambda x: -x[1]):
        print(f"   • {cat}: {cnt}")
