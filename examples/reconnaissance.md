# Reconnaissance Examples

Examples of using Kali GPT Advanced for reconnaissance and information gathering.

## Example 1: Subdomain Enumeration

**Scenario:** Find all subdomains for a target domain

### Steps:
1. Switch to **Reconnaissance Mode**
2. Ask AI:
   ```
   "Find all subdomains for target.com using multiple techniques"
   ```

3. AI provides commands like:
   ```bash
   # Passive reconnaissance
   subfinder -d target.com -silent

   # Active DNS enumeration
   amass enum -d target.com

   # Certificate transparency
   curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
   ```

4. Execute commands via Option 3
5. AI analyzes discovered subdomains
6. Get recommendations for next steps (port scanning, etc.)

---

## Example 2: Network Port Scanning

**Scenario:** Discover open ports and services on target

### Steps:
1. Quick Command Generation (Option 2)
2. Request:
   ```
   "Comprehensive port scan on 192.168.1.100"
   ```

3. AI generates optimized scan:
   ```bash
   # Quick scan first
   nmap -T4 -F 192.168.1.100

   # Then comprehensive
   nmap -sS -sV -sC -O -p- -T4 192.168.1.100 -oN scan_results.txt
   ```

4. Execute and analyze results
5. AI identifies interesting services
6. Suggests enumeration for found services

---

## Example 3: Web Application Fingerprinting

**Scenario:** Identify technologies used by web application

### Steps:
1. Switch to **Web Application Mode**
2. Build Workflow (Option 4):
   ```
   "Fingerprint technologies on https://target.com"
   ```

3. AI creates workflow:
   ```bash
   # Technology detection
   whatweb -v https://target.com

   # Detailed headers
   curl -I https://target.com

   # Directory enumeration
   ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ

   # WAF detection
   wafw00f https://target.com
   ```

4. Execute each step
5. AI correlates findings
6. Provides attack surface analysis

---

## Example 4: OSINT on Target Organization

**Scenario:** Gather public information about target

### Steps:
1. Reconnaissance Mode
2. Ask:
   ```
   "Perform OSINT on target-corp.com to find email formats, employees, and technologies"
   ```

3. AI suggests tools:
   ```bash
   # Email harvesting
   theHarvester -d target-corp.com -b all

   # DNS reconnaissance
   dnsrecon -d target-corp.com

   # Google dorking
   # (AI provides specific dorks)

   # Social media enumeration
   # (AI suggests LinkedIn, Twitter searches)
   ```

4. Analyze findings
5. Create target profile
6. Plan next phase

---

## Example 5: Service Enumeration

**Scenario:** Deep enumeration of discovered services

### Steps:
1. After port scan finds SMB (445) open
2. Ask AI:
   ```
   "Enumerate SMB on 192.168.1.100"
   ```

3. AI provides comprehensive commands:
   ```bash
   # SMB version detection
   nmap -p 445 --script smb-protocols 192.168.1.100

   # Share enumeration
   smbclient -L //192.168.1.100 -N

   # Null session check
   enum4linux -a 192.168.1.100

   # Vulnerability scanning
   nmap -p 445 --script smb-vuln* 192.168.1.100
   ```

4. Execute with AI analysis
5. Identify vulnerabilities
6. Get exploitation suggestions

---

## Tips for Effective Reconnaissance

1. **Start Passive**: Use passive techniques before active scanning
2. **Take Notes**: Use AI to analyze and correlate findings
3. **Be Methodical**: Follow the workflow suggested by AI
4. **Document Everything**: Keep logs of all discoveries
5. **Stay Legal**: Only scan authorized targets

---

## Common Reconnaissance Tools Integrated

- nmap - Port scanning and service detection
- subfinder - Subdomain enumeration
- amass - In-depth DNS enumeration
- theHarvester - OSINT and email gathering
- whatweb - Web technology detection
- ffuf/gobuster - Directory fuzzing
- enum4linux - SMB enumeration
- dnsrecon - DNS reconnaissance
- nikto - Web server scanning

---

**Remember:** All examples assume authorized testing only. Always have explicit permission before conducting any reconnaissance activities.
