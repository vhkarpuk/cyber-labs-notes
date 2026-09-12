# HTB: Arctic (ColdFusion) — Evidence (Sanitized, text-only)

Timestamp (UTC): <YYYY-MM-DD HH:MM:SS UTC>
Environment: Linux <host> <kernel_version> #1 SMP <date> <arch>
Tool versions:
- Nmap 7.94SVN
- Metasploit Framework
- msfvenom

# VPN / Reachability
sudo openvpn <vpn_name>.ovpn
ping <TARGET_IP>

# Scans (commands + sanitized outputs)
sudo nmap -p- -sV <TARGET_IP>
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp?        # Adobe ColdFusion
49154/tcp open  msrpc

# Foothold (sanitized)
# ColdFusion admin at http://<TARGET_IP>:8500/CFIDE/administrator/
# Public PoC → JSP upload → reverse shell
whoami
arctic\tolis                 # service-account context (foothold)

# Privilege escalation (sanitized)
run post/multi/recon/local_exploit_suggester
migrate <x64_PID>
getuid
Server username: NT AUTHORITY\SYSTEM

# Notes
- Replace placeholders <TARGET_IP>, <ATTACKER_IP>, <x64_PID>.
- Do not include flags/credentials; keep sensitive values as <REDACTED>.
