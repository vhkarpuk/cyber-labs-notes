# Cybersecurity Labs & Notes

Hands-on notes and sanitized case studies from my cybersecurity training — HackTheBox and TryHackMe. I'm studying Cyber Security at university and use these labs to build practical, real-world skills.

## Contents

### HackTheBox Machines
- [01 – Fawn](./02-HackTheBox/machines/01-fawn/) — FTP anonymous access
- [02 – SMB Guest](./02-HackTheBox/machines/02-smb-guest/) — SMB guest/anonymous access
- [03 – Redeemer](./02-HackTheBox/machines/03-redeemer/) — Unauthenticated Redis enumeration
- [04 – SSTI (Flask / Mako)](./02-HackTheBox/machines/04-ssti-flask-mako/) — Server-side template injection to RCE
- [05 – Arctic](./02-HackTheBox/machines/05-arctic/) — Adobe ColdFusion 8 file upload (RCE) + local privesc
- [06 – Querier](./02-HackTheBox/machines/06-querier/) — SMB-exposed creds → MSSQL NetNTLMv2 coercion → GPP cpassword
- [07 – Bastion](./02-HackTheBox/machines/07-bastion/) — SMB-exposed VHD → SAM/NTLM → mRemoteNG credential recovery

Each machine folder follows the same format: `README.md` (walkthrough), `FINDINGS.md` (risk/impact/remediation with OWASP/CWE mapping), `evidence/` (sanitized artifacts). See [02-HackTheBox](./02-HackTheBox/) for the full methodology.

### TryHackMe Labs
- *(in progress)*

## Tools & Skills

Tools used across the walkthroughs above: Nmap, smbclient/smbmap, redis-cli, impacket (mssqlclient/psexec), Responder, samdump2, libguestfs (guestmount), Metasploit, John the Ripper / hashcat.
Techniques: service enumeration, unauthenticated file upload, coerced NTLM authentication, offline hash cracking, insecure credential storage, Windows local privilege escalation.
Scripting: C, Python, Bash.

## Disclaimer

These notes are for educational purposes only.
