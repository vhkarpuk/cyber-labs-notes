# Findings — Bastion

## Finding 1 — Unauthenticated SMB Share Exposing a Full System-Image Backup

### Summary
A null/anonymous SMB session can browse a `Backups` share containing a Windows VHD system-image backup of the host.

### Vulnerability Details
- **Type:** Security Misconfiguration / Insecure Storage of Sensitive Data
- **Severity:** High
- **Affected Component:** SMB share `Backups` (TCP/445)
- **Authentication required:** None

### Technical Analysis
The share allows unauthenticated access to a complete filesystem image. Because a VHD contains the full OS volume — including the registry hives that hold password hashes — exposing it is equivalent to leaking an offline copy of the host's secrets.

### Exploitation Steps
1. `smbclient -N -L //<TARGET_IP>/` — list shares.
2. `smbclient -N //<TARGET_IP>/Backups` — browse to `WindowsImageBackup\`.
3. Identify the `.vhd` disk images.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — full disk image incl. hive-stored hashes |
| Integrity | Low — read access |
| Availability | Low |
| Exploitation | Trivial — unauthenticated |

### Remediation
**Immediate:** Remove backups from anonymously readable shares.
**Long-term:** Authenticated least-privilege share access; encrypt backups at rest; store off-host with access logging.

### Mappings
OWASP A05; CWE-306; CWE-312.

### Re-test
Anonymous access to the backup share is denied; backups are encrypted and access-controlled.

---

## Finding 2 — Offline SAM/SYSTEM Extraction → NTLM Recovery

### Summary
Mounting the exposed VHD provides the `SAM` and `SYSTEM` hives, from which local NTLM hashes are dumped and cracked to recover a valid user password.

### Vulnerability Details
- **Type:** Insufficiently Protected / Recoverable Credentials
- **Severity:** High (direct consequence of Finding 1)
- **Affected Component:** Windows local account database (SAM), backed up in the VHD
- **Authentication required:** None (offline from the leaked image)

### Technical Analysis
`samdump2` (or `secretsdump`) uses the SYSTEM boot key to decrypt the SAM and output local NTLM hashes. The recovered NT hash for `l4mpje` is cracked offline against a wordlist, yielding cleartext credentials valid for SSH.

### Exploitation Steps
1. `guestmount --add <disk>.vhd --inspector --ro /mnt/vhd`.
2. Copy `Windows/System32/config/{SAM,SYSTEM}`.
3. `samdump2 SYSTEM SAM` → NTLM hash for `l4mpje`.
4. Crack offline (`hashcat -m 1000 ...`) → `<REDACTED>`.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — valid user credentials recovered |
| Integrity | Medium — interactive access to the host |
| Availability | Low |
| Exploitation | Moderate — offline crack required |

### Remediation
**Immediate:** Remediate Finding 1 (no readable images); rotate recovered credentials.
**Long-term:** Enforce a strong password policy; monitor for unusual backup access; protect backups so hives cannot be extracted.

### Mappings
OWASP A05; CWE-522; CWE-312.

### Re-test
Hives are not retrievable from any share; recovered credentials rotated.

---

## Finding 3 — mRemoteNG Reversible Credential Storage → Local Administrator

### Summary
mRemoteNG stores saved connection passwords in `confCons.xml` using a reversible scheme (a default/known key when no custom master password is set), allowing recovery of the stored local Administrator credential.

### Vulnerability Details
- **Type:** Use of a Broken/Recoverable Password Storage scheme
- **Severity:** Critical
- **Affected Component:** mRemoteNG `confCons.xml`
- **Authentication required:** Local (foothold as `l4mpje`)

### Technical Analysis
Without a user-set master password, mRemoteNG encrypts stored credentials with a hardcoded default key, so anyone who can read `confCons.xml` can decrypt the saved passwords with a public tool. One stored entry contains the local Administrator credential.

### Exploitation Steps
1. Locate `%APPDATA%\mRemoteNG\confCons.xml` on the host.
2. Exfiltrate it (e.g. `scp`).
3. Decrypt with a public mRemoteNG decryptor → `<REDACTED>`.
4. `ssh administrator@<TARGET_IP>` with the recovered password.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — local Administrator credential recovered |
| Integrity | High — full host control |
| Availability | High |
| Exploitation | Trivial — public decryptor |

### Remediation
**Immediate:** Rotate the exposed Administrator credential.
**Long-term:** Set a strong custom master password in mRemoteNG (or avoid storing credentials in it); restrict access to the config file; deploy LAPS for unique local admin passwords.

### Mappings
OWASP A02; A05; CWE-257; CWE-522; CWE-326.

### Re-test
Stored credentials are not decryptable without the master password; exposed accounts rotated.

## Testing Checklist
- [ ] Anonymous SMB lists/read `Backups`
- [ ] VHD mountable; SAM/SYSTEM retrievable
- [ ] NTLM for `l4mpje` dumped and cracked
- [ ] SSH foothold as `l4mpje`
- [ ] mRemoteNG `confCons.xml` present and decryptable
- [ ] Administrator recovered and validated
- [ ] Verify remediations (share ACLs, backup encryption, mRemoteNG master password)

## References
- [OWASP — Security Misconfiguration (A05)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-257: Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)
- [libguestfs (guestmount)](https://libguestfs.org/) · [samdump2](https://tools.kali.org/password-attacks/samdump2)
