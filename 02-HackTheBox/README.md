# Hack The Box — Public Portfolio

Sanitized case studies from **Hack The Box**. Each box lives in its own folder with:

- `README.md` — walkthrough (executive summary, phases, commands).
- `FINDINGS.md` — risk/impact/remediation with OWASP/CWE mappings (+ CVSS/MITRE/Detection/Re-test when applicable).
- `evidence/` — index template for reproducible, sanitized artifacts.

## Structure

```
machines/
01-fawn/
02-smb-guest/
03-redeemer/
04-ssti-flask-mako/
05-arctic/
06-querier/
07-bastion/
```

## Methodology (HTB Labs)

1) Lab Prep & Scope — confirm VPN, target IP, and lab rules.
2) Recon & Port Scanning — identify open TCP ports (UDP if relevant).
3) Service/Version Enumeration — banners, default scripts, web/dir, shares.
4) Vulnerability Analysis — map versions/configs to CVEs/misconfigurations.
5) Exploitation (PoC) — minimally invasive proof of the vector.
6) Post-Exploitation (light) — collect benign evidence; avoid state changes.
7) Remediation & Hardening — practical, actionable fixes (OWASP/CWE mapped).
8) Re-test/Validation — how to verify the fix is effective.
9) Reporting — sanitized write-up and evidence.

-Not every phase applies to every box (e.g., some SP boxes won't have post-exploitation).
