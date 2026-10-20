# Security Policy

FrogSec Labs believes in proactive, ethical, and collaborative vulnerability disclosure to protect the wider infrastructure ecosystem.

If you believe you have found a security vulnerability or bypass in **NetDeflect**, please follow this guide to report it responsibly.

---

## Supported Versions

Only the latest major version branch receives active vulnerability patches and mitigation updates.

| Version | Supported          |
| ------- | ------------------ |
| 4.x.x   | :white_check_mark: |
| < 4.0   | :x:                |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities or zero-day bypasses through public GitHub issues, pull requests, or public community channels.**

To report a vulnerability privately and securely:

1. **GitHub Private Security Advisory (Preferred):**
   - Navigate to the repository's [Security tab](https://github.com/0vm/NetDeflect/security).
   - Click on **"Report a vulnerability"** to draft a private advisory.
   - This creates a private channel between the research team and maintainers where PoCs, logs, and remediation patches can be reviewed confidentially.

2. **Direct Contact:**
   - If GitHub Advisories are not accessible, reach out via the maintainer's designated contact on GitHub (`@0vm`).

---

## Report Guidelines

To help us triage and verify your finding as rapidly as possible, please include:

- **Vulnerability Category:** (e.g., *Kernel Filter Bypass, Denial-of-Service via Carpet-Bombing Aggregation, Rule Injection, False Positive State Lock*).
- **Environment Details:**
  - NetDeflect version / commit hash (`netdeflect.py --version`).
  - Firewall backend in use (`nftables`, `iptables`, `xdp`, `bgp`).
  - Kernel version (`uname -r`) and distribution.
- **Proof of Concept (PoC):**
  - Minimal reproducible example (packet format, crafted header flags, or flood reproduction script).
  - Observed behavior vs. expected behavior.
- **Impact Assessment:**
  - Explanation of how an adversary could exploit this behavior (e.g., whether it leads to unmitigated transit exhaustion, service failure, or collateral customer disconnects).

---

## Disclosure Policy & SLA

- **Acknowledgment:** Maintainers will aim to acknowledge receipt of your initial report within **48 to 72 hours**.
- **Assessment & Triage:** An initial evaluation and reproducer verification will follow within **7 days**.
- **Remediation & Patching:** A coordinated release date will be aligned with the reporter. Standard embargo periods range between **30 to 90 days** depending on vulnerability severity, allowing operators adequate time to deploy updates before public disclosure.
- **Credit:** Researchers following responsible disclosure will receive full attribution in the release notes and GitHub Security Advisory.

---

*Authored with standard industry CVD (Coordinated Vulnerability Disclosure) best practices by FrogSec Labs.*
