# 🛡️ K70n0s510 Templates: The Detection Engineering Collection

![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Templates](https://img.shields.io/badge/Templates-150%2B-red)
![Focus](https://img.shields.io/badge/Focus-High%20Fidelity-blue)
![OWASP](https://img.shields.io/badge/Standard-OWASP%202025-orange)

## 🛡️ Mission Statement
This repository represents a shift from **"manual scanning"** to **Detection-as-Code**.

It contains custom-engineered vulnerability signatures designed to align with the **OWASP Top 10: 2025 Release Candidate**, specifically targeting modern architectural flaws in Cloud, CI/CD, and AI pipelines.

Unlike generic community templates, these signatures are **"On Steroids"**—tuned for **High Fidelity** and **Deep Logic** using flow control, regex verification, and binary analysis.

---

## 🧠 Engineering Philosophy

### 1. 🌊 Flow Logic & Context Awareness
We don't just spray requests. We use conditional execution flows.
> **Example:** The *Jenkins Hunter* first identifies a Jenkins instance. Only *then* does it attempt to access the Script Console or decipher `credentials.xml`, preventing noise and alert fatigue.

### 2. 🎯 Negative Matching (Zero False Positives)
A `200 OK` is not a vulnerability.
> **Example:** The *Kubernetes Scanner* explicitly ignores blog posts and documentation by checking for HTML tags like `<!DOCTYPE html>` in the response body, ensuring only raw API responses trigger an alert.

### 3. 🧩 Polyglot Payloads
> **Example:** The *SSRF Hunter* injects headers (`X-Forwarded-For`) to bypass WAFs and checks AWS, GCP, Azure, and Alibaba metadata endpoints simultaneously in a single request.

### 4. 🔍 Binary & Regex Analysis
* **Binary:** We verify ZIP file magic bytes (`504B0304`) to confirm artifact downloads are valid archives.
* **Regex:** The *Mega-Secrets* template uses 50+ optimized regex patterns to distinguish between a random string and a valid Stripe/Slack/AWS token.

---

## 📂 Architecture & Coverage (OWASP 2025)

| Category | Vulnerability Class | Detection Strategy |
| :--- | :--- | :--- |
| **A01: Access Control** | SSRF / Metadata | Polyglot header injection targeting cloud metadata services (AWS, GCP, Azure). |
| **A02: Misconfiguration** | Kubernetes & Cloud | Deep probes on Kubelet API (`10250`) & header-validated S3 bucket enumeration. |
| **A03: Injection** | SQLi / XSS / LFI | **"God Mode"** templates using 5+ payloads per check (Time-based, Error-based, Polyglot XSS). |
| **A05: Insecure Design** | API Leaks | GraphQL introspection mapping & Swagger/OpenAPI route discovery. |
| **A06: Vuln Components** | Infrastructure RCE | **"Nuclear"** checks for Log4Shell, Struts OGNL, and Jenkins Script Console. |
| **A07: Authentication** | Secret Exposure | 50+ Regex patterns for API keys, SSH private keys, and Auth tokens. |
| **A10: SSRF** | Network Forgery | Blind OOB interaction checks via Interactsh. |
| **A99 / A100** | **Criticals & Zero-Days** | Specific exploits for ScreenConnect, Palo Alto, Ivanti, and Citrix Bleed. |

---

## 🛠️ Usage

### Prerequisite
Ensure [Nuclei](https://github.com/projectdiscovery/nuclei) is installed.

### 1. The Automation Script (Recommended)
This repository includes a robust wrapper script that handles rate limiting, colorized output, and dependency checking.

**Setup:**
```bash
chmod +x run-scan.sh
./run-scan.sh --help

Run a Scan:
Bash

./run-scan.sh [https://target.com](https://target.com)

2. Manual Execution

To run specific "Nuclear" suites (e.g., Supply Chain only):
Bash

nuclei -u [https://target.com](https://target.com) -t owasp-2025/A03-supply-chain/ -rl 50 -bs 10

⚠️ Legal Disclaimer

For Educational and Authorized Security Testing Only.

This repository is a collection of security research tools. Usage of these templates for attacking targets without prior mutual consent is illegal. The author (K70n0s510) assumes no liability for unauthorized use.

Maintained by K70n0s510 | "Stop Scanning, Start Hunting."
