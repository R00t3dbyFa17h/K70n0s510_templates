# K70n0s510 Templates: The Detection Engineering Collection

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Platform](https://img.shields.io/badge/platform-Nuclei-green.svg) ![Standard](https://img.shields.io/badge/standard-OWASP%202025-orange.svg) ![Status](https://img.shields.io/badge/status-Active%20Hunting-red.svg)

## 🛡️ Mission Statement
This repository represents a shift from "manual scanning" to **Detection-as-Code**. 
It contains custom-engineered vulnerability signatures designed to align with the **OWASP Top 10: 2025 Release Candidate**, specifically targeting modern architectural flaws in Cloud, CI/CD, and AI pipelines.

Unlike generic community templates, these signatures are **"On Steroids"**—tuned for **High Fidelity** and **Deep Logic** using flow control, regex verification, and binary analysis.

## 🧠 Engineering Philosophy (Why this engine is different)

### 1. 🌊 Flow Logic & Context Awareness
We don't just spray requests. We use **conditional execution flows**.
* *Example:* The **Jenkins Hunter** first identifies a Jenkins instance. *Only then* does it attempt to access the Script Console or decipher `credentials.xml`, preventing noise and alert fatigue.

### 2. 🎯 Negative Matching (Zero False Positives)
A `200 OK` is not a vulnerability. 
* *Example:* The **Kubernetes Scanner** explicitly ignores blog posts and documentation by checking for HTML tags like `<!DOCTYPE html>` in the response body. If it triggers, it's real.

### 3. 🧩 Polyglot Payloads
Cloud environments are complex. 
* *Example:* The **SSRF Hunter** doesn't just check AWS. It injects headers (`X-Forwarded-For`) to bypass WAFs and checks AWS, GCP, Azure, and Alibaba metadata endpoints simultaneously.

### 4. 🔍 Binary & Regex Analysis
* **Binary:** We verify ZIP file magic bytes (`504B0304`) to confirm artifact downloads are valid archives.
* **Regex:** The **Mega-Secrets** template uses 50+ optimized regex patterns to distinguish between a random string and a valid Stripe/Slack/AWS token.

## 📂 Architecture & Coverage (OWASP 2025)

| Category | Vulnerability Class | Detection Strategy |
| :--- | :--- | :--- |
| **A01: Access Control** | **SSRF / Metadata** | Polyglot header injection targeting cloud metadata services (AWS/GCP/Azure). |
| **A02: Misconfiguration** | **Kubernetes & Cloud** | Deep probes on Kubelet API (10250) & header-validated S3 bucket enumeration. |
| **A03: Supply Chain** | **CI/CD Pipelines** | Analysis of Jenkins `consoleText` and binary validation of TeamCity `artifacts.zip`. |
| **A05: Insecure Design** | **API Leaks** | GraphQL introspection mapping & Swagger/OpenAPI route discovery. |
| **A07: Authentication** | **Secret Exposure** | 50+ Regex patterns for API keys, SSH private keys, and Auth tokens. |
| **A10: Error Handling** | **AI & Logic** | Fuzzing Jupyter Notebooks (`.ipynb`) and forcing verbose stack traces in Python/Java. |

## 🛠️ Usage

**Prerequisite:** [Install Nuclei](https://github.com/projectdiscovery/nuclei)

### 1. Automated Scan (Recommended)
Use the included helper script to standardize scan flags, rate limits, and output formatting.
```bash
chmod +x run-scan.sh
./run-scan.sh target.com
```

### 2. Manual Execution
To run the specialized "Supply Chain" suite:
```bash
nuclei -u https://target.com -t owasp-2025/A03-supply-chain/ -rl 50 -bs 10
```

## ⚠️ Legal Disclaimer
**For Educational and Authorized Security Testing Only.**
This repository is a collection of security research tools. Usage of these templates for attacking targets without prior mutual consent is illegal. The author (K70n0s510) assumes no liability for unauthorized use.

---
*Maintained by K70n0s510 | "Stop Scanning, Start Hunting."*
