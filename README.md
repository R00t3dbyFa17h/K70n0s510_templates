# K70n0s510 Templates: OWASP 2025 Edition

**Official Nuclei Templates by K70n0s510.**

This repository focuses on next-generation vulnerability detection, aligning with the upcoming OWASP Top 10 (2025) standards.

## Structure
- **A03: Supply Chain Risks:** Detection for exposed CI/CD pipelines and secrets.
- **A10: Complex Error Handling:** Stack trace and debug exposure detection.
- **A02: Misconfiguration:** Infrastructure-as-Code exposure.

## Usage
To use these templates with Nuclei:
```bash
nuclei -t owasp-2025/ -u https://target.com
```
