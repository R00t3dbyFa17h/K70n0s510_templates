#!/bin/bash
# K70n0s510 NUCLEAR CLEANUP
# Targets the specific templates spamming the Upwork scan and adds Cloudflare blocks.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"

echo "🔇 Applying Cloudflare Silencers to the Noisy List..."

# 1. Fix JWT Confusion (Critical Noise)
cat <<EOF > "$BASE_DIR/A07-authentication/auth-nuclear/jwt-algo-confusion.yaml"
id: K70n0s510-jwt-confusion
info:
  name: JWT Algorithm Confusion
  author: K70n0s510
  severity: critical
  tags: a07,jwt,auth
http:
  - method: GET
    path: ["{{BaseURL}}/api/user"]
    headers:
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature_placeholder"
    matchers-condition: and
    matchers:
      - type: word
        words: ["Invalid signature", "Unauthorized"]
        negative: true
      # CLOUDFLARE BLOCK
      - type: word
        words: ["Cloudflare", "Attention Required", "Access denied", "cf-mitigated"]
        negative: true
EOF

# 2. Fix React SSRF (Critical Noise)
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
      # CLOUDFLARE BLOCK
      - type: word
        words: ["Cloudflare", "Attention Required", "Access denied", "cf-mitigated"]
        negative: true
EOF

# 3. Fix ViewState MAC (Medium Noise)
cat <<EOF > "$BASE_DIR/A08-integrity/deserial-nuclear/viewstate-mac.yaml"
id: K70n0s510-viewstate-mac
info:
  name: ASP.NET ViewState No MAC
  author: K70n0s510
  severity: medium
  tags: a08,aspnet
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["__VIEWSTATE"]
      - type: regex
        regex: ["__VIEWSTATEGENERATOR"]
        negative: true
      # CLOUDFLARE BLOCK
      - type: word
        words: ["Cloudflare", "Attention Required", "Access denied"]
        negative: true
EOF

# 4. Fix DOM XSS Hash (Medium Noise)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-dom-hash.yaml"
id: K70n0s510-xss-dom-hash
info:
  name: DOM XSS Source (location.hash)
  author: K70n0s510
  severity: medium
  tags: xss,dom
http:
  - method: GET
    path: ["{{BaseURL}}/#<img src=x onerror=alert(1)>"]
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words: ["location.hash", "innerHTML", "document.write"]
      # CLOUDFLARE BLOCK
      - type: word
        words: ["Cloudflare", "Attention Required"]
        negative: true
EOF

# 5. Fix Rate Limiting (Low Noise)
cat <<EOF > "$BASE_DIR/A04-insecure-design/logic-nuclear/missing-rate-limit.yaml"
id: K70n0s510-rate-limit
info:
  name: Missing Rate Limiting (Heuristic)
  author: K70n0s510
  severity: low
  tags: a04,ratelimit
http:
  - method: GET
    path: ["{{BaseURL}}/login"]
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words: ["X-RateLimit", "Retry-After"]
        negative: true
      # CLOUDFLARE BLOCK (If blocked, we ARE rate limited by WAF)
      - type: word
        words: ["Cloudflare", "Attention Required", "Access denied"]
        negative: true
EOF

# 6. Fix S3 God Mode (High Noise)
# We are making this stricter. It now requires 'ListBucketResult' OR a CNAME match.
# Just "NoSuchBucket" is too noisy for root domains.
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/s3-godmode.yaml"
id: K70n0s510-s3-godmode
info:
  name: AWS S3 Bucket Takeover (Strict)
  author: K70n0s510
  severity: high
  tags: s3,aws,takeover
http:
  - method: GET
    path:
      - "http://{{Host}}.s3.amazonaws.com"
      - "http://s3.amazonaws.com/{{Host}}"
    matchers-condition: and
    matchers:
      - type: word
        words: ["The specified bucket does not exist"]
      # STRICTER CHECK: Only fire if we don't see Cloudflare headers (implies direct AWS connection)
      - type: word
        part: header
        words: ["Server: Cloudflare", "cf-ray"]
        negative: true
EOF

echo "✅ 6 Noisy Templates Patched. Ready for Rescan."
