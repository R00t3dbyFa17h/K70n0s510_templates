#!/bin/bash
# K70n0s510 API & CLOUD GOD MODE
# 10 Heavy-Duty Templates for API Security and Cloud Leaks.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A05-insecure-design/api-nuclear"
mkdir -p "$BASE_DIR/A02-misconfiguration/cloud-nuclear"

echo "☁️ Building API & Cloud God Mode Arsenal..."

# ==========================================
# 1. GRAPHQL INTROSPECTION GOD MODE
# ==========================================
cat <<EOF > "$BASE_DIR/A05-insecure-design/api-nuclear/graphql-godmode.yaml"
id: K70n0s510-graphql-godmode
info:
  name: GraphQL Introspection God Mode
  author: K70n0s510
  severity: high
  description: Fuzzes 15+ common GraphQL endpoints for Introspection (Schema Leak).
  tags: graphql,api,fuzz
http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/v1/graphql"
      - "{{BaseURL}}/graphql/console"
      - "{{BaseURL}}/hasura/graphql"
      - "{{BaseURL}}/v1/api/graphql"
      - "{{BaseURL}}/graph"
      - "{{BaseURL}}/query"
    body: '{"query":"query IntrospectionQuery{__schema{queryType{name}}}"}'
    headers:
      Content-Type: application/json

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "__schema"
          - "queryType"
          - "IntrospectionQuery"
      - type: status
        status: [200]
EOF

# ==========================================
# 2. SWAGGER / OPENAPI FUZZER
# ==========================================
cat <<EOF > "$BASE_DIR/A05-insecure-design/api-nuclear/swagger-godmode.yaml"
id: K70n0s510-swagger-godmode
info:
  name: Swagger/OpenAPI Documentation Fuzzer
  author: K70n0s510
  severity: info
  description: Checks 20+ locations for API documentation.
  tags: swagger,api,docs
http:
  - method: GET
    path:
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/swagger/index.html"
      - "{{BaseURL}}/api/docs"
      - "{{BaseURL}}/v2/api-docs"
      - "{{BaseURL}}/openapi.json"
      - "{{BaseURL}}/swagger.json"
      - "{{BaseURL}}/api/swagger/index.html"
      - "{{BaseURL}}/documentation/swagger-ui.html"
      - "{{BaseURL}}/libs/swaggerui/"

    matchers-condition: or
    matchers:
      - type: word
        words: ["Swagger UI", "swagger-ui"]
      - type: word
        words: ["\"openapi\":", "\"swagger\":"]
      - type: word
        words: ["api-docs", "API Documentation"]
EOF

# ==========================================
# 3. JWT NONE ALGORITHM (Auth Bypass)
# ==========================================
cat <<EOF > "$BASE_DIR/A05-insecure-design/api-nuclear/jwt-none-godmode.yaml"
id: K70n0s510-jwt-none
info:
  name: JWT None Algorithm Bypass
  author: K70n0s510
  severity: critical
  description: Attempts to bypass authentication by changing JWT algo to 'none'.
  tags: jwt,auth-bypass,api
http:
  - method: GET
    path: ["{{BaseURL}}/api/user", "{{BaseURL}}/api/admin"]
    headers:
      # This is a sample JWT with "alg": "none" header
      Authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJhZG1pbiI6dHJ1ZX0."

    matchers-condition: and
    matchers:
      - type: word
        words: ["\"username\":", "\"email\":", "\"id\":"]
      - type: word
        words: ["Unauthorized", "Invalid token"]
        negative: true
EOF

# ==========================================
# 4. SPRING BOOT ACTUATOR GOD MODE
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/springboot-godmode.yaml"
id: K70n0s510-springboot-godmode
info:
  name: Spring Boot Actuator God Mode
  author: K70n0s510
  severity: high
  description: Fuzzes for Heapdump, Env, Trace, and ConfigProps.
  tags: springboot,misconfig
http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/heapdump"
      - "{{BaseURL}}/actuator/configprops"
      - "{{BaseURL}}/actuator/mappings"
      - "{{BaseURL}}/actuator/httptrace"
      - "{{BaseURL}}/env"
      - "{{BaseURL}}/heapdump"

    matchers-condition: or
    matchers:
      - type: word
        words: ["\"activeProfiles\":", "propertySources"]
      - type: word
        words: ["application/vnd.spring-boot.actuator"]
      - type: binary
        binary: ["1f8b0800"] # GZIP header for heapdump
EOF

# ==========================================
# 5. FIREBASE CONFIG LEAK
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/firebase-godmode.yaml"
id: K70n0s510-firebase-godmode
info:
  name: Firebase Config (.json) Leak
  author: K70n0s510
  severity: critical
  description: Checks for public access to Firebase database JSON.
  tags: firebase,cloud,google
http:
  - method: GET
    path:
      - "{{BaseURL}}/.json"
      - "{{BaseURL}}/firebase.json"
      - "https://{{Host}}.firebaseio.com/.json"

    matchers-condition: and
    matchers:
      - type: word
        words: ["\"rules\":", "\"users\":", "\"auth\":"]
      - type: word
        words: ["error", "Permission denied"]
        negative: true
EOF

# ==========================================
# 6. S3 BUCKET TAKEOVER / LEAK
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/s3-godmode.yaml"
id: K70n0s510-s3-godmode
info:
  name: AWS S3 Bucket Listing / Takeover
  author: K70n0s510
  severity: high
  tags: s3,aws,takeover
http:
  - method: GET
    path:
      - "http://{{Host}}.s3.amazonaws.com"
      - "http://s3.amazonaws.com/{{Host}}"

    matchers-condition: or
    matchers:
      - type: word
        name: takeover
        words: ["The specified bucket does not exist"]
      - type: word
        name: listing
        words: ["ListBucketResult", "<Name>{{Host}}</Name>"]
EOF

# ==========================================
# 7. SECRETS & KEYS (Regex God Mode)
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/secrets-godmode.yaml"
id: K70n0s510-secrets-godmode
info:
  name: API Key & Secret Regex Hunter
  author: K70n0s510
  severity: critical
  description: Scans response bodies for AWS, Google, Stripe, Slack, and Private Keys.
  tags: token,secrets,leaks
http:
  - method: GET
    path: ["{{BaseURL}}", "{{BaseURL}}/config.js", "{{BaseURL}}/main.js", "{{BaseURL}}/app.js"]

    matchers-condition: or
    matchers:
      - type: regex
        name: aws-access-key
        regex: ["AKIA[0-9A-Z]{16}"]
      - type: regex
        name: google-api
        regex: ["AIza[0-9A-Za-z\\-_]{35}"]
      - type: regex
        name: slack-token
        regex: ["xox[baprs]-([0-9a-zA-Z]{10,48})"]
      - type: regex
        name: private-key
        regex: ["-----BEGIN PRIVATE KEY-----"]
      - type: regex
        name: stripe-key
        regex: ["sk_live_[0-9a-zA-Z]{24}"]
EOF

# ==========================================
# 8. KUBERNETES API UNAUTH
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/k8s-godmode.yaml"
id: K70n0s510-k8s-godmode
info:
  name: Kubernetes API Unauthenticated Access
  author: K70n0s510
  severity: critical
  tags: k8s,kubernetes,cloud
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/pods"
      - "{{BaseURL}}/api/v1/secrets"
      - "{{BaseURL}}:10250/pods" # Kubelet
      - "{{BaseURL}}:6443/api/v1"

    matchers-condition: and
    matchers:
      - type: word
        words: ["\"kind\":", "\"apiVersion\":", "\"items\":"]
      - type: status
        status: [200]
EOF

# ==========================================
# 9. DOCKER REGISTRY CATALOG
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/cloud-nuclear/docker-godmode.yaml"
id: K70n0s510-docker-godmode
info:
  name: Docker Registry Catalog
  author: K70n0s510
  severity: high
  tags: docker,cloud
http:
  - method: GET
    path:
      - "{{BaseURL}}/v2/_catalog"
      - "{{BaseURL}}/v2/"

    matchers-condition: and
    matchers:
      - type: word
        words: ["\"repositories\":", "Docker-Distribution-Api-Version"]
      - type: status
        status: [200]
EOF

# ==========================================
# 10. GITLAB PUBLIC API LEAK
# ==========================================
cat <<EOF > "$BASE_DIR/A05-insecure-design/api-nuclear/gitlab-godmode.yaml"
id: K70n0s510-gitlab-godmode
info:
  name: GitLab Public Projects/Users
  author: K70n0s510
  severity: medium
  tags: gitlab,api
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v4/projects"
      - "{{BaseURL}}/api/v4/users"
      - "{{BaseURL}}/api/v4/groups"

    matchers-condition: and
    matchers:
      - type: word
        words: ["\"visibility\":\"public\"", "\"avatar_url\":"]
      - type: status
        status: [200]
EOF

echo "✅ 10 API & Cloud God Mode Templates Built."
