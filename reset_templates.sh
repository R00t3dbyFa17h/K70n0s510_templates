#!/bin/bash
# K70n0s510 Template Reset Script
# This will clean the owasp-2025 folder and rebuild the entire arsenal.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"

echo -e "\n\033[0;33m🧹 Cleaning up old/mismatched templates in $BASE_DIR...\033[0m"
rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"
mkdir -p "$BASE_DIR/A01-access-control"
mkdir -p "$BASE_DIR/A02-misconfiguration"
mkdir -p "$BASE_DIR/A03-supply-chain"
mkdir -p "$BASE_DIR/A05-insecure-design"
mkdir -p "$BASE_DIR/A06-vulnerable-components"
mkdir -p "$BASE_DIR/A10-error-handling"
mkdir -p "$BASE_DIR/A99-critical-cves"
mkdir -p "$BASE_DIR/A100-2025-zero-days"
mkdir -p "$BASE_DIR/A101-2025-nuclear"

echo -e "\033[0;34m🛠️ Rebuilding Arsenal (80+ Templates)...\033[0m"

# --- 1. CORE & MISCONFIGURATIONS ---
cat <<EOF > "$BASE_DIR/A01-access-control/cloud-metadata-ssrf.yaml"
id: K70n0s510-polyglot-metadata
info:
  name: Cloud Metadata SSRF (Polyglot & Bypass)
  author: K70n0s510
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/"
      - "{{BaseURL}}/?url=http://metadata.google.internal/computeMetadata/v1/project/project-id"
    headers:
      X-Forwarded-For: 127.0.0.1
      Metadata-Flavor: Google
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["ami-id", "instance-id", "computeMetadata", "google"]
EOF

cat <<EOF > "$BASE_DIR/A05-insecure-design/juiceshop-artifacts.yaml"
id: K70n0s510-juiceshop-artifacts
info:
  name: OWASP Juice Shop Specific Artifacts
  author: K70n0s510
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/rest/admin/application-configuration"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["application-configuration", "\"config\":"]
EOF

cat <<EOF > "$BASE_DIR/A02-misconfiguration/exposed-env.yaml"
id: K70n0s510-exposed-env
info:
  name: Critical Environment File (.env) Exposure
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["DB_PASSWORD=", "AWS_ACCESS_KEY_ID="]
EOF

cat <<EOF > "$BASE_DIR/A03-supply-chain/exposed-git-config.yaml"
id: K70n0s510-exposed-git-config
info:
  name: Exposed .git/config File
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["[core]", "repositoryformatversion"]
EOF

cat <<EOF > "$BASE_DIR/A02-misconfiguration/editor-temp-files.yaml"
id: K70n0s510-editor-temp-files
info:
  name: Exposed Editor Temporary Files (.swp/~)
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/index.php.swp"
      - "{{BaseURL}}/.env.swp"
      - "{{BaseURL}}/wp-config.php.swp"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: binary
        binary: ["623056494d"]
EOF

cat <<EOF > "$BASE_DIR/A05-insecure-design/swagger-ui.yaml"
id: K70n0s510-swagger-ui
info:
  name: Public Swagger/OpenAPI Documentation
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/api/docs"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Swagger UI", "\"openapi\":"]
EOF

cat <<EOF > "$BASE_DIR/A10-error-handling/exposed-logs.yaml"
id: K70n0s510-exposed-logs
info:
  name: Exposed Application Log Files
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/debug.log"
      - "{{BaseURL}}/storage/logs/laravel.log"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Stack trace", "Debug Message", "PHP Fatal error"]
EOF

# --- 2. GUARANTEED HITS ---
cat <<EOF > "$BASE_DIR/A02-misconfiguration/phpinfo.yaml"
id: K70n0s510-phpinfo
info:
  name: PHPInfo Exposed
  severity: medium
http:
  - method: GET
    path: ["{{BaseURL}}/phpinfo.php", "{{BaseURL}}/info.php"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["PHP Extension", "PHP Version"]
EOF

cat <<EOF > "$BASE_DIR/A02-misconfiguration/backup-zips.yaml"
id: K70n0s510-backup-zips
info:
  name: Exposed Backup Archives
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/www.zip", "{{BaseURL}}/backup.zip"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: binary
        binary: ["504b0304"]
EOF

cat <<EOF > "$BASE_DIR/A06-vulnerable-components/wordpress-users.yaml"
id: K70n0s510-wordpress-users
info:
  name: WordPress User Enumeration
  severity: low
http:
  - method: GET
    path: ["{{BaseURL}}/wp-json/wp/v2/users"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["\"slug\":", "\"id\":"]
EOF

# --- 3. CRITICAL CVEs (A99) ---
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2024-1709-screenconnect.yaml"
id: CVE-2024-1709
info:
  name: ConnectWise ScreenConnect Auth Bypass
  severity: critical
http:
  - method: GET
    path: ["{{BaseURL}}/SetupWizard.aspx/"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["ConnectWise ScreenConnect", "SetupWizard"]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-22515-confluence.yaml"
id: CVE-2023-22515
info:
  name: Confluence Data Center Auth Bypass
#!/bin/bash
# K70n0s510 Template Reset Script
# This will clean the owasp-2025 folder and rebuild the entire arsenal.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"

echo -e "\n\033[0;33m🧹 Cleaning up old/mismatched templates in $BASE_DIR...\033[0m"
rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"
mkdir -p "$BASE_DIR/A01-access-control"
mkdir -p "$BASE_DIR/A02-misconfiguration"
mkdir -p "$BASE_DIR/A03-supply-chain"
mkdir -p "$BASE_DIR/A05-insecure-design"
mkdir -p "$BASE_DIR/A06-vulnerable-components"
mkdir -p "$BASE_DIR/A10-error-handling"
mkdir -p "$BASE_DIR/A99-critical-cves"
mkdir -p "$BASE_DIR/A100-2025-zero-days"
mkdir -p "$BASE_DIR/A101-2025-nuclear"

echo -e "\033[0;34m🛠️ Rebuilding Arsenal (80+ Templates)...\033[0m"

# --- 1. CORE & MISCONFIGURATIONS ---
cat <<EOF > "$BASE_DIR/A01-access-control/cloud-metadata-ssrf.yaml"
id: K70n0s510-polyglot-metadata
info:
  name: Cloud Metadata SSRF (Polyglot & Bypass)
  author: K70n0s510
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/"
      - "{{BaseURL}}/?url=http://metadata.google.internal/computeMetadata/v1/project/project-id"
    headers:
      X-Forwarded-For: 127.0.0.1
      Metadata-Flavor: Google
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["ami-id", "instance-id", "computeMetadata", "google"]
EOF

cat <<EOF > "$BASE_DIR/A05-insecure-design/juiceshop-artifacts.yaml"
id: K70n0s510-juiceshop-artifacts
info:
  name: OWASP Juice Shop Specific Artifacts
  author: K70n0s510
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/rest/admin/application-configuration"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["application-configuration", "\"config\":"]
EOF

cat <<EOF > "$BASE_DIR/A02-misconfiguration/exposed-env.yaml"
id: K70n0s510-exposed-env
info:
  name: Critical Environment File (.env) Exposure
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["DB_PASSWORD=", "AWS_ACCESS_KEY_ID="]
EOF

cat <<EOF > "$BASE_DIR/A03-supply-chain/exposed-git-config.yaml"
id: K70n0s510-exposed-git-config
info:
  name: Exposed .git/config File
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["[core]", "repositoryformatversion"]
EOF

cat <<EOF > "$BASE_DIR/A02-misconfiguration/editor-temp-files.yaml"
id: K70n0s510-editor-temp-files
info:
  name: Exposed Editor Temporary Files (.swp/~)
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/index.php.swp"
      - "{{BaseURL}}/.env.swp"
      - "{{BaseURL}}/wp-config.php.swp"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: binary
        binary: ["623056494d"]
EOF

cat <<EOF > "$BASE_DIR/A05-insecure-design/swagger-ui.yaml"
id: K70n0s510-swagger-ui
info:
  name: Public Swagger/OpenAPI Documentation
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/swagger-ui.html"
      - "{{BaseURL}}/api/docs"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Swagger UI", "\"openapi\":"]
EOF

cat <<EOF > "$BASE_DIR/A10-error-handling/exposed-logs.yaml"
id: K70n0s510-exposed-logs
info:
  name: Exposed Application Log Files
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/debug.log"
      - "{{BaseURL}}/storage/logs/laravel.log"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Stack trace", "Debug Message", "PHP Fatal error"]
EOF

# --- 2. GUARANTEED HITS ---
cat <<EOF > "$BASE_DIR/A02-misconfiguration/phpinfo.yaml"
id: K70n0s510-phpinfo
info:
  name: PHPInfo Exposed
  severity: medium
EOF

# --- FINAL VERIFICATION ---
echo -e "\n\033[0;32m✅ Build Complete. Verifying Template Count in: $BASE_DIR\033[0m"
nuclei -t "$BASE_DIR" -tl | wc -l
