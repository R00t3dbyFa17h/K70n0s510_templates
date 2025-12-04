  GNU nano 8.7                 build_silent_config.sh

#!/bin/bash
# K70n0s510 SILENT CONFIG HUNTER
# 10 Low-Noise Templates for identifying infrastructure leaks.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A02-misconfiguration/config-nuclear"

echo "🤫 Building Silent Config Arsenal..."

# ==========================================
# 1. Docker Compose Leak
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/docker-compose.yaml"
id: K70n0s510-docker-compose
info:
  name: Exposed Docker Compose File
  author: K70n0s510
  severity: high
  description: Detects exposed docker-compose.yml which leaks service architecture and environment variables.
  tags: config,docker,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/docker-compose.yml"
      - "{{BaseURL}}/docker-compose.yaml"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "version:"
          - "services:"
          - "image:"
      - type: status
        status: [200]
EOF

# ==========================================
# 2. NPM Package.json Leak
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/npm-package.yaml"
id: K70n0s510-npm-package
info:
  name: Exposed package.json
  author: K70n0s510
  severity: medium
  description: Leaks all node.js dependencies and versions, allowing for CVE mapping.
  tags: config,node,npm
http:
  - method: GET
    path:
      - "{{BaseURL}}/package.json"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "\"name\":"
          - "\"dependencies\":"
          - "\"version\":"
      - type: status
        status: [200]
EOF

# ==========================================
# 3. PHP Composer.json Leak
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/composer-json.yaml"
id: K70n0s510-composer-json
info:
  name: Exposed composer.json
  author: K70n0s510
  severity: medium
  description: Leaks PHP dependencies and versions.
  tags: config,php,composer
http:
  - method: GET
    path:
      - "{{BaseURL}}/composer.json"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "\"require\":"
          - "\"license\":"
      - type: status
        status: [200]
EOF

# ==========================================
# 4. JetBrains (.idea) Exposure
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/jetbrains-idea.yaml"
id: K70n0s510-jetbrains-idea
info:
  name: Exposed JetBrains .idea Project
  author: K70n0s510
  severity: low
  description: Detects exposed .idea configuration files from IntelliJ/PyCharm.
  tags: config,ide,jetbrains
http:
  - method: GET
    path:
      - "{{BaseURL}}/.idea/workspace.xml"
      - "{{BaseURL}}/.idea/modules.xml"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "project version"
          - "component name="
      - type: status
        status: [200]
EOF

# ==========================================
# 5. VSCode Configuration Exposure
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/vscode-settings.yaml"
id: K70n0s510-vscode-settings
info:
  name: Exposed .vscode Settings
  author: K70n0s510
  severity: low
  description: Detects exposed VSCode settings.json which may contain paths or env vars.
  tags: config,ide,vscode
http:
  - method: GET
    path:
      - "{{BaseURL}}/.vscode/settings.json"
      - "{{BaseURL}}/.vscode/sftp.json"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "editor.tabSize"
          - "files.exclude"
      - type: status
        status: [200]
EOF

# ==========================================
# 6. Django Debug Mode
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/django-debug.yaml"
id: K70n0s510-django-debug
info:
  name: Django Debug Mode Enabled
  author: K70n0s510
  severity: medium
  description: Detects the distinct yellow Django error page indicating Debug=True.
  tags: config,django,python
http:
  - method: GET
    path:
      - "{{BaseURL}}/doesnotexist_random_123"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "DisallowedHost"
          - "Django"
          - "Request Method:"
          - "Exception Type:"
      - type: status
        status: [404, 500]
EOF

# ==========================================
# 7. Laravel Debug Mode
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/laravel-debug.yaml"
id: K70n0s510-laravel-debug
info:
  name: Laravel Debug Mode Enabled
  author: K70n0s510
  severity: medium
  description: Detects exposed Laravel stack traces (Ignition).
  tags: config,laravel,php
http:
  - method: GET
    path:
      - "{{BaseURL}}/_ignition/health-check"
      - "{{BaseURL}}/doesnotexist_random_123"
    matchers-condition: or
    matchers:
      - type: word
        words: ["\"can_connect\":", "\"service\":\""]
      - type: word
        words: ["Whoops! There was an error.", "Generate a documentation key"]
EOF

# ==========================================
# 8. Ruby on Rails Info Route
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/rails-info.yaml"
id: K70n0s510-rails-info
info:
  name: Ruby on Rails Info/Routes Exposure
  author: K70n0s510
  severity: medium
  description: Detects the /rails/info/routes page which lists all API endpoints.
  tags: config,rails,ruby
http:
  - method: GET
    path:
      - "{{BaseURL}}/rails/info/routes"
      - "{{BaseURL}}/rails/info/properties"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<strong>Routes</strong>"
          - "Path"
          - "Controller#Action"
      - type: status
        status: [200]
EOF

# ==========================================
# 9. Server Status (Extended)
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/apache-status-extended.yaml"
id: K70n0s510-apache-status-ext
info:
  name: Apache Server Status (Extended)
  author: K70n0s510
  severity: low
  description: Checks for the machine-readable version of server-status.
  tags: config,apache
http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status?auto"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Total Accesses:"
          - "Total kBytes:"
          - "Uptime:"
      - type: status
        status: [200]
EOF

# ==========================================
# 10. Webpack Source Map Leak
# ==========================================
cat <<EOF > "$BASE_DIR/A02-misconfiguration/config-nuclear/webpack-sourcemap.yaml"
id: K70n0s510-webpack-sourcemap
info:
  name: Webpack Source Map Leak
  author: K70n0s510
  severity: info
  description: Detects presence of .js.map files which allow reconstructing frontend source code.
  tags: config,webpack,js
http:
  - method: GET
    path:
      - "{{BaseURL}}/main.js.map"
      - "{{BaseURL}}/app.js.map"
      - "{{BaseURL}}/runtime.js.map"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "\"sources\":["
          - "\"mappings\":"
      - type: status
        status: [200]
EOF

echo "✅ 10 Silent Config Templates Built."
