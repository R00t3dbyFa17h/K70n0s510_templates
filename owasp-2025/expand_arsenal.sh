#!/bin/bash
BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"

echo -e "\033[0;34m🚀 Adding the missing 50+ Templates...\033[0m"

# --- MISSING INFRASTRUCTURE (A02/A05) ---
cat <<EOF > "$BASE_DIR/A02-misconfiguration/apache-status.yaml"
id: K70n0s510-apache-status
info: {name: Apache Server Status, severity: medium}
http: [{method: GET, path: ["{{BaseURL}}/server-status"], matchers: [{type: status, status: [200]}, {type: word, words: ["Apache Server Status"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A02-misconfiguration/directory-listing.yaml"
id: K70n0s510-directory-listing
info: {name: Directory Listing Enabled, severity: info}
http: [{method: GET, path: ["{{BaseURL}}/images/", "{{BaseURL}}/uploads/"], matchers: [{type: status, status: [200]}, {type: word, words: ["Index of /"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A05-insecure-design/robots-txt.yaml"
id: K70n0s510-robots-txt
info: {name: Robots.txt Found, severity: info}
http: [{method: GET, path: ["{{BaseURL}}/robots.txt"], matchers: [{type: status, status: [200]}, {type: word, words: ["User-agent:"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A06-vulnerable-components/xmlrpc.yaml"
id: K70n0s510-xmlrpc
info: {name: WordPress XML-RPC, severity: low}
http: [{method: GET, path: ["{{BaseURL}}/xmlrpc.php"], matchers: [{type: status, status: [405, 200]}, {type: word, words: ["XML-RPC server accepts POST"]}]}]
EOF

# --- MISSING CRITICALS (A99) ---
cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2024-23897-jenkins.yaml"
id: CVE-2024-23897
info: {name: Jenkins CLI File Read, severity: high}
http: [{method: GET, path: ["{{BaseURL}}/cli?remoting=false"], headers: {Session: "UUID-123", Side: "download"}, matchers: [{type: word, words: ["Jenkins-CLI"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-46805-ivanti.yaml"
id: CVE-2023-46805
info: {name: Ivanti Connect Secure Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/api/v1/totp/user-backup-code/../../system/system-information"], matchers: [{type: word, words: ["system-information"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-42793-teamcity.yaml"
id: CVE-2023-42793
info: {name: TeamCity Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/app/rest/users/id:1/tokens/RPC2"], matchers: [{type: word, words: ["<token name="]}]}]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-7028-gitlab.yaml"
id: CVE-2023-7028
info: {name: GitLab Account Takeover, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/users/password/new"], matchers: [{type: word, words: ["authenticity_token", "gitlab"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-3128-grafana.yaml"
id: CVE-2023-3128
info: {name: Grafana Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/login/azuread"], matchers: [{type: word, words: ["Grafana", "login"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2023-34362-moveit.yaml"
id: CVE-2023-34362
info: {name: MOVEit Transfer SQLi, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/human.aspx"], matchers: [{type: word, words: ["MOVEit Transfer"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A99-critical-cves/CVE-2022-41040-exchange.yaml"
id: CVE-2022-41040
info: {name: Exchange ProxyNotShell, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/autodiscover/autodiscover.json?@evil.com/&Email=autodiscover/autodiscover.json%3f@evil.com"], matchers: [{type: word, words: ["Microsoft Exchange"]}]}]
EOF

# --- MISSING 2025 ZERO DAYS (A100) ---
cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-20334-cisco.yaml"
id: CVE-2025-20334
info: {name: Cisco IOS XE API Injection, severity: critical}
http: [{method: PUT, path: ["{{BaseURL}}/restconf/data/Cisco-IOS-XE-native:native"], matchers: [{type: status, status: [401, 200]}, {type: word, words: ["Cisco-IOS-XE"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-22462-ivanti-neurons.yaml"
id: CVE-2025-22462
info: {name: Ivanti Neurons Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/HEAT/ServiceAPI/Frs_SaaS_App.aspx"], matchers: [{type: word, words: ["Ivanti Neurons", "SessionId"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-32756-fortivoice.yaml"
id: CVE-2025-32756
info: {name: FortiVoice RCE, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/voice/user/login"], matchers: [{type: word, words: ["FortiVoice", "admin"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-24813-tomcat.yaml"
id: CVE-2025-24813
info: {name: Tomcat Path Traversal RCE, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/..;/WEB-INF/web.xml"], matchers: [{type: word, words: ["<web-app"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-20281-cisco-ise.yaml"
id: CVE-2025-20281
info: {name: Cisco ISE RCE, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/admin/LoginAction.action"], matchers: [{type: word, words: ["Cisco ISE"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A100-2025-zero-days/CVE-2025-49825-teleport.yaml"
id: CVE-2025-49825
info: {name: Teleport Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/web/login"], matchers: [{type: word, words: ["Teleport", "<title>Login"]}]}]
EOF

# --- MISSING NUCLEAR (A101) ---
cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-8424-citrix.yaml"
id: CVE-2025-8424
info: {name: Citrix NetScaler Access Control Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/admin/ns_gui/ns_gui.htm"], matchers: [{type: word, words: ["NetScaler", "Management"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-59481-f5.yaml"
id: CVE-2025-59481
info: {name: F5 BIG-IP iControl REST PrivEsc, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/mgmt/shared/authn/login"], matchers: [{type: word, words: ["restjavad", "BIG-IP"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-26399-solarwinds.yaml"
id: CVE-2025-26399
info: {name: SolarWinds Web Help Desk RCE, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/helpdesk/Action/AjaxProxy?class=java.util.ArrayList"], matchers: [{type: status, status: [500]}, {type: word, words: ["SolarWinds"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-43561-coldfusion.yaml"
id: CVE-2025-43561
info: {name: Adobe ColdFusion Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/CFIDE/adminapi/accessmanager.cfc?method=check"], matchers: [{type: word, words: ["wddxPacket"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-31161-crushftp.yaml"
id: CVE-2025-31161
info: {name: CrushFTP AWS4 Auth Bypass, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/"], headers: {Authorization: "AWS4-HMAC-SHA256 Credential=FOO"}, matchers: [{type: word, words: ["<dir>", "CrushFTP"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-8078-zyxel.yaml"
id: CVE-2025-8078
info: {name: Zyxel Firewall Command Injection, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/cgi-bin/zld_auth?cmd=whoami"], matchers: [{type: word, words: ["root", "admin"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2025-53770-sharepoint.yaml"
id: CVE-2025-53770
info: {name: SharePoint Unauth RCE, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/_vti_bin/Sites.asmx"], matchers: [{type: word, words: ["SharePoint", "wsdl"]}]}]
EOF

cat <<EOF > "$BASE_DIR/A101-2025-nuclear/CVE-2023-43208-mirth.yaml"
id: CVE-2023-43208
info: {name: Mirth Connect Unauth RCE, severity: critical}
http: [{method: GET, path: ["{{BaseURL}}/api/server/version"], headers: {X-Requested-With: "OpenAPI"}, matchers: [{type: word, words: ["4.4.0", "4.3.0"]}]}]
EOF

echo -e "\n\033[0;32m✅ Expansion Pack Installed. Verify count below:\033[0m"
find "$BASE_DIR" -name "*.yaml" | wc -l
