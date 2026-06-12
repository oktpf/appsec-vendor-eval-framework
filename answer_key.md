# Answer Key - Multi-Testbed Framework

## SAST Findings (Dataflow)

## secret-testbed (11 findings)

### 1. SQL Injection (CWE-89)
```
UID: SECRET_CWE-89_0
Source: src/app/apis.py:99
 -> src/app/apis.py:100
 -> src/app/db_utils.py:12
 -> src/app/db_utils.py:15
Sink: src/app/db_utils.py:16
```

### 2. Command Injection (CWE-78)
```
UID: SECRET_CWE-78_0
Source: src/app/apis.py:105
 -> src/app/apis.py:106
 -> src/app/db_utils.py:19
 -> src/app/db_utils.py:20
Sink: src/app/db_utils.py:21
```

### 3. IDOR / Missing Auth (CWE-639)
```
UID: SECRET_CWE-639_0
Source: src/app/apis.py:99
Sink: src/app/apis.py:100
```

### 4. Second-Order SQL Injection (CWE-89)
```
UID: SECRET_CWE-89_1
Source: src/app/db_utils.py:26 (via Database theme_path)
 -> src/app/db_utils.py:29
Sink: src/app/db_utils.py:30
```

### 5. Second-Order Path Traversal (CWE-73)
```
UID: SECRET_CWE-73_0
Source: src/app/db_utils.py:26 (via Database theme_path)
 -> src/app/db_utils.py:29
Sink: src/app/db_utils.py:31
```

### 6. SSRF (CWE-918)
```
UID: SECRET_CWE-918_0
Source: src/app/apis.py:117
Sink: src/app/apis.py:118
```

### 7. Zip Slip (CWE-22)
```
UID: SECRET_CWE-22_0
Source: src/app/apis.py:125
 -> src/app/apis.py:128
 -> src/app/db_utils.py:35
 -> src/app/db_utils.py:37
Sink: src/app/db_utils.py:38
```

### 8. XXE (CWE-611)
```
UID: SECRET_CWE-611_0
Source: src/app/apis.py:133
 -> src/app/apis.py:134
 -> src/app/db_utils.py:40
Sink: src/app/db_utils.py:42
```

### 9. Insecure Deserialization (CWE-502)
```
UID: SECRET_CWE-502_0
Source: src/app/apis.py:139
 -> src/app/apis.py:140
 -> src/app/db_utils.py:45
Sink: src/app/db_utils.py:47
```

### 10. Lambda Command Injection (CWE-78)
```
UID: SECRET_CWE-78_1
Source: aws_lambda/s3_processor.py:10
 -> aws_lambda/s3_processor.py:15
Sink: aws_lambda/s3_processor.py:16
```

### 11. Lambda Path Traversal (CWE-73)
```
UID: SECRET_CWE-73_1
Source: aws_lambda/s3_processor.py:10
 -> aws_lambda/s3_processor.py:12
Sink: aws_lambda/s3_processor.py:13
```

---

## reflection-testbed (8 findings + 4 honeypots)

### 1. Arbitrary Class Instantiation (CWE-470)
```
UID: REFLECTION_CWE-470_0
Source: java/src/main/java/com/testbed/ReflectionController.java:65
Sink: java/src/main/java/com/testbed/ReflectionController.java:66
Difficulty: easy
```

### 2. Reflection-based Command Execution (CWE-94)
```
UID: REFLECTION_CWE-94_0
Source: java/src/main/java/com/testbed/ReflectionController.java:105
Sink: java/src/main/java/com/testbed/ReflectionController.java:106
Difficulty: medium
```

### 3. Untrusted Deserialization (CWE-502)
```
UID: REFLECTION_CWE-502_0
Source: java/src/main/java/com/testbed/DeserializationService.java:33
Sink: java/src/main/java/com/testbed/DeserializationService.java:34
Difficulty: medium
```

### 4. Path Traversal via ResourceBundle (CWE-22)
```
UID: REFLECTION_CWE-22_0
Source: java/src/main/java/com/testbed/ReflectionController.java:152
Sink: java/src/main/java/com/testbed/ReflectionController.java:153
Difficulty: easy
```

### 5. Arbitrary Code Execution via eval() (CWE-94)
```
UID: REFLECTION_CWE-94_1
Source: python/app.py:42
Sink: python/app.py:43
Difficulty: easy
```

### 6. Command Injection via getattr() (CWE-78)
```
UID: REFLECTION_CWE-78_0
Source: python/app.py:85
Sink: python/app.py:86
Difficulty: medium
```

### 7. Arbitrary Module Import via __import__() (CWE-94)
```
UID: REFLECTION_CWE-94_2
Source: python/app.py:129
Sink: python/app.py:130
Difficulty: easy
```

### 8. Unsafe YAML Deserialization (CWE-502)
```
UID: REFLECTION_CWE-502_1
Source: python/app.py:166
Sink: python/app.py:167
Difficulty: easy
```

---

## access-control-testbed (14 findings + 4 honeypots)

### 1. IDOR — User Profile by ID (CWE-639)
```
UID: ACCESS_CWE-639_0
Source: node/src/routes/users.js:12
Sink: node/src/routes/users.js:21
Difficulty: easy
```

### 2. Missing Authorization on Admin Endpoint (CWE-862)
```
UID: ACCESS_CWE-862_0
Source: node/src/routes/users.js:28
Sink: node/src/routes/users.js:42
Difficulty: easy
```

### 3. Mass Assignment — User Model Save (CWE-915)
```
UID: ACCESS_CWE-915_0
Source: node/src/routes/users.js:47
Sink: node/src/routes/users.js:65
Difficulty: easy
```

### 4. Insecure Direct Object Reference via JWT (CWE-285)
```
UID: ACCESS_CWE-285_0
Source: python/app.py:36
Sink: python/app.py:54
Difficulty: medium
```

### 5. Horizontal Privilege Escalation (CWE-639)
```
UID: ACCESS_CWE-639_1
Source: python/app.py:58
Sink: python/app.py:85
Difficulty: easy
```

### 6. Vertical Privilege Escalation (CWE-269)
```
UID: ACCESS_CWE-269_0
Source: node/src/routes/users.js:93
Sink: node/src/routes/users.js:108
Difficulty: hard
```

### 7. Open Redirect After Auth (CWE-601)
```
UID: ACCESS_CWE-601_0
Source: python/app.py:89
Sink: python/app.py:107
Difficulty: easy
```

### 8. Missing Function-Level Access Control (CWE-306)
```
UID: ACCESS_CWE-306_0
Source: node/src/routes/internal.js:8
Sink: node/src/routes/internal.js:22
Difficulty: easy
```

### 9. Mass Assignment via ORM updateMany() (CWE-915)
```
UID: ACCESS_CWE-915_1
Source: python/app.py:112
Sink: python/app.py:140
Difficulty: medium
```

### 10. IDOR via Predictable Sequential IDs (CWE-639)
```
UID: ACCESS_CWE-639_2
Source: node/src/routes/users.js:19
Sink: node/src/routes/users.js:20
Difficulty: easy
```

### 11. Race Condition — Coupon Redemption (CWE-362)
```
UID: ACCESS_CWE-362_0
Source: python/app.py:144
Sink: python/app.py:184
Difficulty: hard
```

### 12. Missing Workflow Enforcement (CWE-840)
```
UID: ACCESS_CWE-840_0
Source: node/src/routes/orders.js:15
Sink: node/src/routes/orders.js:35
Difficulty: hard
```

### 13. Numeric Overflow (CWE-190)
```
UID: ACCESS_CWE-190_0
Source: python/app.py:188
Sink: python/app.py:226
Difficulty: medium
```

### 14. Bulk Operation Without Throttling (CWE-639)
```
UID: ACCESS_CWE-639_3
Source: node/src/routes/internal.js:24
Sink: node/src/routes/internal.js:35
Difficulty: medium
```

---

## database-testbed (8 findings + 3 honeypots)

### 1. TSQL — EXEC(@sql) String Concatenation (CWE-89)
```
UID: DATABASE_CWE-89_0
Source: tsql/procedures/usp_SearchUsers.sql:24
Sink: tsql/procedures/usp_SearchUsers.sql:30
Difficulty: easy
```

### 2. TSQL — Unsanitized Column Name in sp_executesql (CWE-89)
```
UID: DATABASE_CWE-89_1
Source: tsql/procedures/usp_SearchUsers.sql:55
Sink: tsql/procedures/usp_SearchUsers.sql:62
Difficulty: easy
```

### 3. PL/SQL — EXECUTE IMMEDIATE Concatenation (CWE-89)
```
UID: DATABASE_CWE-89_2
Source: plsql/packages/pkg_user_management.sql:45
Sink: plsql/packages/pkg_user_management.sql:50
Difficulty: easy
```

### 4. PL/SQL — DBMS_SQL.PARSE User-Controlled Statement (CWE-89)
```
UID: DATABASE_CWE-89_3
Source: plsql/packages/pkg_report_generator.sql:50
Sink: plsql/packages/pkg_report_generator.sql:57
Difficulty: medium
```

### 5. TSQL — xp_cmdshell Command Injection (CWE-78)
```
UID: DATABASE_CWE-78_0
Source: tsql/procedures/usp_RunDiagnostic.sql:28
Sink: tsql/procedures/usp_RunDiagnostic.sql:30
Difficulty: easy
```

### 6. TSQL — Second-Order Injection via Temp Table (CWE-89)
```
UID: DATABASE_CWE-89_4
Source: tsql/procedures/usp_AuditLog.sql:30
 -> tsql/procedures/usp_AuditLog.sql:45
Sink: tsql/procedures/usp_AuditLog.sql:45
Difficulty: hard
```

### 7. PL/SQL — AUTHID CURRENT_USER Privilege Escalation (CWE-284)
```
UID: DATABASE_CWE-284_0
Source: plsql/packages/pkg_user_management.sql:65
Sink: plsql/packages/pkg_user_management.sql:75
Difficulty: hard
```

### 8. PL/SQL — Dynamic Table Name in View Creation (CWE-89)
```
UID: DATABASE_CWE-89_5
Source: plsql/packages/pkg_report_generator.sql:130
Sink: plsql/packages/pkg_report_generator.sql:137
Difficulty: medium
```

---

## cloud-iac-testbed (10 IaC findings + 4 honeypots)

### 1. Terraform — S3 Bucket Public Read ACL (CWE-250)
```
UID: CLOUD_CWE-250_0
Source: terraform/main.tf:7
Sink: terraform/main.tf:23
Difficulty: easy
```

### 2. Terraform — Security Group SSH Exposure (CWE-250)
```
UID: CLOUD_CWE-250_1
Source: terraform/main.tf:27
Sink: terraform/main.tf:38
Difficulty: easy
```

### 3. Terraform — IAM Policy Wildcard Admin (CWE-276)
```
UID: CLOUD_CWE-276_0
Source: terraform/main.tf:48
Sink: terraform/main.tf:65
Difficulty: easy
```

### 4. Dockerfile — Secrets in ARG Instructions (CWE-798)
```
UID: CLOUD_CWE-798_0
Source: docker/Dockerfile:8
Sink: docker/Dockerfile:9
Difficulty: easy
```

### 5. Dockerfile — Hardcoded Secrets in ENV Instructions (CWE-798)
```
UID: CLOUD_CWE-798_1
Source: docker/Dockerfile:29
Sink: docker/Dockerfile:34
Difficulty: easy
```

### 6. Dockerfile — Secret in RUN Instruction (CWE-798)
```
UID: CLOUD_CWE-798_2
Source: docker/Dockerfile:44
Sink: docker/Dockerfile:44
Difficulty: easy
```

### 7. Kubernetes — Privileged Container with HostPath (CWE-250)
```
UID: CLOUD_CWE-250_2
Source: kubernetes/deployment.yaml:64
Sink: kubernetes/deployment.yaml:99
Difficulty: easy
```

### 8. Kubernetes — No Security Context (CWE-798)
```
UID: CLOUD_CWE-798_3
Source: kubernetes/deployment.yaml:23
Sink: kubernetes/deployment.yaml:111
Difficulty: easy
```

### 9. Kubernetes — Cluster Admin RBAC Binding (CWE-276)
```
UID: CLOUD_CWE-276_1
Source: kubernetes/rbac.yaml:13
Sink: kubernetes/rbac.yaml:20
Difficulty: easy
```

### 10. CloudFormation — S3 Bucket Policy Wildcard Principal (CWE-250)
```
UID: CLOUD_CWE-250_3
Source: cloudformation/template.yaml:35
Sink: cloudformation/template.yaml:44
Difficulty: easy
```

---

## web-vulns-testbed (18 findings + 5 honeypots)

### 1. JWT alg: none Algorithm Accepted (CWE-287)
```
UID: WEB_CWE-287_0
Source: node/src/routes/auth.js:12
Sink: node/src/routes/auth.js:21
Difficulty: easy
```

### 2. MD5 Password Hashing Without Salt (CWE-327)
```
UID: WEB_CWE-327_0
Source: python/flask_app/app.py:17
Sink: python/flask_app/app.py:22
Difficulty: easy
```

### 3. DES/RC4 Weak Encryption (CWE-327)
```
UID: WEB_CWE-327_1
Source: java/src/main/java/com/testbed/EncryptionService.java:20
Sink: java/src/main/java/com/testbed/EncryptionService.java:85
Difficulty: medium
```

### 4. Predictable Session Token via Math.random() (CWE-330)
```
UID: WEB_CWE-330_0
Source: node/src/routes/auth.js:50
Sink: node/src/routes/auth.js:54
Difficulty: easy
```

### 5. Reflected XSS (CWE-79)
```
UID: WEB_CWE-79_0
Source: python/flask_app/app.py:58
Sink: python/flask_app/app.py:75
Difficulty: easy
```

### 6. Stored XSS (CWE-79)
```
UID: WEB_CWE-79_1
Source: node/src/routes/comments.js:14
Sink: node/src/routes/comments.js:20
Difficulty: easy
```

### 7. Server-Side Template Injection (CWE-94)
```
UID: WEB_CWE-94_0
Source: python/flask_app/app.py:80
Sink: python/flask_app/app.py:91
Difficulty: easy
```

### 8. CRLF Injection (CWE-113)
```
UID: WEB_CWE-113_0
Source: java/src/main/java/com/testbed/CookieController.java:24
Sink: java/src/main/java/com/testbed/CookieController.java:60
Difficulty: easy
```

### 9. Host Header Injection (CWE-94)
```
UID: WEB_CWE-94_1
Source: python/flask_app/app.py:96
Sink: python/flask_app/app.py:113
Difficulty: medium
```

### 10. CORS Misconfiguration (CWE-942)
```
UID: WEB_CWE-942_0
Source: node/src/middleware/cors.js:10
Sink: node/src/middleware/cors.js:19
Difficulty: easy
```

### 11. Debug Mode Enabled in Production (CWE-306)
```
UID: WEB_CWE-306_0
Source: python/flask_app/config.py:6
Sink: python/flask_app/config.py:6
Difficulty: easy
```

### 12. Verbose Error Messages Leaking Stack Traces (CWE-209)
```
UID: WEB_CWE-209_0
Source: java/application.yml:3
Sink: java/application.yml:6
Difficulty: easy
```

### 13. Missing Rate Limiting on Login (CWE-308)
```
UID: WEB_CWE-308_0
Source: node/src/routes/auth.js:Comment
Sink: node/src/routes/auth.js:Comment
Difficulty: medium
```

### 14. Open Redirect Without Allowlist (CWE-523)
```
UID: WEB_CWE-523_0
Source: node/src/routes/auth.js:28
Sink: node/src/routes/auth.js:30
Difficulty: easy
```

### 15. Shadow API Endpoint (CWE-1021)
```
UID: WEB_CWE-1021_0
Source: node/src/routes/v1-users.js:12
Sink: node/src/routes/v1-users.js:32
Difficulty: easy
```

### 16. Debug/Admin Endpoint Exposed (CWE-306)
```
UID: WEB_CWE-306_1
Source: java/application.yml:11
Sink: java/application.yml:38
Difficulty: easy
```

### 17. Unsafe Upstream API Consumption (CWE-20)
```
UID: WEB_CWE-20_0
Source: python/flask_app/app.py:122
Sink: python/flask_app/app.py:145
Difficulty: medium
```

### 18. SSRF via Upstream API Call (CWE-918)
```
UID: WEB_CWE-918_1
Source: node/src/routes/proxy.js:10
Sink: node/src/routes/proxy.js:45
Difficulty: medium
```

---

## Hardcoded Credentials (secret-testbed)

```
LOCAL_DB_PASS:src/app/db_utils.py:9
LOCAL_REDIS_TOKEN:src/app/db_utils.py:10
SLACK_WEBHOOK:src/app/apis.py:15
AUTH_CACHE:src/app/views.py:10
SESSION_DEBUG_TOKEN:src/app/views.py:11
FB_APP_SECRET:src/app/__init__.py:4
AWS_ACCESS_KEY_ID:.aws/credentials:2
AWS_SECRET_ACCESS_KEY:.aws/credentials:3
GOOGLE_SERVICE_ACCOUNT:src/app/static/credentials/google-sa.json:4
ARTIFACTORY_API_KEY:build/artifactory_config.xml:4
MONGO_DB_URL:tests/test_db.py:6
HEROKU_API_KEY:.dockerignore:1
MAILGUN_API_KEY:.flake8:2
AZURE_SERVICE_PRINCIPAL:.github/workflows/deploy.yml:14
NPM_TOKEN:.npmrc:1
PYPI_TOKEN:.pypirc:3
GITHUB_PAT:src/run.py:6
RSA_PRIVATE_KEY:src/app/certs/server.key:1
DB_ROOT_PASSWORD:build/Dockerfile:16
SHOPIFY_TOKEN:README.md:21
```

---

# HONEYPOTS (Expected False Positives)

These patterns LOOK vulnerable but are NOT actually exploitable.
Vendors that flag these as real vulnerabilities should be penalized on precision scoring.

## reflection-testbed honeypots (4)

### HP-1: eval() on sanitized/whitelisted input (NOT exploitable)
```
UID: HONEY_REFLECTION_0
File: python/app.py:157 (validate_config endpoint)
Pattern: eval(expr) appears to accept user input
Why safe: Input validated by regex ^[\d\s\+\-\*\/\(\)\.]+$ before eval()
Only numeric expressions allowed — no code execution possible
Expected FP: CWE-94 (Code Injection)
```

### HP-2: os.system() with hardcoded arguments (NOT exploitable)
```
UID: HONEY_REFLECTION_1
File: python/app.py:139 (healthcheck endpoint)
Pattern: os.system("df -h / | tail -1") and os.system("free -m | grep Mem")
Why safe: Commands are hardcoded strings — no user input reaches the sink
Expected FP: CWE-78 (OS Command Injection)
```

### HP-3: Class.forName() on internal packages only (NOT exploitable)
```
UID: HONEY_REFLECTION_2
File: java/src/main/java/com/testbed/ReflectionController.java:150 (loadPlugin endpoint)
Pattern: Class.forName("com.testbed.plugins." + pluginName) appears to allow arbitrary class loading
Why safe: Package prefix "com.testbed.plugins." is hardcoded — user can only load classes within that package
No path traversal or arbitrary class instantiation possible
Expected FP: CWE-470 (Unsafe Reflection)
```

### HP-4: MD5 for cache key generation (NOT exploitable)
```
UID: HONEY_REFLECTION_3
File: java/src/main/java/com/testbed/ReflectionController.java:168 (generateCacheKey endpoint)
Pattern: MessageDigest.getInstance("MD5") used for hashing
Why safe: Used only for generating cache keys from config names — not for passwords or sensitive data
No cryptographic security requirement for this use case
Expected FP: CWE-327 (Use of Broken Cryptographic Algorithm)
```

## access-control-testbed honeypots (4)

### HP-5: SQL query with string concatenation using parameterized values (NOT exploitable)
```
UID: HONEY_ACCESS_0
File: node/src/routes/users.js:92 (users/search endpoint)
Pattern: Dynamic SQL construction with user-provided sortBy column
Why safe: Sequelize ORM handles the query — sortCol is passed to order[] array, not concatenated into raw SQL
Expected FP: CWE-89 (SQL Injection)
```

### HP-6: Missing authorization on audit logs endpoint (NOT exploitable)
```
UID: HONEY_ACCESS_1
File: node/src/routes/users.js:115 (audit/logs endpoint)
Pattern: GET /audit/logs has no auth middleware — appears publicly accessible
Why safe: getAuditLogs() function returns empty array in current implementation
No actual data exposure — endpoint is a stub
Expected FP: CWE-862 (Missing Authorization)
```

### HP-7: Mass assignment on user preferences (NOT exploitable)
```
UID: HONEY_ACCESS_2
File: python/app.py:245 (update_preferences endpoint)
Pattern: setattr(user, key, value) loops through all request fields
Why safe: hasattr(user, key) check ensures only existing User model attributes can be set
Cannot inject arbitrary attributes or escalate privileges
Expected FP: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
```

### HP-8: eval() on sanitized pricing expressions (NOT exploitable)
```
UID: HONEY_ACCESS_3
File: python/app.py:270 (evaluate_pricing_rule endpoint)
Pattern: eval(expr) appears to accept user input for pricing calculations
Why safe: Input validated by regex ^[\d\s\+\-\*\/\(\)\.\%]+$ before eval()
Only numeric expressions allowed — no code execution possible
Expected FP: CWE-94 (Code Injection)
```

## database-testbed honeypots (3)

### HP-9: Dynamic SQL with hardcoded filter values (NOT exploitable)
```
UID: HONEY_DATABASE_0
File: tsql/procedures/usp_GetUserStats.sql
Pattern: EXEC sp_executesql @sql appears to use dynamic SQL with user input
Why safe: @reportType is validated against whitelist ('active', 'admins', 'summary')
SQL filters are hardcoded strings appended conditionally — no user input concatenated
Expected FP: CWE-89 (SQL Injection)
```

### HP-10: xp_cmdshell with fixed command (NOT exploitable)
```
UID: HONEY_DATABASE_1
File: tsql/procedures/usp_RunBackup.sql
Pattern: EXEC xp_cmdshell 'dir C:\Backups' appears to allow command injection
Why safe: Command string is hardcoded — no user input reaches xp_cmdshell
@backupPath parameter is only used in PRINT statement, not executed
Expected FP: CWE-78 (OS Command Injection)
```

### HP-11: EXECUTE IMMEDIATE with bind variables (NOT exploitable)
```
UID: HONEY_DATABASE_2
File: plsql/packages/pkg_audit_logging.sql (log_action procedure)
Pattern: EXECUTE IMMEDIATE v_sql_stmt appears to use dynamic SQL
Why safe: USING clause binds parameters safely — no string concatenation of user input
v_sql_stmt contains only column names and bind placeholders
Expected FP: CWE-89 (SQL Injection)
```

## cloud-iac-testbed honeypots (4)

### HP-12: S3 bucket with public ACL but VPC endpoint policy blocks access (NOT exploitable)
```
UID: HONEY_CLOUD_0
File: terraform/main.tf (analytics_data_lake bucket + s3_gateway endpoint)
Pattern: S3 bucket has block_public_acls = false — appears publicly accessible
Why safe: VPC endpoint policy explicitly Denies s3:* to Principals outside the organization
External access blocked by endpoint policy despite public ACL setting
Expected FP: CWE-250 (Execution with Unnecessary Privileges)
```

### HP-13: Hardcoded secret used only for build-time validation (NOT exploitable)
```
UID: HONEY_CLOUD_1
File: docker/Dockerfile:21 (BUILD_VALIDATION_TOKEN ARG)
Pattern: ARG BUILD_VALIDATION_TOKEN="build_val_tk_..." appears to leak a secret
Why safe: Token is only used in build stage for validation check
Not passed to production stage — not accessible at runtime
Expected FP: CWE-798 (Use of Hard-coded Credentials)
```

### HP-14: Privileged container with read-only root filesystem and resource limits (NOT exploitable)
```
UID: HONEY_CLOUD_2
File: kubernetes/deployment.yaml (monitoring-sidecar-deployment)
Pattern: privileged: true, runAsUser: 0 appears to be a privileged container
Why safe: readOnlyRootFilesystem: true prevents filesystem modifications
allowPrivilegeEscalation: false, capabilities drop ALL except SYS_TIME
Resource limits constrain CPU/memory — hostPath mounts are read-only (/proc, /sys)
Expected FP: CWE-250 (Execution with Unnecessary Privileges)
```

## web-vulns-testbed honeypots (5)

### HP-15: eval() on sanitized search input (NOT exploitable)
```
UID: HONEY_WEB_0
File: python/flask_app/app.py:175 (search_products endpoint)
Pattern: eval(f"'{product['name']}' == '{product['name']}' and True") appears to use eval with user input
Why safe: Search query validated by regex ^[a-zA-Z0-9\s\-_]+$ before use
eval() expression uses only product catalog data — no user input in the evaluated string
Expected FP: CWE-94 (Code Injection)
```

### HP-16: os.system() with hardcoded diagnostic commands (NOT exploitable)
```
UID: HONEY_WEB_1
File: python/flask_app/app.py:200 (run_diagnostics endpoint)
Pattern: os.system("df -h /"), os.system("free -m"), os.system("ps aux | wc -l")
Why safe: All commands are hardcoded strings — no user input reaches os.system()
Expected FP: CWE-78 (OS Command Injection)
```

### HP-17: SQL query with string concatenation using parameterized values (NOT exploitable)
```
UID: HONEY_WEB_2
File: node/src/routes/auth.js:65 (users/search endpoint)
Pattern: Dynamic SQL construction with user-provided name and role parameters
Why safe: executeSearch() function returns empty array — no actual database query executed
Query string is constructed but never passed to a real database driver
Expected FP: CWE-89 (SQL Injection)
```

### HP-18: Class.forName() on internal packages only (NOT exploitable)
```
UID: HONEY_WEB_3
File: java/src/main/java/com/testbed/EncryptionService.java:115 (loadFeatureModule method)
Pattern: Class.forName("com.testbed.features." + moduleName) appears to allow arbitrary class loading
Why safe: Package prefix "com.testbed.features." is hardcoded — user can only load classes within that package
No path traversal or arbitrary class instantiation possible
Expected FP: CWE-470 (Unsafe Reflection)
```

### HP-19: MD5 for content hashing (NOT exploitable)
```
UID: HONEY_WEB_4
File: java/src/main/java/com/testbed/EncryptionService.java:103 (generateContentHash method)
Pattern: MessageDigest.getInstance("MD5") used for hashing content
Why safe: Used only for generating content fingerprints for cache invalidation — not for passwords or sensitive data
No cryptographic security requirement for this use case
Expected FP: CWE-327 (Use of Broken Cryptographic Algorithm)
```

---

## Summary

| Testbed | True Vulnerabilities | Honeypots (Expected FPs) |
|---------|---------------------|--------------------------|
| secret-testbed | 11 SAST + ~23 secrets | 0 |
| reflection-testbed | 8 | 4 |
| access-control-testbed | 14 | 4 |
| database-testbed | 8 | 3 |
| cloud-iac-testbed | 10 IaC | 4 |
| web-vulns-testbed | 18 | 5 |
|| **Total** | **~122-123** | **30** |

---

## mass-assignment-testbed (30 CWE-915 findings + 10 honeypots)

### Java — UserController (3 vulnerable)

#### 1. BeanUtils.copyProperties DTO→Entity (CWE-915)
```
UID: MASSASSIGN_JAVA_USER_0
Source: java/src/main/java/com/acme/controllers/UserController.java:48
Sink: java/src/main/java/com/acme/controllers/UserController.java:53
Pattern: BeanUtils.copyProperties(request, user) copies ALL matching properties from UserProfileUpdateRequest to User entity
Sensitive properties exposed: role, isAdmin, status
Difficulty: easy
```

#### 2. Raw JSON binding on registration (CWE-915)
```
UID: MASSASSIGN_JAVA_USER_1
Source: java/src/main/java/com/acme/controllers/UserController.java:68
Sink: java/src/main/java/com/acme/controllers/UserController.java:73
Pattern: @RequestBody Map<String, Object> userData iterated with setProperty() reflection — no allowlist
Sensitive properties exposed: role, isAdmin, status
Difficulty: easy
```

#### 3. Raw JSON binding on settings update (CWE-915)
```
UID: MASSASSIGN_JAVA_USER_2
Source: java/src/main/java/com/acme/controllers/UserController.java:87
Sink: java/src/main/java/com/acme/controllers/UserController.java:91
Pattern: @RequestBody Map<String, Object> settings iterated with setProperty() reflection — no allowlist
Sensitive properties exposed: role, isAdmin, status
Difficulty: easy
```

### Java — OrderController (3 vulnerable)

#### 4. Raw JSON binding on order creation (CWE-915)
```
UID: MASSASSIGN_JAVA_ORDER_0
Source: java/src/main/java/com/acme/controllers/OrderController.java:32
Sink: java/src/main/java/com/acme/controllers/OrderController.java:36
Pattern: @RequestBody Map<String, Object> orderData iterated with setProperty() reflection — no allowlist
Sensitive properties exposed: discount, discountPercentage, totalAmount, freeShipping, status
Difficulty: easy
```

#### 5. BeanUtils.copyProperties on order update (CWE-915)
```
UID: MASSASSIGN_JAVA_ORDER_1
Source: java/src/main/java/com/acme/controllers/OrderController.java:57
Sink: java/src/main/java/com/acme/controllers/OrderController.java:60
Pattern: BeanUtils.copyProperties(updates, order) copies ALL matching properties from request to Order entity
Sensitive properties exposed: discount, discountPercentage, totalAmount, freeShipping, status
Difficulty: easy
```

#### 6. Raw JSON binding on coupon application (CWE-915)
```
UID: MASSASSIGN_JAVA_ORDER_2
Source: java/src/main/java/com/acme/controllers/OrderController.java:78
Sink: java/src/main/java/com/acme/controllers/OrderController.java:82
Pattern: @RequestBody Map<String, Object> request iterated with setProperty() reflection — no allowlist
Sensitive properties exposed: discount, discountPercentage, totalAmount, freeShipping
Difficulty: easy
```

### Java — SubscriptionController (3 vulnerable)

#### 7. Raw JSON binding on subscription creation (CWE-915)
```
UID: MASSASSIGN_JAVA_SUB_0
Source: java/src/main/java/com/acme/controllers/SubscriptionController.java:32
Sink: java/src/main/java/com/acme/controllers/SubscriptionController.java:36
Pattern: @RequestBody Map<String, Object> subData iterated with setProperty() reflection — no allowlist
Sensitive properties exposed: planLevel, trialDaysRemaining, creditBalance, discountPercentage, manuallyUpgraded, monthlyAmount
Difficulty: easy
```

#### 8. BeanUtils.copyProperties on subscription update (CWE-915)
```
UID: MASSASSIGN_JAVA_SUB_1
Source: java/src/main/java/com/acme/controllers/SubscriptionController.java:57
Sink: java/src/main/java/com/acme/controllers/SubscriptionController.java:60
Pattern: BeanUtils.copyProperties(updates, subscription) copies ALL matching properties from request to Subscription entity
Sensitive properties exposed: planLevel, trialDaysRemaining, creditBalance, discountPercentage, manuallyUpgraded, monthlyAmount
Difficulty: easy
```

#### 9. Raw JSON binding on promotion application (CWE-915)
```
UID: MASSASSIGN_JAVA_SUB_2
Source: java/src/main/java/com/acme/controllers/SubscriptionController.java:78
Sink: java/src/main/java/com/acme/controllers/SubscriptionController.java:82
Pattern: @RequestBody Map<String, Object> request iterated with setProperty() reflection — no allowlist
Sensitive properties exposed: planLevel, trialDaysRemaining, creditBalance, discountPercentage, manuallyUpgraded
Difficulty: easy
```

### .NET — UsersController (3 vulnerable)

#### 10. Reflection CopyProperties DTO→Entity (CWE-915)
```
UID: MASSASSIGN_DOTNET_USER_0
Source: dotnet/Controllers/UsersController.cs:42
Sink: dotnet/Controllers/UsersController.cs:46
Pattern: CopyProperties(request, user) uses reflection to copy ALL properties from UserProfileUpdateRequest to User entity
Sensitive properties exposed: Role, IsAdmin, Status
Difficulty: easy
```

#### 11. Dynamic JSON binding on registration (CWE-915)
```
UID: MASSASSIGN_DOTNET_USER_1
Source: dotnet/Controllers/UsersController.cs:62
Sink: dotnet/Controllers/UsersController.cs:67
Pattern: [FromBody] dynamic userData iterated with SetProperty() reflection — no allowlist
Sensitive properties exposed: Role, IsAdmin, Status
Difficulty: easy
```

#### 12. Dynamic JSON binding on settings update (CWE-915)
```
UID: MASSASSIGN_DOTNET_USER_2
Source: dotnet/Controllers/UsersController.cs:81
Sink: dotnet/Controllers/UsersController.cs:86
Pattern: [FromBody] dynamic settings iterated with SetProperty() reflection — no allowlist
Sensitive properties exposed: Role, IsAdmin, Status
Difficulty: easy
```

### .NET — OrdersController (3 vulnerable)

#### 13. Dynamic JSON binding on order creation (CWE-915)
```
UID: MASSASSIGN_DOTNET_ORDER_0
Source: dotnet/Controllers/OrdersController.cs:32
Sink: dotnet/Controllers/OrdersController.cs:37
Pattern: [FromBody] dynamic orderData iterated with SetProperty() reflection — no allowlist
Sensitive properties exposed: Discount, DiscountPercentage, TotalAmount, FreeShipping, Status
Difficulty: easy
```

#### 14. Reflection CopyProperties on order update (CWE-915)
```
UID: MASSASSIGN_DOTNET_ORDER_1
Source: dotnet/Controllers/OrdersController.cs:58
Sink: dotnet/Controllers/OrdersController.cs:63
Pattern: SetProperty() reflection copies ALL properties from request to Order entity — no allowlist
Sensitive properties exposed: Discount, DiscountPercentage, TotalAmount, FreeShipping, Status
Difficulty: easy
```

#### 15. Dynamic JSON binding on coupon application (CWE-915)
```
UID: MASSASSIGN_DOTNET_ORDER_2
Source: dotnet/Controllers/OrdersController.cs:81
Sink: dotnet/Controllers/OrdersController.cs:86
Pattern: [FromBody] dynamic request iterated with SetProperty() reflection — no allowlist
Sensitive properties exposed: Discount, DiscountPercentage, TotalAmount, FreeShipping
Difficulty: easy
```

### .NET — SubscriptionsController (3 vulnerable)

#### 16. Dynamic JSON binding on subscription creation (CWE-915)
```
UID: MASSASSIGN_DOTNET_SUB_0
Source: dotnet/Controllers/SubscriptionsController.cs:32
Sink: dotnet/Controllers/SubscriptionsController.cs:37
Pattern: [FromBody] dynamic subData iterated with SetProperty() reflection — no allowlist
Sensitive properties exposed: PlanLevel, TrialDaysRemaining, CreditBalance, DiscountPercentage, ManuallyUpgraded, MonthlyAmount
Difficulty: easy
```

#### 17. Reflection CopyProperties on subscription update (CWE-915)
```
UID: MASSASSIGN_DOTNET_SUB_1
Source: dotnet/Controllers/SubscriptionsController.cs:58
Sink: dotnet/Controllers/SubscriptionsController.cs:63
Pattern: SetProperty() reflection copies ALL properties from request to Subscription entity — no allowlist
Sensitive properties exposed: PlanLevel, TrialDaysRemaining, CreditBalance, DiscountPercentage, ManuallyUpgraded, MonthlyAmount
Difficulty: easy
```

#### 18. Dynamic JSON binding on promotion application (CWE-915)
```
UID: MASSASSIGN_DOTNET_SUB_2
Source: dotnet/Controllers/SubscriptionsController.cs:81
Sink: dotnet/Controllers/SubscriptionsController.cs:86
Pattern: [FromBody] dynamic request iterated with SetProperty() reflection — no allowlist
Sensitive properties exposed: PlanLevel, TrialDaysRemaining, CreditBalance, DiscountPercentage, ManuallyUpgraded
Difficulty: easy
```

### Node.js — users.js (2 vulnerable)

#### 19. Object.assign on profile update (CWE-915)
```
UID: MASSASSIGN_NODE_USER_0
Source: node/src/routes/users.js:30
Sink: node/src/routes/users.js:32
Pattern: Object.assign(user, req.body) spreads ALL request properties onto User object — no allowlist
Sensitive properties exposed: role, isAdmin, status
Difficulty: easy
```

#### 20. Object.assign on registration (CWE-915)
```
UID: MASSASSIGN_NODE_USER_1
Source: node/src/routes/users.js:48
Sink: node/src/routes/users.js:50
Pattern: Object.assign(newUser, req.body) overwrites default role/isAdmin with attacker-controlled values
Sensitive properties exposed: role, isAdmin, status
Difficulty: easy
```

### Node.js — orders.js (2 vulnerable)

#### 21. Object.assign on order creation (CWE-915)
```
UID: MASSASSIGN_NODE_ORDER_0
Source: node/src/routes/orders.js:30
Sink: node/src/routes/orders.js:32
Pattern: Object.assign(newOrder, req.body) overwrites default discount/totalAmount with attacker-controlled values
Sensitive properties exposed: discount, discountPercentage, totalAmount, freeShipping, status
Difficulty: easy
```

#### 22. Object.assign on order update (CWE-915)
```
UID: MASSASSIGN_NODE_ORDER_1
Source: node/src/routes/orders.js:53
Sink: node/src/routes/orders.js:55
Pattern: Object.assign(order, req.body) spreads ALL request properties onto Order object — no allowlist
Sensitive properties exposed: discount, discountPercentage, totalAmount, freeShipping, status
Difficulty: easy
```

### Node.js — subscriptions.js (2 vulnerable)

#### 23. Object.assign on subscription creation (CWE-915)
```
UID: MASSASSIGN_NODE_SUB_0
Source: node/src/routes/subscriptions.js:30
Sink: node/src/routes/subscriptions.js:32
Pattern: Object.assign(newSub, req.body) overwrites default planLevel/trialDaysRemaining with attacker-controlled values
Sensitive properties exposed: planLevel, trialDaysRemaining, creditBalance, discountPercentage, manuallyUpgraded, monthlyAmount
Difficulty: easy
```

#### 24. Object.assign on subscription update (CWE-915)
```
UID: MASSASSIGN_NODE_SUB_1
Source: node/src/routes/subscriptions.js:53
Sink: node/src/routes/subscriptions.js:55
Pattern: Object.assign(subscription, req.body) spreads ALL request properties onto Subscription object — no allowlist
Sensitive properties exposed: planLevel, trialDaysRemaining, creditBalance, discountPercentage, manuallyUpgraded, monthlyAmount
Difficulty: easy
```

### Python — app.py (6 vulnerable)

#### 25. Dict update on profile update (CWE-915)
```
UID: MASSASSIGN_PYTHON_USER_0
Source: python/app.py:43
Sink: python/app.py:45
Pattern: for key, value in request.get_json().items(): user[key] = value — no allowlist
Sensitive properties exposed: role, is_admin, status
Difficulty: easy
```

#### 26. Dict update on registration (CWE-915)
```
UID: MASSASSIGN_PYTHON_USER_1
Source: python/app.py:63
Sink: python/app.py:65
Pattern: for key, value in request.get_json().items(): new_user[key] = value — overwrites default role/is_admin
Sensitive properties exposed: role, is_admin, status
Difficulty: easy
```

#### 27. Dict update on order creation (CWE-915)
```
UID: MASSASSIGN_PYTHON_ORDER_0
Source: python/app.py:123
Sink: python/app.py:125
Pattern: for key, value in request.get_json().items(): new_order[key] = value — overwrites default discount/total_amount
Sensitive properties exposed: discount, discount_percentage, total_amount, free_shipping, status
Difficulty: easy
```

#### 28. Dict update on order update (CWE-915)
```
UID: MASSASSIGN_PYTHON_ORDER_1
Source: python/app.py:147
Sink: python/app.py:149
Pattern: for key, value in request.get_json().items(): order[key] = value — no allowlist
Sensitive properties exposed: discount, discount_percentage, total_amount, free_shipping, status
Difficulty: easy
```

#### 29. Dict update on subscription creation (CWE-915)
```
UID: MASSASSIGN_PYTHON_SUB_0
Source: python/app.py:207
Sink: python/app.py:209
Pattern: for key, value in request.get_json().items(): new_sub[key] = value — overwrites default planLevel/trialDaysRemaining
Sensitive properties exposed: plan_level, trial_days_remaining, credit_balance, discount_percentage, manually_upgraded, monthly_amount
Difficulty: easy
```

#### 30. Dict update on subscription update (CWE-915)
```
UID: MASSASSIGN_PYTHON_SUB_1
Source: python/app.py:231
Sink: python/app.py:233
Pattern: for key, value in request.get_json().items(): subscription[key] = value — no allowlist
Sensitive properties exposed: plan_level, trial_days_remaining, credit_balance, discount_percentage, manually_upgraded, monthly_amount
Difficulty: easy
```

---

## mass-assignment-testbed honeypots (10)

### HP-20: DTO with explicit property mapping — User profile (NOT exploitable)
```
UID: HONEY_MASSASSIGN_0
File: java/src/main/java/com/acme/controllers/UserController.java (updateProfileSafe method)
      dotnet/Controllers/UsersController.cs (UpdateProfileSafe method)
Pattern: UserProfileUpdateRequest DTO only contains username, email, displayName, phone, avatarUrl
Why safe: Sensitive properties (role, isAdmin, status) are NOT present in the DTO class definition.
Even if BeanUtils.copyProperties or reflection is used, there's nothing to copy because the DTO lacks those fields.
Manual mapping only copies allowed properties from DTO to entity.
Expected FP: CWE-915 (Mass Assignment) — tool may flag the copy operation without recognizing DTO field exclusion
```

### HP-21: DTO with explicit property mapping — Order creation (NOT exploitable)
```
UID: HONEY_MASSASSIGN_1
File: java/src/main/java/com/acme/controllers/OrderController.java (createOrderSafe method)
      dotnet/Controllers/OrdersController.cs (CreateOrderSafe method)
Pattern: Explicit allowlist of safe properties (userId, shippingAddressLine1, city, state, zipCode)
Why safe: Discount, totalAmount, freeShipping are calculated server-side based on business logic.
Client-provided pricing values are never accepted — only shipping address and user reference.
Expected FP: CWE-915 (Mass Assignment) — tool may flag setProperty calls without recognizing allowlist filtering
```

### HP-22: DTO with explicit property mapping — Subscription preferences (NOT exploitable)
```
UID: HONEY_MASSASSIGN_2
File: java/src/main/java/com/acme/controllers/SubscriptionController.java (updateSubscriptionPreferences method)
      dotnet/Controllers/SubscriptionsController.cs (UpdateSubscriptionPreferences method)
Pattern: Explicit allowlist of safe properties (autoRenew only)
Why safe: PlanLevel, trialDaysRemaining, creditBalance are NOT settable through this endpoint.
Plan upgrades go through a separate flow with payment processing; credits applied only by admin endpoints.
Expected FP: CWE-915 (Mass Assignment) — tool may flag setProperty calls without recognizing allowlist filtering
```

### HP-23: Node.js allowlist pattern — User profile (NOT exploitable)
```
UID: HONEY_MASSASSIGN_3
File: node/src/routes/users.js (PUT /users/:id/profile/safe)
Pattern: const allowedFields = ['username', 'email', 'displayName', 'phone', 'avatarUrl'] with for-loop filtering
Why safe: Only properties in the allowlist are copied from req.body to user object.
Sensitive fields (role, isAdmin, status) are never assigned because they're not in allowedFields.
Expected FP: CWE-915 (Mass Assignment) — tool may flag Object.assign-like patterns without recognizing allowlist
```

### HP-24: Node.js allowlist pattern — Order creation (NOT exploitable)
```
UID: HONEY_MASSASSIGN_4
File: node/src/routes/orders.js (POST /orders/safe)
Pattern: const allowedFields = ['userId', 'shippingAddressLine1', ...] with for-loop filtering
Why safe: Only shipping address and user reference are accepted from client.
Discount, totalAmount, freeShipping are calculated server-side — never trusted from client input.
Expected FP: CWE-915 (Mass Assignment) — tool may flag property assignment without recognizing allowlist
```

### HP-25: Node.js allowlist pattern — Subscription preferences (NOT exploitable)
```
UID: HONEY_MASSASSIGN_5
File: node/src/routes/subscriptions.js (PUT /subscriptions/:id/preferences)
Pattern: const allowedFields = ['autoRenew'] with for-loop filtering
Why safe: Only autoRenew preference is settable. PlanLevel, trialDaysRemaining, creditBalance excluded.
Expected FP: CWE-915 (Mass Assignment) — tool may flag property assignment without recognizing allowlist
```

### HP-26: Python allowlist pattern — User profile (NOT exploitable)
```
UID: HONEY_MASSASSIGN_6
File: python/app.py (PUT /api/users/<int:user_id>/profile/safe)
Pattern: allowed_fields = ['username', 'email', 'display_name', 'phone', 'avatar_url'] with for-loop filtering
Why safe: Only properties in the allowlist are copied from request JSON to user dict.
Sensitive fields (role, is_admin, status) are never assigned because they're not in allowed_fields.
Expected FP: CWE-915 (Mass Assignment) — tool may flag dict[key] = value without recognizing allowlist
```

### HP-27: Python allowlist pattern — Order creation (NOT exploitable)
```
UID: HONEY_MASSASSIGN_7
File: python/app.py (POST /api/orders/safe)
Pattern: allowed_fields = ['user_id', 'shipping_address_line1', ...] with for-loop filtering
Why safe: Only shipping address and user reference are accepted from client.
Discount, total_amount, free_shipping are calculated server-side — never trusted from client input.
Expected FP: CWE-915 (Mass Assignment) — tool may flag dict[key] = value without recognizing allowlist
```

### HP-28: Python allowlist pattern — Subscription preferences (NOT exploitable)
```
UID: HONEY_MASSASSIGN_8
File: python/app.py (PUT /api/subscriptions/<int:sub_id>/preferences)
Pattern: allowed_fields = ['auto_renew'] with for-loop filtering
Why safe: Only autoRenew preference is settable. planLevel, trialDaysRemaining, creditBalance excluded.
Expected FP: CWE-915 (Mass Assignment) — tool may flag dict[key] = value without recognizing allowlist
```

### HP-29: .NET DTO validation with data annotations (NOT exploitable)
```
UID: HONEY_MASSASSIGN_9
File: dotnet/DTOs/UserProfileUpdateRequest.cs + dotnet/Controllers/UsersController.cs (UpdateProfileSafe)
Pattern: UserProfileUpdateRequest DTO has [Required], [StringLength], [EmailAddress] validation attributes.
Sensitive properties (Role, IsAdmin, Status) are intentionally absent from the DTO class.
Why safe: Model binding only populates properties that exist on the DTO type.
Even with automatic model binding, Role/IsAdmin/Status cannot be set because they're not DTO members.
Manual mapping in UpdateProfileSafe explicitly copies only Username and Email to the User entity.
Expected FP: CWE-915 (Mass Assignment) — tool may flag model binding or reflection without recognizing DTO field exclusion
```

---

## Updated Summary

| Testbed | True Vulnerabilities | Honeypots (Expected FPs) |
|---------|---------------------|--------------------------|
| secret-testbed | 11 SAST + ~23 secrets | 0 |
| reflection-testbed | 8 | 4 |
| access-control-testbed | 14 | 4 |
| database-testbed | 8 | 3 |
| cloud-iac-testbed | 10 IaC | 4 |
| web-vulns-testbed | 18 | 5 |
| mass-assignment-testbed | 30 CWE-915 | 10 |
| **Total** | **~122-123** | **30** |

---

# LICENSE: License Analysis Findings (SCA Policy)

These findings are for the `license-testbed` repository. Unlike SAST findings (file:line), license
findings are evaluated from CycloneDX SBOM output — the tool scans the dependency tree and reports
each dependency's license identifier, policy classification, and risk severity.

Scoring methodology: see `SCORING_RUBRIC.md` §6 and `CYCLONEDX_WORKSHEET.md`.

---

## Expected CycloneDX SBOM Components (30+)

The tool should produce a CycloneDX 1.6 BOM with at minimum these components listed. All license IDs must be valid SPDX identifiers.

### Direct Dependencies — Real npm Packages

| UID | Package | Version | Expected License (SPDX) | Category | Risk |
|-----|---------|---------|------------------------|----------|------|
| LICENSE_COMP_EXPRESS | express | ^4.18.2 | MIT | permissive | None |
| LICENSE_COMP_LODASH | lodash | ^4.17.21 | MIT | permissive | None |
| LICENSE_COMP_RXJS | rxjs | ^7.8.1 | Apache-2.0 | permissive | None |
| LICENSE_COMP_SEMVER | semver | ^7.6.0 | ISC | permissive | None |
| LICENSE_COMP_SOURCEMAP | source-map | ^0.7.4 | BSD-3-Clause | permissive | None |
| LICENSE_COMP_SPDXIDS | spdx-license-ids | ^3.0.16 | CC0-1.0 | public-domain | None |
| LICENSE_COMP_NODEFORGE | node-forge | ^1.3.1 | (BSD-3-Clause OR GPL-2.0) | dual-license | Edge Case |
| LICENSE_COMP_FFMPEG | ffmpeg-static | ^5.1.0 | GPL-3.0-or-later | **strong-copyleft** | **High** |
| LICENSE_COMP_SHARP | sharp | ^0.35.0 | Apache-2.0 | permissive | Low |
| LICENSE_COMP_MYGPL | my-gpl-package | ^1.0.0 | GPL-2.0 | **strong-copyleft** | **High** |
| LICENSE_COMP_EXTJS | extjs-gpl | ^6.2.0 | GPL-3.0 | dead-code-edge | Low |

### Direct Dependencies — Workspace Packages (@license-testbed/*)

| UID | Package | Version | Expected License (SPDX) | Category | Risk |
|-----|---------|---------|------------------------|----------|------|
| LICENSE_COMP_AGPL | @license-testbed/agpl-pkg | 1.0.0 | AGPL-3.0-only | **network-copyleft** | **Critical** |
| LICENSE_COMP_LGPL | @license-testbed/lgpl-pkg | 1.0.0 | LGPL-2.1-only | weak-copyleft | Medium |
| LICENSE_COMP_MPL | @license-testbed/mpl-pkg | 1.0.0 | MPL-2.0 | weak-copyleft | Low-Med |
| LICENSE_COMP_BUSL | @license-testbed/busl-pkg | 1.0.0 | BUSL-1.1 | **non-osi-commercial** | **High** |
| LICENSE_COMP_SSPL | @license-testbed/sspl-pkg | 1.0.0 | SSPL-1.0 | **non-osi-commercial** | **High** |
| LICENSE_COMP_WTFPL | @license-testbed/wtfpl-pkg | 1.0.0 | WTFPL | permissive | None |
| LICENSE_COMP_UNLICENSE | @license-testbed/unlicense-pkg | 1.0.0 | Unlicense | public-domain | None |
| LICENSE_COMP_BSD2 | @license-testbed/bsd2-pkg | 1.0.0 | BSD-2-Clause | permissive | None |
| LICENSE_COMP_BSD3 | @license-testbed/bsd3-pkg | 1.0.0 | BSD-3-Clause | permissive | None |
| LICENSE_COMP_0BSD | @license-testbed/zerobsd-pkg | 1.0.0 | 0BSD | permissive | None |
| LICENSE_COMP_APACHE2 | @license-testbed/apache2-pkg | 1.0.0 | Apache-2.0 | permissive | None |
| LICENSE_COMP_MIT | @license-testbed/mit-pkg | 1.0.0 | MIT | permissive | None |
| LICENSE_COMP_ISC | @license-testbed/isc-pkg | 1.0.0 | ISC | permissive | None |
| LICENSE_COMP_DEVONLYGPL | @license-testbed/dev-only-gpl | 1.0.0 | GPL-3.0-only | **strong-copyleft** | Low (**dev-only**) |

### Transitive Dependencies (Key Items)

| UID | Package | Via | Expected License (SPDX) | Category | Risk |
|-----|---------|-----|------------------------|----------|------|
| LICENSE_COMP_LIBVIPS | @img/sharp-libvips-linux-x64 | sharp | LGPL-3.0-or-later | **weak-copyleft-transitive** | Medium |

### Dev Dependencies (Permissive Baseline)

| UID | Package | License | Notes |
|-----|---------|---------|-------|
| LICENSE_COMP_MOCHA | mocha | MIT | test runner |
| LICENSE_COMP_CHAI | chai | MIT | assertion lib |
| LICENSE_COMP_TYPESCRIPT | typescript | Apache-2.0 | build tool |
| LICENSE_COMP_TSLIB | tslib | 0BSD | build tool |

---

## Scoring Guide for CycloneDX Worksheet

When evaluating a vendor's CycloneDX output, verify:

1. **Component completeness** — all direct deps listed (30+ components minimum)
2. **License field type** — `license.id` (SPDX ID) vs `license.name` (free text). Prefer `id`.
3. **Dual-license handling** — `node-forge` must use `(BSD-3-Clause OR GPL-2.0)` expression, not a single choice
4. **Transitive inclusion** — `@img/sharp-libvips-*` present with LGPL-3.0-or-later
5. **Dev tagging** — `@license-testbed/dev-only-gpl` and mocha/chai/typescript/tslib tagged as dev
6. **Evidence accuracy** — license info should cite the source (package.json, license file, scan match)

Key items that are **critical to catch** for the scorecard (from SCORING_RUBRIC §6b):
- GPL-3.0 on `ffmpeg-static` (production strong copyleft)
- AGPL-3.0 on `@license-testbed/agpl-pkg` (network copyleft)
- BUSL-1.1 / SSPL-1.0 on `busl-pkg` / `sspl-pkg` (non-OSI, commercially-restrictive)
- Dev-vs-production differentiation for GPL-3.0 (dev-only-gpl < ffmpeg-static)

---

## License Testbed Update Summary

| Testbed | True Vulnerabilities | Honeypots (Expected FPs) |
|---------|---------------------|--------------------------|
| secret-testbed | 11 SAST + ~23 secrets | 0 |
| reflection-testbed | 8 | 4 |
| access-control-testbed | 14 | 4 |
| database-testbed | 8 | 3 |
| cloud-iac-testbed | 10 IaC | 4 |
| web-vulns-testbed | 18 | 5 |
| mass-assignment-testbed | 30 CWE-915 | 10 |
| license-testbed | 11 license findings | 0 (policy test) |
| **Total** | **~133-134** | **30** |
