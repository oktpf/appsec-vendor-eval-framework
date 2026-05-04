# Answer Key - Advanced Security Benchmark

## SAST Findings (Dataflow)

### 1. SQL Injection (CWE-89)
UID: CWE-89_0
Source: src/app/apis.py:99
 -> src/app/apis.py:100
 -> src/app/db_utils.py:12
 -> src/app/db_utils.py:15
Sink: src/app/db_utils.py:16

### 2. Command Injection (CWE-78)
UID: CWE-78_0
Source: src/app/apis.py:105
 -> src/app/apis.py:106
 -> src/app/db_utils.py:19
 -> src/app/db_utils.py:20
Sink: src/app/db_utils.py:21

### 3. IDOR / Missing Auth (CWE-639)
UID: CWE-639_0
Source: src/app/apis.py:99
Sink: src/app/apis.py:100

### 4. Second-Order SQL Injection (CWE-89)
UID: CWE-89_1
Source: src/app/db_utils.py:26 (via Database theme_path)
 -> src/app/db_utils.py:29
Sink: src/app/db_utils.py:30

### 5. Second-Order Path Traversal (CWE-73)
UID: CWE-73_0
Source: src/app/db_utils.py:26 (via Database theme_path)
 -> src/app/db_utils.py:29
Sink: src/app/db_utils.py:31

### 6. SSRF (CWE-918)
UID: CWE-918_0
Source: src/app/apis.py:117
Sink: src/app/apis.py:118

### 7. Zip Slip (CWE-22)
UID: CWE-22_0
Source: src/app/apis.py:125
 -> src/app/apis.py:128
 -> src/app/db_utils.py:35
 -> src/app/db_utils.py:37
Sink: src/app/db_utils.py:38

### 8. XXE (CWE-611)
UID: CWE-611_0
Source: src/app/apis.py:133
 -> src/app/apis.py:134
 -> src/app/db_utils.py:40
Sink: src/app/db_utils.py:42

### 9. Insecure Deserialization (CWE-502)
UID: CWE-502_0
Source: src/app/apis.py:139
 -> src/app/apis.py:140
 -> src/app/db_utils.py:45
Sink: src/app/db_utils.py:47

### 10. Lambda Command Injection (CWE-78)
UID: CWE-78_1
Source: aws_lambda/s3_processor.py:10
 -> aws_lambda/s3_processor.py:15
Sink: aws_lambda/s3_processor.py:16

### 11. Lambda Path Traversal (CWE-73)
UID: CWE-73_1
Source: aws_lambda/s3_processor.py:10
 -> aws_lambda/s3_processor.py:12
Sink: aws_lambda/s3_processor.py:13

## Hardcoded Credentials
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
