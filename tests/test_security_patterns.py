import pytest
from pathlib import Path
from helpfulgremlin.detector import Detector

@pytest.fixture
def detector():
    return Detector()

class TestSecurityPatterns:
    
    def test_unsafe_execution_python(self, detector):
        line = "eval('print(1)')"
        match = detector.check_line(line, Path("script.py"))
        assert match is not None
        assert match.name == "Unsafe Execution (eval)"
        
    def test_unsafe_execution_python_ignored_in_txt(self, detector):
        line = "eval('print(1)')"
        match = detector.check_line(line, Path("readme.txt"))
        assert match is None

    def test_unsafe_deserialization(self, detector):
        line = "data = pickle.load(f)"
        match = detector.check_line(line, Path("model.py"))
        assert match is not None
        assert match.name == "Unsafe Deserialization"

    def test_insecure_ssl(self, detector):
        line = "requests.get(url, verify=False)"
        match = detector.check_line(line, Path("api.py"))
        assert match is not None
        assert match.name == "Insecure SSL (verify=False)"

    def test_weak_hashing(self, detector):
        line = "hashlib.md5(b'123')"
        match = detector.check_line(line, Path("auth.py"))
        assert match is not None
        assert match.name == "Weak Hashing (MD5)"

    def test_binding_all_interfaces(self, detector):
        line = "app.run(host='0.0.0.0')"
        match = detector.check_line(line, Path("server.py"))
        assert match is not None
        assert match.name == "Binding to All Interfaces"

    def test_aws_key_detection_still_works(self, detector):
        # Regression test for existing patterns
        line = "AKIA1234567890123456"
        match = detector.check_line(line, Path("config.py"))
        assert match is not None
        assert match.name == "AWS Access Key"
        
    def test_aws_key_detection_works_in_txt(self, detector):
        # AWS Key should be detected in ALL files (no 'files' restriction in YAML)
        line = "AKIA1234567890123456"
        match = detector.check_line(line, Path("notes.txt"))
        assert match is not None
        assert match.name == "AWS Access Key"

    def test_google_cloud_service_account(self, detector):
        line = '"type": "service_account"'
        match = detector.check_line(line, Path("credentials.json"))
        assert match is not None
        assert match.name == "Google Cloud Service Account"

    def test_database_uri(self, detector):
        line = "url = 'postgres://admin:secret123@localhost:5432/mydb'"
        match = detector.check_line(line, Path("config.py"))
        assert match is not None
        assert match.name == "PostgreSQL / MySQL URI"

    def test_mongodb_uri(self, detector):
        line = "MONGO_URI=mongodb+srv://admin:pass@cluster0.abc.mongodb.net"
        match = detector.check_line(line, Path(".env"))
        assert match is not None
        assert match.name == "MongoDB URI"

    def test_redis_uri(self, detector):
        line = "redis://default:redispw@localhost:6379"
        match = detector.check_line(line, Path("cache.py"))
        assert match is not None
        assert match.name == "Redis URI"

    def test_ssh_private_key(self, detector):
        line = "-----BEGIN OPENSSH PRIVATE KEY-----"
        match = detector.check_line(line, Path("id_rsa"))
        assert match is not None
        assert match.name == "Generic Private Key"

    def test_jwt_token(self, detector):
        line = "const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';"
        match = detector.check_line(line, Path("auth.js"))
        assert match is not None
        assert match.name == "JWT Token"

    def test_command_injection(self, detector):
        line = "subprocess.Popen(cmd, shell=True)"
        match = detector.check_line(line, Path("script.py"))
        assert match is not None
        assert match.name == "Command Injection Risk (shell=True)"

    def test_flask_debug_mode(self, detector):
        line = "app.run(host='0.0.0.0', debug=True)"
        match = detector.check_line(line, Path("app.py"))
        assert match is not None
        # Could match binding all interfaces or flask debug, but let's check basic pattern
        line2 = "DEBUG = True"
        match2 = detector.check_line(line2, Path("settings.py"))
        assert match2 is not None
        assert match2.name == "Flask/Django Debug Mode"

    def test_node_tls_reject(self, detector):
        line = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"
        match = detector.check_line(line, Path("server.js"))
        assert match is not None
        assert match.name == "Disabled Node TLS"

    def test_react_dangerously_set_inner_html(self, detector):
        line = "<div dangerouslySetInnerHTML={{ __html: data }} />"
        match = detector.check_line(line, Path("component.tsx"))
        assert match is not None
        assert match.name == "React dangerouslySetInnerHTML"

    def test_docker_root_user(self, detector):
        line = "USER root"
        match = detector.check_line(line, Path("Dockerfile"))
        assert match is not None
        assert match.name == "Docker Root User"

    def test_sql_injection_fstring(self, detector):
        line = "query = f'SELECT * FROM users WHERE id = {user_id}'"
        match = detector.check_line(line, Path("db.py"))
        assert match is not None
        assert match.name == "SQL Injection Risk (f-string/template)"
