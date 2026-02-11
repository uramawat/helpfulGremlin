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
