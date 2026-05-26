import pytest
from pathlib import Path
from helpfulgremlin.detector import Detector

@pytest.fixture
def detector():
    return Detector()

def test_load_patterns(detector):
    """Ensure patterns are loaded from YAML."""
    assert len(detector.patterns) > 0
    names = [p.name for p in detector.patterns]
    assert "AWS Access Key" in names
    assert "OpenAI API Key" in names
    assert "Gemini / Google Cloud API Key" in names

@pytest.mark.parametrize("secret, pattern_name", [
    ("AKIA0000000000000000", "AWS Access Key"),
    (f"sk-proj-{'0'*32}", "OpenAI API Key"),
    (f"sk_live_{'0'*24}", "Stripe Secret Key"),
    (f"xoxb-{'0'*12}-{'0'*12}-{'0'*12}-{'0'*32}", "Slack Token"),
    ("-----BEGIN RSA PRIVATE KEY-----", "Generic Private Key"),
    (f"ghp_{'0'*36}", "GitHub Token"),
    ("AIzaSyD-0000000000000000000000000000000", "Gemini / Google Cloud API Key"),
    (f"sk-ant-api03-{'0'*30}", "Anthropic API Key"),
])
def test_regex_detection(detector, secret, pattern_name):
    """Test that specific secrets set off the correct regex."""
    match = detector.check_line(f"key = '{secret}'")
    assert match is not None
    assert match.name == pattern_name

def test_entropy_calculation(detector):
    """Test Shannon entropy math."""
    # Low entropy: repeated chars
    assert detector.calculate_shannon_entropy("Bk00...") < 3.0
    # High entropy: random chars
    # "7f8c9d0a1b2c3d4e5f6g7h8i9j0k1l2"
    assert detector.calculate_shannon_entropy("7f8c9d0a1b2c3d4e5f6g7h8i9j0k1l2") > 4.0

def test_high_entropy_detection(detector):
    """Test that high entropy strings are flagged."""
    # A random string with wide charset
    high_ent_secret = "wsx78ujmko9lzx57483920sjid892301293810293!@#"  
    match = detector.check_line(f"secret = '{high_ent_secret}'")
    
    assert match is not None
    assert match.name == "High Entropy String"
    assert "High entropy string detected" in match.description

def test_entropy_false_positives(detector):
    """Test that common low-entropy/structured strings are NOT flagged."""
    safes = [
        "http://example.com/some/long/path/uuid/structure",
        "this_is_a_very_long_variable_name_but_low_entropy",
        "/usr/local/bin/python3.9",
        "c8646b83-a988-4443-9828-569203648588", # UUIDs are filtered
    ]
    for safe in safes:
        match = detector.check_line(f"var = '{safe}'")
        if match:
             print(f"Failed on: {safe} matched {match.name}")
        assert match is None

def test_bearer_header_detection(detector):
    match = detector.check_line("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456")
    assert match is not None
    assert match.name == "Bearer Authorization Header"
    assert match.category == "secret"

def test_npm_token_detection(detector):
    match = detector.check_line("//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz123456")
    assert match is not None
    assert match.name == "npm Token"

def test_pypi_token_detection(detector):
    match = detector.check_line("password = pypi-abcdefghijklmnopqrstuvwxyz123456")
    assert match is not None
    assert match.name == "PyPI Token"

def test_agent_config_hardcoded_env_value(detector):
    text = '{"mcpServers":{"github":{"env":{"GITHUB_TOKEN":"plain-secret-value"}}}}'
    findings = detector.scan_file(Path(".mcp.json"), text)

    assert any(f.name == "Hardcoded Agent Config Secret" for f in findings)
    assert any(f.name == "Sensitive File Present" for f in findings)

def test_agent_config_placeholder_is_not_secret(detector):
    text = '{"mcpServers":{"github":{"env":{"GITHUB_TOKEN":"${GITHUB_TOKEN}"}}}}'
    findings = detector.scan_file(Path(".mcp.json"), text)

    assert [f.name for f in findings] == ["Sensitive File Present"]

def test_invalid_agent_config_falls_back_to_line_scan(detector):
    text = '{"mcpServers": {"github": {"env": {"OPENAI_API_KEY": "sk-proj-00000000000000000000000000000000"'
    findings = detector.scan_file(Path(".mcp.json"), text)

    assert any(f.name == "Unreadable Agent Config" for f in findings)
    assert any(f.name == "OpenAI API Key" for f in findings)
