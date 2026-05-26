import pytest
from typer.testing import CliRunner
from helpfulgremlin.main import app

runner = CliRunner()

def test_clean_scan(tmp_path):
    """Test scanning a clean directory."""
    (tmp_path / "clean.py").write_text("print('hello world')")
    result = runner.invoke(app, [str(tmp_path)])
    
    assert result.exit_code == 0, f"STDOUT: {result.stdout}"
    assert "No issues found" in result.stdout

def test_dirty_scan(tmp_path):
    """Test scanning a directory with secrets."""
    (tmp_path / "dirty.py").write_text("key = 'AKIA0000000000000000'")
    result = runner.invoke(app, [str(tmp_path)])
    
    assert result.exit_code == 1, f"STDOUT: {result.stdout}"
    assert "Found 1 Potential Issues" in result.stdout
    assert "AWS Access Key" in result.stdout

def test_dirty_scan_ignored(tmp_path):
    """Test that ignored secrets do not trigger a fail."""
    (tmp_path / ".gitignore").write_text("dirty.py")
    (tmp_path / "dirty.py").write_text("key = 'AKIA0000000000000000'")
    
    result = runner.invoke(app, [str(tmp_path)])
    
    assert result.exit_code == 0
    assert "No issues found" in result.stdout

def test_verbose_flag(tmp_path):
    """Test verbose output."""
    (tmp_path / "test.py").write_text("print('hi')")
    result = runner.invoke(app, [str(tmp_path), "--verbose"])
    
    assert result.exit_code == 0
    assert "Scanned" in result.stdout
    assert "test.py" in result.stdout

def test_sensitive_file_presence_warning(tmp_path):
    """Test that dangerous local config files create presence warnings."""
    (tmp_path / ".env.local").write_text("PLACEHOLDER=example")
    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 1, f"STDOUT: {result.stdout}"
    assert "Sensitive File Present" in result.stdout
    assert "credential-file" in result.stdout

def test_output_includes_severity_and_category(tmp_path):
    """Test that the report exposes normalized finding metadata."""
    (tmp_path / "dirty.py").write_text("key = 'AKIA0000000000000000'")
    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 1, f"STDOUT: {result.stdout}"
    assert "Severity" in result.stdout
    assert "Category" in result.stdout
    assert "secret" in result.stdout
