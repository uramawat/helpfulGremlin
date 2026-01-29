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
