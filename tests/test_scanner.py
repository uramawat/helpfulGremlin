import pytest
from pathlib import Path
from helpfulgremlin.scanner import Scanner

@pytest.fixture
def temp_repo(tmp_path):
    """Creates a temporary repo structure."""
    
    # Create valid files
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')")
    (tmp_path / "README.md").write_text("# Hello")
    
    # Create ignored files
    (tmp_path / ".gitignore").write_text("ignored.txt\nnode_modules/")
    (tmp_path / "ignored.txt").write_text("secrets")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}")
    
    # Create binary file
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")

    # Create lock file
    (tmp_path / "poetry.lock").write_text("HASH123...")
    
    return tmp_path

def test_scanner_traversal(temp_repo):
    """Test that scanner finds valid files and skips ignored ones."""
    scanner = Scanner(temp_repo)
    found_files = set(str(p.relative_to(temp_repo)) for p in scanner.walk())
    
    assert "src/main.py" in found_files
    assert "README.md" in found_files
    
    # Ignored by .gitignore
    assert "ignored.txt" not in found_files
    assert "node_modules/package.json" not in found_files
    
    # Ignored by default (binary)
    assert "binary.bin" not in found_files
    
    # Ignored by default (lock)
    assert "poetry.lock" not in found_files

def test_single_file_scan(temp_repo):
    """Test scanning a single file directly."""
    target_file = temp_repo / "src" / "main.py"
    scanner = Scanner(target_file)
    found = list(scanner.walk())
    assert len(found) == 1
    assert found[0] == target_file

def test_binary_detection(temp_repo):
    """Test inner binary detection logic."""
    scanner = Scanner(temp_repo)
    assert scanner.is_binary(temp_repo / "binary.bin")
    assert not scanner.is_binary(temp_repo / "src" / "main.py")
