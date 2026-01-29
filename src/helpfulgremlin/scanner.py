import os
import pathspec
from typing import Iterator, List
from pathlib import Path

class Scanner:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.ignore_spec = self._load_gitignore()

    def _load_gitignore(self) -> pathspec.PathSpec:
        gitignore_path = self.root_dir / ".gitignore"
        lines = []
        
        # Always ignore .git directory
        lines.append(".git/")
        lines.append(".venv/")
        lines.append("venv/")
        lines.append("env/")
        lines.append(".env/")
        lines.append("__pycache__/")
        lines.append("*.pyc")
        lines.append("node_modules/")
        lines.append("*.lock")
        lines.append("*-lock.json")

        if gitignore_path.exists():
            with open(gitignore_path, "r") as f:
                lines.extend(f.readlines())
        
        return pathspec.PathSpec.from_lines("gitignore", lines)

    def is_binary(self, path: Path) -> bool:
        """
        Simple heuristic to check if a file is binary.
        Reads the first 1024 bytes and checks for null bytes.
        """
        try:
            with open(path, "rb") as f:
                chunk = f.read(1024)
                if b"\0" in chunk:
                    return True
                # If we can't decode it as utf-8, it's likely binary (or at least not text we want to scan)
                try:
                    chunk.decode("utf-8")
                except UnicodeDecodeError:
                    return True
        except Exception:
            return True
        return False

    def walk(self) -> Iterator[Path]:
        """
        Yields paths to files that should be scanned.
        Respects .gitignore.
        """
        # If input path is a file, verify and yield it directly
        if self.root_dir.is_file():
            if not self.is_binary(self.root_dir):
                yield self.root_dir
            return

        for root, dirs, files in os.walk(self.root_dir):
            # Calculate relative path for matching
            rel_root = os.path.relpath(root, self.root_dir)
            if rel_root == ".":
                rel_root = ""
                
            # Filter directories in-place to prevent recursion into ignored dirs
            # We must iterate over a copy of the list to modify it
            dirs[:] = [
                d for d in dirs 
                if not self.ignore_spec.match_file(os.path.join(rel_root, d))
            ]

            for file in files:
                rel_path = os.path.join(rel_root, file)
                if self.ignore_spec.match_file(rel_path):
                    continue
                
                full_path = Path(root) / file
                
                # Large Scale Optimization: Skip files > 5MB
                try:
                    if full_path.stat().st_size > 5 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                    
                if not self.is_binary(full_path):
                    yield full_path
