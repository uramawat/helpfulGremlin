import json
import re
from dataclasses import dataclass
from typing import Any, List, Optional
from pathlib import Path

import yaml
import importlib.resources

@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    description: str
    files: Optional[List[str]] = None
    category: str = "secret"
    severity: str = "high"
    remediation: Optional[str] = None

@dataclass
class Finding:
    file_path: Path
    line_no: Optional[int]
    name: str
    category: str
    severity: str
    snippet: str
    remediation: str
    description: str

class Detector:
    AGENT_CONFIG_FILES = {
        ".mcp.json",
        "mcp.json",
        "claude_desktop_config.json",
    }
    AGENT_CONFIG_PATHS = {
        ".claude/settings.json",
        ".cursor/mcp.json",
    }
    SENSITIVE_FILE_NAMES = {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".mcp.json",
        "mcp.json",
        "claude_desktop_config.json",
        ".claude.json",
        "credentials.json",
        "service-account.json",
    }
    SENSITIVE_PATH_SUFFIXES = {
        ".claude/settings.json",
        ".cursor/mcp.json",
        "gcloud/application_default_credentials.json",
    }
    SENSITIVE_KEYWORDS = (
        "api_key",
        "apikey",
        "auth",
        "bearer",
        "client_secret",
        "credential",
        "key",
        "password",
        "secret",
        "token",
    )
    PLACEHOLDER_RE = re.compile(r"^\$[A-Z_][A-Z0-9_]*$|^\$\{[A-Z_][A-Z0-9_]*\}$|^%[A-Z_][A-Z0-9_]*%$")

    def __init__(self):
        self.patterns: List[SecretPattern] = []
        self._load_patterns()

    def _load_patterns(self):
        try:
            # Load from the package using importlib.resources
            # We assume patterns.yaml is in the same package as this module (helpfulgremlin)
            # In Python 3.9+ we can use files() but keeping it simple for now or using the open_text equivalent
            # For 3.13 (current env), files() is standard.
            
            # Using importlib.resources.files
            package_files = importlib.resources.files("helpfulgremlin")
            yaml_path = package_files.joinpath("patterns.yaml")
            
            if yaml_path.is_file():
                with yaml_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    for item in data.get("patterns", []):
                        try:
                            self.patterns.append(SecretPattern(
                                name=item["name"],
                                pattern=re.compile(item["pattern"]),
                                description=item["description"],
                                files=item.get("files"),
                                category=item.get("category", self._default_category(item["name"])),
                                severity=item.get("severity", self._default_severity(item["name"])),
                                remediation=item.get("remediation"),
                            ))
                        except re.error as e:
                            print(f"Error compiling regex for {item['name']}: {e}")
            else:
                 print("Warning: patterns.yaml not found in package.")

        except Exception as e:
            print(f"Error loading patterns: {e}")
            # Fallback to critical defaults if YAML fails? 
            # For now, let's trust the YAML exists since we just created it.


    def calculate_shannon_entropy(self, data: str) -> float:
        import math
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = data.count(x) / len(data)
            entropy += - p_x * math.log2(p_x)
        return entropy

    def check_line(self, line: str, file_path: Path = None, line_no: Optional[int] = None) -> Optional[Finding]:
        """
        Checks a single line against all patterns.
        Returns the first matching Finding, or None.
        """
        extension = file_path.suffix if file_path else ""

        # 1. Regex Checks
        for pat in self.patterns:
            # Context-Aware Check: Skip if pattern is not relevant for this file type
            if pat.files and extension not in pat.files:
                continue

            if pat.pattern.search(line):
                return self._finding_from_pattern(pat, line, file_path, line_no)
        
        # 2. Entropy Checks (Optional, can be computationally expensive)
        # Simple heuristic: split by space, quotes, assignment, colons
        tokens = re.split(r'[\s"\'=,;()<>\[\]{}:.]', line)
        for token in tokens:
            if len(token) > 12 and len(token) < 128:  # Reasonable length for a secret
                # Filter out likely non-secrets (URLs, Paths, UUIDs)
                if "/" in token or "\\" in token or token.startswith("http"):
                    continue
                
                entropy = self.calculate_shannon_entropy(token)
                if entropy > 4.2:
                    pattern = SecretPattern(
                        name="High Entropy String",
                        pattern=re.compile(re.escape(token)),
                        description=f"High entropy string detected ({entropy:.2f} bits). Potential secret or password.",
                        category="entropy",
                        severity="medium",
                        remediation="Verify if secret. If yes, move to env vars.",
                    )
                    return self._finding_from_pattern(pattern, line, file_path, line_no)
        return None

    def scan_file(self, file_path: Path, text: str) -> List[Finding]:
        findings: List[Finding] = []
        presence = self._presence_warning(file_path)
        if presence:
            findings.append(presence)

        if self._is_agent_config(file_path):
            findings.extend(self._scan_agent_config(file_path, text))

        for i, line in enumerate(text.splitlines(), 1):
            finding = self.check_line(line, file_path, i)
            if finding:
                findings.append(finding)

        return self._dedupe_findings(findings)

    def _finding_from_pattern(
        self,
        pattern: SecretPattern,
        line: str,
        file_path: Optional[Path],
        line_no: Optional[int],
    ) -> Finding:
        snippet = line.strip()
        if len(snippet) > 80:
            snippet = snippet[:80] + "..."
        path = file_path or Path("<unknown>")
        return Finding(
            file_path=path,
            line_no=line_no,
            name=pattern.name,
            category=pattern.category,
            severity=pattern.severity,
            snippet=snippet,
            remediation=pattern.remediation or self._default_remediation(pattern.name, path),
            description=pattern.description,
        )

    def _default_remediation(self, name: str, file_path: Path) -> str:
        fname = file_path.name.lower()
        lname = name.lower()

        if ".env" in fname:
            return "Stop tracking this file. Run `git rm --cached` and add it to .gitignore."
        if "private key" in lname:
            return "Rotate key. Never commit private key material."
        if "key" in lname or "token" in lname or "secret" in lname:
            return "Revoke this credential and load it from an environment variable."
        if "entropy" in lname:
            return "Verify if secret. If yes, move to env vars."
        return "Review and remove or rewrite before pushing."

    def _default_category(self, name: str) -> str:
        lname = name.lower()
        if "entropy" in lname:
            return "entropy"
        if any(term in lname for term in ("unsafe", "insecure", "weak", "debug", "injection", "docker", "binding", "dangerously")):
            return "security-practice"
        return "secret"

    def _default_severity(self, name: str) -> str:
        lname = name.lower()
        if "entropy" in lname:
            return "medium"
        if any(term in lname for term in ("unsafe", "insecure", "weak", "debug", "injection", "docker", "binding", "dangerously")):
            return "medium"
        return "high"

    def _presence_warning(self, file_path: Path) -> Optional[Finding]:
        normalized = file_path.as_posix()
        suffix_match = any(normalized.endswith(suffix) for suffix in self.SENSITIVE_PATH_SUFFIXES)
        if file_path.name not in self.SENSITIVE_FILE_NAMES and not file_path.name.startswith(".env.") and not suffix_match:
            return None

        category = "agent-config" if self._is_agent_config(file_path) else "credential-file"
        return Finding(
            file_path=file_path,
            line_no=None,
            name="Sensitive File Present",
            category=category,
            severity="low",
            snippet=file_path.name,
            remediation="Confirm this file is intentionally committed. Prefer checked-in examples with placeholders.",
            description="Sensitive local configuration file detected in the scan target.",
        )

    def _is_agent_config(self, file_path: Path) -> bool:
        normalized = file_path.as_posix()
        return file_path.name in self.AGENT_CONFIG_FILES or any(
            normalized.endswith(path) for path in self.AGENT_CONFIG_PATHS
        )

    def _scan_agent_config(self, file_path: Path, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return [
                Finding(
                    file_path=file_path,
                    line_no=None,
                    name="Unreadable Agent Config",
                    category="agent-config",
                    severity="medium",
                    snippet="invalid JSON",
                    remediation="Fix the JSON so agent configuration can be reviewed reliably.",
                    description="Agent configuration could not be parsed as JSON.",
                )
            ]

        findings: List[Finding] = []
        self._walk_config_values(data, [], file_path, findings)
        return findings

    def _walk_config_values(
        self,
        value: Any,
        path: List[str],
        file_path: Path,
        findings: List[Finding],
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                self._walk_config_values(child, path + [str(key)], file_path, findings)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                self._walk_config_values(child, path + [str(index)], file_path, findings)
            return
        if not isinstance(value, str):
            return

        key_path = ".".join(path)
        key_name = path[-1].lower() if path else ""
        lower_path = key_path.lower()

        if self._looks_like_placeholder(value):
            return

        line_finding = self.check_line(value, file_path, None)
        if line_finding:
            findings.append(Finding(
                file_path=file_path,
                line_no=None,
                name=line_finding.name,
                category="agent-config",
                severity=line_finding.severity,
                snippet=f"{key_path}: {self._redact(value)}",
                remediation="Move this literal value into an environment variable referenced by the agent config.",
                description=line_finding.description,
            ))
            return

        if (
            len(value) >= 12
            and any(keyword in lower_path or keyword in key_name for keyword in self.SENSITIVE_KEYWORDS)
            and not self._looks_like_safe_reference(value)
        ):
            findings.append(Finding(
                file_path=file_path,
                line_no=None,
                name="Hardcoded Agent Config Secret",
                category="agent-config",
                severity="high",
                snippet=f"{key_path}: {self._redact(value)}",
                remediation="Move this literal value into an environment variable referenced by the agent config.",
                description="Agent/MCP configuration contains a hardcoded secret-like value.",
            ))

    def _looks_like_placeholder(self, value: str) -> bool:
        return bool(self.PLACEHOLDER_RE.match(value.strip()))

    def _looks_like_safe_reference(self, value: str) -> bool:
        stripped = value.strip()
        return (
            self._looks_like_placeholder(stripped)
            or stripped.startswith("env:")
            or stripped.startswith("process.env.")
            or stripped.startswith("os.environ")
        )

    def _redact(self, value: str) -> str:
        if len(value) <= 8:
            return "***"
        return f"{value[:4]}...{value[-4:]}"

    def _dedupe_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for finding in findings:
            key = (
                finding.file_path,
                finding.line_no,
                finding.name,
                finding.category,
                finding.snippet,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique
