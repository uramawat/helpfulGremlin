import re
from dataclasses import dataclass
from typing import List, Optional

import yaml
import importlib.resources

@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    description: str

class Detector:
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
                                description=item["description"]
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

    def check_line(self, line: str) -> Optional[SecretPattern]:
        """
        Checks a single line against all patterns.
        Returns the first matching SecretPattern, or None.
        """
        # 1. Regex Checks
        for pat in self.patterns:
            if pat.pattern.search(line):
                return pat
        
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
                    return SecretPattern(
                        name="High Entropy String",
                        pattern=re.compile(re.escape(token)),
                        description=f"High entropy string detected ({entropy:.2f} bits). Potential secret or password."
                    )
        return None
