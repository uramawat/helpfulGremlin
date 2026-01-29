# 👾 helpfulGremlin

**Sanity check your vibes before you git push.**

![Build Status](https://github.com/Start-Vibe-Coding/helpfulGremlin/actions/workflows/release.yml/badge.svg)

`helpfulGremlin` is a lightweight, zero-config CLI utility designed to scan your codebase for sensitive artifacts—API keys, secrets, tokens, and private keys—before they are accidentally exposed. Built for "vibe-coding" where velocity is high, it acts as a friendly guardrail.

## 🚀 Quick Start

Run it instantly using `uv` (no installation required):

```bash
# Run in the current directory
uvx helpfulGremlin
```

Or install it globally:

```bash
uv tool install helpfulGremlin
helpfulGremlin .
```

## 🛠 Usage

```bash
# Scan the current directory
helpfulGremlin

# Scan a specific directory or file
helpfulGremlin ./src/my_script.py

# Verbose mode (see every file checked)
helpfulGremlin . --verbose

# Run with multiple worker processes (for large repos)
helpfulGremlin . --workers 4
```

## 🏗 Architecture & Design Decisions

### 1. **Python & `uv` First**
We chose **Python** for its rich ecosystem of text processing and regex libraries. Typically, Python tools are hard to distribute, but with **`uv`**, `helpfulGremlin` can be run ephemerally (`uvx`) without messing up your system python.

### 2. **Hybrid Detection Engine**
The tool uses a two-layer detection strategy:
- **Layer 1: Regex Signatures**: Fast pattern matching for known secrets (AWS, OpenAI, Stripe, etc.). Patterns are externalized in `src/helpfulgremlin/patterns.yaml`.
- **Layer 2: Entropy Analysis**: Uses Shannon Entropy to detect high-randomness strings (like passwords or unknown API keys) that don't match specific regexes. This catches weird custom secrets others miss.

### 3. **Smart Context Awareness**
- **Gitignore Support**: Automatically parses your `.gitignore` to avoid scanning `node_modules`, `venv`, etc.
- **Binary Skipping**: Detects and skips binary files to save CPU.
- **Large File Protection**: Skipping files > 5MB to prevent memory exhaustion.
- **Context-Aware Remediation**: It doesn't just say "Error"; it suggests *how* to fix it (e.g., "Move this hardcoded key to an environment variable").

### 4. **Modern UX (`textual` / `rich`)**
We use the `rich` library to provide beautiful, emoji-enriched terminal output, progress bars, and tables. Security tools shouldn't be boring 1990s textual walls.

## 🕵️ Detected Patterns

`helpfulGremlin` currently detects:

- **Cloud Providers**: AWS (Access/Secret Keys), Google Cloud API Keys, Azure Storage Keys (opt-in).
- **AI/ML**: OpenAI, Anthropic, Gemini, HuggingFace, Replicate.
- **Services**: Stripe, Slack, Twilio, Salesforce, Facebook.
- **Generic**: PEM Private Keys, Generic "api_key" variable assignments.
- **Unknowns**: High-entropy strings (> 4.2 bits of randomness).

## ⚙️ Configuration

You can customize the detection rules by editing the `patterns.yaml` file inside the package.

## 📦 License

MIT
