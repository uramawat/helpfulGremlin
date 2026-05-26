# 👾 helpfulGremlin

**Sanity check your vibes before you git push.**

![Build Status](https://github.com/uramawat/helpfulGremlin/actions/workflows/release.yml/badge.svg)

I built `helpfulGremlin` because I wanted a lightweight, zero-config CLI utility to scan my codebase for sensitive artifacts—API keys, secrets, tokens, private keys, and now AI-agent configuration leaks—before they are accidentally exposed. It's designed for "vibe-coding" where velocity is high, acting as a friendly guardrail.

Recently, I extended it to also check for **AI-agent-era leak surfaces** (like MCP configs, `.env` files, npm/PyPI auth files, and pasted bearer headers) plus bad security practices (like `eval()`, `pickle.load()`, or disabling SSL verification), making it more than just a generic secret scanner.

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
I chose **Python** for its rich ecosystem of text processing and regex libraries. Typically, Python tools are hard to distribute, but with **`uv`**, `helpfulGremlin` can be run ephemerally (`uvx`) without messing up your system python.

### 2. **Hybrid Detection Engine**
I implemented a three-layer detection strategy:
- **Layer 1: Regex Signatures**: Fast pattern matching for known secrets (AWS, OpenAI, Stripe, etc.). Patterns are externalized in `src/helpfulgremlin/patterns.yaml`.
- **Layer 2: Entropy Analysis**: Uses Shannon Entropy to detect high-randomness strings (like passwords or unknown API keys) that don't match specific regexes. This catches weird custom secrets others miss.
- **Layer 3: Agent Config Analysis**: Parses local MCP/agent JSON configs when possible and inspects env, header, command, arg, and URL values for hardcoded credentials.

### 3. **Smart Context Awareness**
I designed the scanner to be intelligent about *where* it looks:
- **Context-Aware Scanning**: Security checks are scoped to file types (e.g., Python-specific checks like `eval()` only run on `.py` files). This keeps performance high.
- **Agent-Aware Defaults**: Warns on risky local config files such as `.mcp.json`, `.claude/settings.json`, `.cursor/mcp.json`, `.env.local`, `.npmrc`, `.pypirc`, and cloud credential JSON files.
- **Gitignore Support**: Automatically parses your `.gitignore` to avoid scanning `node_modules`, `venv`, etc.
- **Binary Skipping**: Detects and skips binary files to save CPU.
- **Large File Protection**: Skipping files > 5MB to prevent memory exhaustion.
- **Remediation**: It doesn't just say "Error"; it suggests *how* to fix it (e.g., "Move this hardcoded key to an environment variable").

### 4. **Modern UX (`textual` / `rich`)**
I used the `rich` library to provide beautiful, emoji-enriched terminal output, progress bars, and tables. Security tools shouldn't be boring 1990s textual walls.

## 🕵️ Detected Patterns

`helpfulGremlin` currently detects:

- **Cloud Providers**: AWS (Access/Secret Keys), Google Cloud API Keys, Google Cloud Service Accounts, Azure Storage Keys (opt-in).
- **Databases**: PostgreSQL, MySQL, MongoDB, and Redis URIs.
- **AI/ML**: OpenAI, Anthropic, Gemini, HuggingFace, Replicate.
- **Services**: Stripe, Slack, Twilio, Salesforce, Facebook.
- **AI Agent Configs**:
    - MCP project configs: `.mcp.json`, `mcp.json`
    - Agent/editor configs: `.claude/settings.json`, `.cursor/mcp.json`, `claude_desktop_config.json`
    - Dangerous local credential files: `.env*`, `.npmrc`, `.pypirc`, `.netrc`, cloud credential JSON
    - Pasted bearer authorization headers and hardcoded MCP env/header values
- **Security Best Practices**: 
    - Unsafe Checks: `eval()`, `exec()`, `shell=True`
    - Unsafe Deserialization: `pickle.load()`
    - Insecure SSL/TLS: `verify=False`, Node `NODE_TLS_REJECT_UNAUTHORIZED`
    - Insecure Environments: Flask/Django `debug=True`, Docker `USER root`
    - Web Risks: `dangerouslySetInnerHTML` (XSS), formatted SQL queries (SQLi)
    - Weak Hashing: `MD5`
    - Insecure Network Binding: `0.0.0.0`
- **Generic**: PEM Private Keys, SSH Private Keys, JWT Tokens, Generic "api_key" variable assignments.
- **Unknowns**: High-entropy strings (> 4.2 bits of randomness).

## ⚙️ Configuration

You can customize the detection rules by editing the `patterns.yaml` file inside the package.

## 📦 License

MIT
