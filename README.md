# Dheemai — SkillScanner

**Security analyzer for ClawHub AI agent skills.** Scan a skill before you run it.

ClawHub skills are ZIP packages that execute code, call tools, and access your filesystem on behalf of an AI agent. A malicious or poorly written skill can steal secrets, run arbitrary commands, or exfiltrate data. Dheemai scans the skill's code and manifest before it ever runs.

---

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000` in your browser.

---

## How to Scan a Skill

Three ways to submit a skill for analysis:

### 1. Upload Files
Drop individual files — `SKILL.md` plus any scripts (`.py`, `.sh`, `.bash`) — into the upload zone. Use this when you've extracted a downloaded skill archive.

### 2. Upload ZIP
Drop the `.zip` archive directly. Dheemai extracts it in a temporary directory, scans every text file, then deletes the temp files.

### 3. GitHub URL
Paste a GitHub repo URL (`https://github.com/owner/repo` or `owner/repo/path/to/skill`). Dheemai fetches `SKILL.md` and the `scripts/` directory directly from GitHub's raw content API — no local download needed.

---

## Architecture

```
Browser (HTML/CSS/JS)
        │
        │  multipart/form-data  or  JSON
        ▼
FastAPI  (app/main.py)
  ├── POST /api/scan/upload   — one or more raw files
  ├── POST /api/scan/zip      — ZIP archive
  ├── POST /api/scan/github   — GitHub repo URL (fetched via httpx)
  └── GET  /api/scan/example  — built-in vulnerable skill for demo
        │
        ▼
  SkillScanner  (app/scanner.py)
  ├── parse_skill_metadata()   — reads YAML frontmatter from SKILL.md
  ├── analyze_skill_metadata() — checks declared tools/permissions
  └── scan_content()           — regex pattern matching per file
        │
        ▼
  ScanResult  (app/models.py)
  └── List[SecurityFinding]    — severity, category, file, line, snippet, recommendation
```

**No database. No persistence.** Each scan is stateless — results are returned directly in the HTTP response and rendered in the browser.

---

## How the Scanner Works

Scanning happens in two passes for each skill.

### Pass 1 — Metadata Analysis (`SKILL.md`)

Every ClawHub skill declares its identity and required tools in a `SKILL.md` YAML frontmatter block:

```yaml
---
name: my-skill
version: 1.0.0
tools:
  - bash
  - file_write
  - web_fetch
---
```

Dheemai parses this and checks:

| Check | Severity | What it looks for |
|---|---|---|
| Wildcard tools | Critical | `tools: "*"` or `tools: all` |
| High-risk tools | High | `bash`, `shell`, `execute`, `computer`, `file_delete`, `sudo`, `admin` |
| Too many tools | Medium | More than 5 tools declared |
| Missing name | Info | Empty or absent `name` field |
| Missing version | Info | Absent `version` field |

A skill that requests `bash` and `file_delete` with no version and no name is a red flag before you ever look at the code.

### Pass 2 — Code Pattern Matching

Every `.py`, `.sh`, `.bash`, `.zsh`, and `.md` file is scanned line by line against a set of regex rules. Each match produces a `SecurityFinding` with the file path, line number, matched snippet, and a remediation recommendation.

| Category | Severity | What triggers it |
|---|---|---|
| Command Injection | Critical | `os.system()`, `subprocess` with `shell=True`, `eval()`, `exec()`, bash subshells |
| Code Execution via Input | Critical | `eval(input(...))`, `exec(input(...))`, `globals()[`, `__builtins__[` |
| Unsafe Deserialization | Critical | `pickle.load`, `pickle.loads`, `yaml.load()` without safe loader, `marshal.load` |
| Hardcoded Secrets | Critical | Variables named `password`, `api_key`, `token`, `secret` assigned string literals; OpenAI `sk-` keys; GitHub `ghp_` tokens |
| SQL Injection | Critical | String concatenation in `execute()`, f-strings with `SELECT`/`INSERT`/`UPDATE`/`DELETE` |
| Dangerous Shell Commands | Critical | `rm -rf /`, `rm -rf $VAR`, `mkfs.`, `dd if=`, fork bomb `:(){:|:&};:` |
| Path Traversal | High | `open()` with string concatenation, `../` sequences, `os.path.join` with `input()` |
| Prompt Injection | High | "ignore previous instructions", "you are now a", `<<SYS>>`, `[INST]`, `jailbreak`, `DAN mode` |
| Data Exfiltration | High | `requests.post` / `httpx.post` containing env vars, passwords, tokens, or secrets |
| SSRF | High | Requests to `169.254.x.x` (AWS metadata), `localhost`, `127.x`, `file://`, `gopher://` |
| Environment Variable Leakage | High | `print(os.environ)`, logging env vars to stdout |
| Privilege Escalation | High | `sudo`, `chmod 777`, `chown root`, `setuid()` |
| Dangerous Imports | Medium | `import ctypes`, `import pty`, `__import__()`, raw `import socket` |
| Network Exposure | Medium | Binding to `0.0.0.0`, `INADDR_ANY`, `socket.listen()` |
| Insecure HTTP | Medium | Plain `http://` to non-localhost, `verify=False`, `CERT_NONE` |
| Insecure Randomness | Low | `random.random()`, `random.randint()`, `random.choice()` — use `secrets` instead |

Duplicate findings on the same file + line + category are suppressed.

---

## Scan Result Format

```json
{
  "skill_name": "data-fetcher",
  "total_files_scanned": 3,
  "summary": {
    "critical": 4,
    "high": 2,
    "medium": 1,
    "low": 1,
    "info": 2
  },
  "findings": [
    {
      "severity": "critical",
      "category": "Command Injection",
      "title": "Command Injection detected",
      "description": "Matched `subprocess.run(f\"curl {user_input}\", shell=True` — rule: command_injection",
      "file_path": "scripts/fetch.py",
      "line_number": 12,
      "code_snippet": "result = subprocess.run(f\"curl {user_input}\", shell=True, capture_output=True)",
      "recommendation": "Use subprocess with shell=False and pass arguments as a list. Avoid eval/exec."
    }
  ]
}
```

---

## Project Structure

```
SkillScanner/
├── app/
│   ├── main.py          # FastAPI routes — upload, ZIP, GitHub, example
│   ├── scanner.py       # SkillScanner class — all detection logic
│   ├── models.py        # Pydantic models — ScanResult, SecurityFinding, SkillMetadata
│   └── templates/
│       └── index.html   # Single-page UI (tabs, drag-drop, results rendering)
├── static/
│   └── styles.css
└── requirements.txt
```

---

## API Reference

| Method | Endpoint | Body | Description |
|---|---|---|---|
| `GET` | `/` | — | Web UI |
| `POST` | `/api/scan/upload` | `multipart/form-data files=...` | Scan individual files |
| `POST` | `/api/scan/zip` | `multipart/form-data file=...` | Scan a ZIP archive |
| `POST` | `/api/scan/github` | `form repo_url=...` | Scan a GitHub repo |
| `GET` | `/api/scan/example` | — | Demo scan with intentional vulnerabilities |
| `GET` | `/api/health` | — | Health check |

---

## Limitations

- Pattern matching catches known bad patterns — it does not execute or emulate the skill
- Obfuscated code (base64-encoded payloads, dynamic imports) may evade regex rules
- GitHub scanning only fetches `SKILL.md` and files under `scripts/` — deeply nested layouts may be missed
- No dependency vulnerability checking (CVE lookup) yet
