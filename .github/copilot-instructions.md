# SkillScanner - ClawHub Skill Security Analyzer

## Project Overview
SkillScanner is a FastAPI web application that analyzes ClawHub AI agent skills for security vulnerabilities.

## Tech Stack
- **Backend**: Python 3.11+ with FastAPI
- **Frontend**: HTML/CSS/JavaScript (Jinja2 templates)
- **Key Libraries**: python-multipart, pyyaml, aiofiles

## Project Structure
```
SkillScanner/
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI app entry point
│   ├── scanner.py        # Security scanning logic
│   ├── models.py         # Pydantic models
│   └── templates/
│       └── index.html    # Web UI
├── static/
│   └── styles.css
├── requirements.txt
└── README.md
```

## Running the App
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Security Checks Performed
- Command injection patterns
- Path traversal vulnerabilities
- Hardcoded secrets/credentials
- Unsafe shell command execution
- Privilege escalation risks
- Dangerous imports/functions
