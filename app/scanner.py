"""Security scanner for ClawHub skills."""
import re
import yaml
from pathlib import Path
from typing import Optional
from .models import SecurityFinding, ScanResult, Severity, SkillMetadata


class SkillScanner:
    """Analyzes ClawHub skills for security vulnerabilities."""

    # Security patterns for detection
    PATTERNS = {
        "command_injection": {
            "patterns": [
                r"os\.system\s*\(",
                r"subprocess\.call\s*\([^)]*shell\s*=\s*True",
                r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
                r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True",
                r"eval\s*\(",
                r"exec\s*\(",
                r"`[^`]*\$[^`]*`",  # Bash command substitution
                r"\$\([^)]+\)",  # Bash subshell
            ],
            "severity": Severity.CRITICAL,
            "category": "Command Injection",
            "recommendation": "Use subprocess with shell=False and pass arguments as a list. Avoid eval/exec.",
        },
        "path_traversal": {
            "patterns": [
                r"open\s*\([^)]*\+[^)]*\)",
                r"\.\.\/",
                r"\.\./",
                r"Path\s*\([^)]*\+",
                r"os\.path\.join\s*\([^)]*input\s*\(",
            ],
            "severity": Severity.HIGH,
            "category": "Path Traversal",
            "recommendation": "Validate and sanitize file paths. Use pathlib and resolve() to prevent directory traversal.",
        },
        "hardcoded_secrets": {
            "patterns": [
                r"(?:password|passwd|pwd|secret|api_key|apikey|token|auth)\s*=\s*['\"][^'\"]{8,}['\"]",
                r"(?:AWS|AZURE|GCP|GITHUB|OPENAI)_[A-Z_]*(?:KEY|SECRET|TOKEN)\s*=\s*['\"][^'\"]+['\"]",
                r"sk-[a-zA-Z0-9]{20,}",  # OpenAI API key pattern
                r"ghp_[a-zA-Z0-9]{36}",  # GitHub token
                r"Bearer\s+[a-zA-Z0-9._-]+",
            ],
            "severity": Severity.CRITICAL,
            "category": "Hardcoded Secrets",
            "recommendation": "Use environment variables or secret management. Never hardcode credentials.",
        },
        "unsafe_deserialization": {
            "patterns": [
                r"pickle\.load",
                r"pickle\.loads",
                r"yaml\.load\s*\([^)]*(?!Loader)",
                r"yaml\.unsafe_load",
                r"marshal\.load",
            ],
            "severity": Severity.CRITICAL,
            "category": "Unsafe Deserialization",
            "recommendation": "Use yaml.safe_load() instead of yaml.load(). Avoid pickle with untrusted data.",
        },
        "privilege_escalation": {
            "patterns": [
                r"sudo\s+",
                r"chmod\s+777",
                r"chmod\s+\+[rwx]+",
                r"chown\s+root",
                r"setuid\s*\(",
            ],
            "severity": Severity.HIGH,
            "category": "Privilege Escalation",
            "recommendation": "Avoid elevated privileges. Use least-privilege principle.",
        },
        "dangerous_imports": {
            "patterns": [
                r"import\s+ctypes",
                r"from\s+ctypes",
                r"import\s+pty",
                r"import\s+socket",
                r"__import__\s*\(",
            ],
            "severity": Severity.MEDIUM,
            "category": "Dangerous Imports",
            "recommendation": "Review necessity of low-level imports. Document security implications.",
        },
        "network_exposure": {
            "patterns": [
                r"0\.0\.0\.0",
                r"INADDR_ANY",
                r"\.listen\s*\(",
                r"socket\.bind\s*\(",
            ],
            "severity": Severity.MEDIUM,
            "category": "Network Exposure",
            "recommendation": "Bind to localhost unless external access is required. Use firewalls.",
        },
        "sql_injection": {
            "patterns": [
                r"execute\s*\([^)]*%s",
                r"execute\s*\([^)]*\+",
                r"f['\"].*SELECT.*\{",
                r"f['\"].*INSERT.*\{",
                r"f['\"].*UPDATE.*\{",
                r"f['\"].*DELETE.*\{",
            ],
            "severity": Severity.CRITICAL,
            "category": "SQL Injection",
            "recommendation": "Use parameterized queries. Never concatenate user input into SQL.",
        },
        "insecure_http": {
            "patterns": [
                r"http://(?!localhost|127\.0\.0\.1)",
                r"verify\s*=\s*False",
                r"CERT_NONE",
            ],
            "severity": Severity.MEDIUM,
            "category": "Insecure HTTP",
            "recommendation": "Use HTTPS. Enable certificate verification.",
        },
        "dangerous_bash": {
            "patterns": [
                r"rm\s+-rf\s+/",
                r"rm\s+-rf\s+\$",
                r">\s*/dev/sd",
                r"mkfs\.",
                r"dd\s+if=",
                r":(){:\|:&};:",  # Fork bomb
            ],
            "severity": Severity.CRITICAL,
            "category": "Dangerous Shell Commands",
            "recommendation": "Add safeguards before destructive operations. Validate variables.",
        },
        "prompt_injection": {
            "patterns": [
                r"ignore\s+(previous|prior|above|all)\s+instructions",
                r"ignore\s+your\s+(system\s+)?prompt",
                r"you\s+are\s+now\s+(a|an)\s+\w",
                r"new\s+instruction[s]?\s*:",
                r"system\s+prompt\s*[:=]",
                r"<\s*/?system\s*>",
                r"<<SYS>>",
                r"\[INST\]",
                r"jailbreak",
                r"DAN\s+(mode|prompt)",
            ],
            "severity": Severity.HIGH,
            "category": "Prompt Injection",
            "recommendation": "Do not embed user-controlled content directly into LLM prompts. Sanitize and validate all external input before use in prompts.",
        },
        "data_exfiltration": {
            "patterns": [
                r"curl\s+.*-d\s+",
                r"curl\s+.*--data",
                r"wget\s+.*--post-data",
                r"requests\.(post|put|patch)\s*\([^)]*(?:os\.environ|password|secret|token|key)",
                r"httpx\.(post|put|patch)\s*\([^)]*(?:os\.environ|password|secret|token|key)",
                r"urllib.*urlopen.*data=",
                r"socket\.send\s*\([^)]*(?:password|secret|token|key|environ)",
            ],
            "severity": Severity.HIGH,
            "category": "Data Exfiltration",
            "recommendation": "Audit all outbound network requests. Ensure sensitive data is not transmitted to external endpoints.",
        },
        "ssrf": {
            "patterns": [
                r"requests\.get\s*\([^)]*(?:169\.254|10\.\d+|192\.168|172\.1[6-9]|172\.2\d|172\.3[01])",
                r"http://localhost",
                r"http://127\.",
                r"http://0\.0\.0\.0",
                r"http://\[::1\]",
                r"file://",
                r"gopher://",
                r"dict://",
            ],
            "severity": Severity.HIGH,
            "category": "Server-Side Request Forgery (SSRF)",
            "recommendation": "Validate and whitelist allowed URLs. Block requests to internal network ranges and localhost.",
        },
        "env_variable_leakage": {
            "patterns": [
                r"print\s*\(.*os\.environ",
                r"print\s*\(.*os\.getenv",
                r"logging\.\w+\s*\(.*os\.environ",
                r"logging\.\w+\s*\(.*os\.getenv",
                r"sys\.stdout\.write\s*\(.*os\.environ",
                r"os\.environ\s*\)\s*$",
                r"pprint\s*\(.*os\.environ",
            ],
            "severity": Severity.HIGH,
            "category": "Environment Variable Leakage",
            "recommendation": "Never log or print environment variables. They may contain secrets and credentials.",
        },
        "insecure_random": {
            "patterns": [
                r"random\.random\s*\(",
                r"random\.randint\s*\(",
                r"random\.choice\s*\(",
                r"random\.shuffle\s*\(",
                r"import\s+random(?!\s*#.*secure)",
            ],
            "severity": Severity.LOW,
            "category": "Insecure Randomness",
            "recommendation": "Use the `secrets` module instead of `random` for security-sensitive operations like tokens, passwords, or nonces.",
        },
        "code_execution_via_input": {
            "patterns": [
                r"compile\s*\([^)]*input\s*\(",
                r"eval\s*\([^)]*input\s*\(",
                r"exec\s*\([^)]*input\s*\(",
                r"__builtins__\[",
                r"getattr\s*\([^)]*__",
                r"globals\s*\(\s*\)\s*\[",
                r"locals\s*\(\s*\)\s*\[",
            ],
            "severity": Severity.CRITICAL,
            "category": "Code Execution via User Input",
            "recommendation": "Never pass user-controlled data to eval/exec/compile. Use safe alternatives like ast.literal_eval for data parsing.",
        },
    }

    def __init__(self):
        self.findings: list[SecurityFinding] = []

    def scan_content(self, content: str, file_path: str, file_type: str) -> list[SecurityFinding]:
        """Scan file content for security issues."""
        findings = []
        lines = content.split("\n")

        for pattern_name, pattern_info in self.PATTERNS.items():
            for pattern in pattern_info["patterns"]:
                for line_num, line in enumerate(lines, 1):
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        matched_text = match.group(0)[:80]
                        finding = SecurityFinding(
                            severity=pattern_info["severity"],
                            category=pattern_info["category"],
                            title=f"{pattern_info['category']} detected",
                            description=f"Matched `{matched_text}` — rule: {pattern_name}",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip()[:120],
                            recommendation=pattern_info["recommendation"],
                        )
                        # Avoid duplicate findings on same line for same category
                        if not any(
                            f.file_path == finding.file_path
                            and f.line_number == finding.line_number
                            and f.category == finding.category
                            for f in findings
                        ):
                            findings.append(finding)

        return findings

    # Tools considered high-risk when declared in SKILL.md
    HIGH_RISK_TOOLS = {
        "bash", "computer", "execute", "shell", "terminal",
        "file_write", "file_delete", "sudo", "admin",
    }

    # Tools that are suspicious if the skill has no clear need
    SENSITIVE_TOOLS = {
        "web_search", "web_fetch", "http_request", "network",
        "email", "calendar", "contacts",
    }

    def parse_skill_metadata(self, skill_md_content: str) -> Optional[SkillMetadata]:
        """Parse SKILL.md YAML frontmatter."""
        try:
            # Extract YAML frontmatter between --- markers
            match = re.match(r"^---\s*\n(.*?)\n---", skill_md_content, re.DOTALL)
            if match:
                yaml_content = match.group(1)
                data = yaml.safe_load(yaml_content)
                return SkillMetadata(
                    name=data.get("name", "Unknown"),
                    version=data.get("version"),
                    description=data.get("description"),
                    tools=data.get("tools", []),
                    scripts=data.get("scripts", []),
                )
        except Exception:
            pass
        return None

    def analyze_skill_metadata(self, metadata: SkillMetadata, file_path: str) -> list:
        """Analyze SKILL.md metadata for security misconfigurations."""
        from .models import SecurityFinding
        findings = []
        tools_lower = [t.lower() for t in metadata.tools]

        # Check for wildcard / all tools
        if "*" in metadata.tools or "all" in tools_lower:
            findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                category="Excessive Permissions",
                title="Skill requests all tools (wildcard permission)",
                description="The skill declares tools: '*' or 'all', granting it access to every available tool. This is overly broad and violates least-privilege.",
                file_path=file_path,
                line_number=None,
                code_snippet=f"tools: {metadata.tools}",
                recommendation="Declare only the specific tools the skill requires. Avoid wildcard permissions.",
            ))

        # Check for high-risk tools
        risky = [t for t in metadata.tools if t.lower() in self.HIGH_RISK_TOOLS]
        if risky:
            findings.append(SecurityFinding(
                severity=Severity.HIGH,
                category="Excessive Permissions",
                title=f"Skill requests high-risk tool(s): {', '.join(risky)}",
                description=f"The skill declares access to privileged tools that can execute arbitrary commands or modify the filesystem: {risky}",
                file_path=file_path,
                line_number=None,
                code_snippet=f"tools: {metadata.tools}",
                recommendation="Justify the need for each high-risk tool. Prefer narrower alternatives when possible.",
            ))

        # Warn if many tools are requested (> 5)
        if len(metadata.tools) > 5:
            findings.append(SecurityFinding(
                severity=Severity.MEDIUM,
                category="Excessive Permissions",
                title=f"Skill requests a large number of tools ({len(metadata.tools)})",
                description="Requesting many tools increases the attack surface if the skill is compromised or misbehaves.",
                file_path=file_path,
                line_number=None,
                code_snippet=f"tools: {metadata.tools}",
                recommendation="Request only the tools strictly necessary. Review each declared tool for necessity.",
            ))

        # Check for missing name/version (poor hygiene)
        if metadata.name in ("Unknown", "", None):
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                category="Metadata Quality",
                title="Skill is missing a name in SKILL.md",
                description="A missing or empty name makes it harder to identify and audit this skill.",
                file_path=file_path,
                line_number=None,
                code_snippet=None,
                recommendation="Add a descriptive `name` field to the SKILL.md frontmatter.",
            ))

        if not metadata.version:
            findings.append(SecurityFinding(
                severity=Severity.INFO,
                category="Metadata Quality",
                title="Skill is missing a version in SKILL.md",
                description="Without versioning, it is difficult to track changes and audit the skill over time.",
                file_path=file_path,
                line_number=None,
                code_snippet=None,
                recommendation="Add a `version` field (e.g., '1.0.0') to the SKILL.md frontmatter.",
            ))

        return findings

    def scan_skill_directory(self, skill_path: Path) -> ScanResult:
        """Scan an entire skill directory."""
        findings = []
        files_scanned = 0
        skill_name = skill_path.name

        # Scan SKILL.md
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            content = skill_md.read_text()
            metadata = self.parse_skill_metadata(content)
            if metadata:
                skill_name = metadata.name
                findings.extend(self.analyze_skill_metadata(metadata, "SKILL.md"))
            findings.extend(self.scan_content(content, "SKILL.md", "markdown"))
            files_scanned += 1

        # Scan scripts directory
        scripts_dir = skill_path / "scripts"
        if scripts_dir.exists():
            for script_file in scripts_dir.rglob("*"):
                if script_file.is_file():
                    suffix = script_file.suffix.lower()
                    if suffix in [".py", ".sh", ".bash", ".zsh", ""]:
                        try:
                            content = script_file.read_text()
                            file_type = "python" if suffix == ".py" else "bash"
                            rel_path = str(script_file.relative_to(skill_path))
                            findings.extend(self.scan_content(content, rel_path, file_type))
                            files_scanned += 1
                        except Exception:
                            pass

        # Generate summary
        summary = {s.value: 0 for s in Severity}
        for finding in findings:
            summary[finding.severity.value] += 1

        return ScanResult(
            skill_name=skill_name,
            total_files_scanned=files_scanned,
            findings=findings,
            summary=summary,
        )

    def scan_files(self, files: dict[str, str]) -> ScanResult:
        """Scan uploaded files (filename -> content mapping)."""
        findings = []
        skill_name = "Uploaded Skill"

        for filename, content in files.items():
            if filename == "SKILL.md" or filename.endswith("/SKILL.md"):
                metadata = self.parse_skill_metadata(content)
                if metadata:
                    skill_name = metadata.name
                    findings.extend(self.analyze_skill_metadata(metadata, filename))

            suffix = Path(filename).suffix.lower()
            if suffix in [".py", ".sh", ".bash", ".zsh", ".md", ""]:
                file_type = "python" if suffix == ".py" else "bash" if suffix in [".sh", ".bash", ".zsh"] else "markdown"
                findings.extend(self.scan_content(content, filename, file_type))

        summary = {s.value: 0 for s in Severity}
        for finding in findings:
            summary[finding.severity.value] += 1

        return ScanResult(
            skill_name=skill_name,
            total_files_scanned=len(files),
            findings=findings,
            summary=summary,
        )
