"""Pydantic models for SkillScanner."""
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityFinding(BaseModel):
    """Represents a single security finding."""
    severity: Severity
    category: str
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str


class ScanResult(BaseModel):
    """Complete scan result for a skill."""
    skill_name: str
    total_files_scanned: int
    findings: list[SecurityFinding]
    summary: dict[str, int]  # severity -> count


class SkillMetadata(BaseModel):
    """Parsed SKILL.md metadata."""
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    tools: list[str] = []
    scripts: list[str] = []
