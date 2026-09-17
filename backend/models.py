"""
AegisSec - Core Data Models & Schemas
Pydantic data models for projects, scans, findings, users, RBAC, and integrations.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class RoleEnum(str, Enum):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


class FindingStatusEnum(str, Enum):
    OPEN = "open"
    IN_TRIAGE = "in_triage"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


# --- User & Auth Models ---
class UserModel(BaseModel):
    id: str
    username: str
    email: str
    role: RoleEnum
    created_at: str


class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    role: RoleEnum = RoleEnum.DEVELOPER


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserModel


# --- Project Models ---
class ProjectCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    git_url: Optional[str] = ""
    git_branch: Optional[str] = "main"
    git_pat: Optional[str] = ""


class ProjectModel(BaseModel):
    id: str
    name: str
    description: str
    git_url: str
    git_branch: str
    git_pat_configured: bool
    created_by: str
    created_at: str
    last_scanned: Optional[str] = None
    total_findings: int = 0
    risk_score: float = 0.0


# --- Finding & Scan Models ---
class FindingModel(BaseModel):
    id: str
    scan_id: str
    project_id: str
    type: str  # 'sast' or 'sca'
    title: str
    description: str
    remediation: str
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    language: Optional[str] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    license: Optional[str] = None
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    cvss_score: float
    cvss_vector: str
    epss_score: float
    epss_percentile: float
    composite_risk_score: float
    quadrant: str
    urgency: str
    sla_days: int
    standards: List[str] = []
    status: str = "open"
    author_name: Optional[str] = "Unknown"
    author_email: Optional[str] = "unknown@domain.local"
    commit_hash: Optional[str] = "HEAD"
    commit_date: Optional[str] = None
    commit_message: Optional[str] = None
    jira_key: Optional[str] = None
    zammad_id: Optional[str] = None


class ScanModel(BaseModel):
    id: str
    project_id: str
    project_name: str
    scan_type: str  # 'full', 'sast', 'sca'
    status: str  # 'queued', 'running', 'completed', 'failed'
    started_at: str
    completed_at: Optional[str] = None
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    average_cvss: float = 0.0
    average_epss: float = 0.0
    composite_risk_score: float = 0.0
    error_message: Optional[str] = None


# --- Custom Rule Models ---
class CustomRuleModel(BaseModel):
    id: str
    name: str
    type: str
    rule_category: str
    nl_prompt: str
    languages: List[str] = []
    severity: str
    cwe: str
    standards: List[str] = []
    regex: Optional[str] = None
    description: str
    remediation: str
    yaml_representation: str
    is_active: bool = True


class RuleGenerateRequest(BaseModel):
    prompt: str
    ecosystem: Optional[str] = "auto"


class RuleTestRequest(BaseModel):
    rule_yaml: str
    sample_code: str
    language: Optional[str] = "python"


# --- Integrations ---
class JiraConfigRequest(BaseModel):
    enabled: bool = False
    url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Bug"


class ZammadConfigRequest(BaseModel):
    enabled: bool = False
    url: str
    api_token: str
    group: str = "Users"


class CreateTicketRequest(BaseModel):
    platform: str  # 'jira' or 'zammad'
    finding_id: str
