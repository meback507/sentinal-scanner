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
    assigned_projects: List[str] = Field(default_factory=list)


class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    role: RoleEnum = RoleEnum.DEVELOPER
    assigned_projects: Optional[List[str]] = Field(default_factory=list)


class UserUpdateRequest(BaseModel):
    role: Optional[RoleEnum] = None
    password: Optional[str] = None
    email: Optional[str] = None
    assigned_projects: Optional[List[str]] = None


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
    assigned_users: Optional[List[str]] = Field(default_factory=list)


class ProjectMemberAssignRequest(BaseModel):
    user_ids: Optional[List[str]] = None
    user_id: Optional[str] = None
    role: Optional[str] = "member"


class FindingStatusUpdateRequest(BaseModel):
    status: Optional[str] = None
    status_val: Optional[str] = None
    reason: Optional[str] = None
    comment: Optional[str] = None


class CopilotChatRequest(BaseModel):
    message: str
    project_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list)


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
    members: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    member_count: Optional[int] = 0


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
    ticket_assigned_to: Optional[str] = None
    ticket_assigned_email: Optional[str] = None
    fingerprint: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    age_days: Optional[int] = 0
    first_seen_date: Optional[str] = None
    age_display: Optional[str] = None
    cisa_kev: Optional[bool] = False
    cisa_kev_due_date: Optional[str] = None
    ai_confidence_score: Optional[float] = None
    ai_confidence_label: Optional[str] = None
    ai_confidence_rationale: Optional[str] = None
    dependency_lag_versions: Optional[str] = None
    reachability_status: Optional[str] = "UNKNOWN"
    entropy: Optional[float] = None
    masked_value: Optional[str] = None
    sonar_key: Optional[str] = None
    sonar_rule_id: Optional[str] = None
    sonar_type: Optional[str] = None
    sonar_severity: Optional[str] = None
    rule_source: Optional[str] = None


class SecretScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "input.txt"


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
    project_id: Optional[str] = None
    project_name: Optional[str] = None


class RuleGenerateRequest(BaseModel):
    prompt: str
    ecosystem: Optional[str] = "auto"
    project_id: Optional[str] = None


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


class LLMConfigRequest(BaseModel):
    enabled: bool = True
    provider: str = "openai"  # 'openai', 'anthropic', 'gemini', 'ollama', 'custom'
    api_key: Optional[str] = ""
    model: str = "gpt-4o"
    endpoint_url: Optional[str] = ""
    temperature: float = 0.2
    enable_rule_generation: bool = True
    enable_remediation: bool = True


class AIRemediationResponse(BaseModel):
    success: bool = True
    provider: str
    model: str
    finding_id: str
    root_cause: str
    code_diff: str
    compliance_notes: str
    verification_guidance: str
    root_cause_analysis: Optional[str] = None
    suggested_fix_diff: Optional[str] = None
    compliance_implications: Optional[str] = None
    verification_steps: Optional[str] = None
    is_mock: bool = False


class GateCheckRequest(BaseModel):
    project_id: str
    commit_sha: Optional[str] = "HEAD"
    branch: Optional[str] = "main"
    strict_mode: Optional[bool] = False
    max_critical: Optional[int] = 0
    max_high: Optional[int] = 2


class ApplyPatchRequest(BaseModel):
    patch_code: Optional[str] = None
    resolution_note: Optional[str] = "Auto-remediated via Sentinel AI Assistant"


class QualityGateResponse(BaseModel):
    project_id: str
    project_name: str
    status: str  # 'PASSED', 'FAILED'
    passed: bool
    summary: str
    evaluated_at: str
    criteria: Dict[str, Any]
    metrics: Dict[str, Any]


# --- Batch Patching & Multi-File PR Models ---
class BatchPatchRequest(BaseModel):
    finding_ids: List[str]
    dry_run: Optional[bool] = False
    resolution_note: Optional[str] = "Batch remediated via Sentinel Auto-Patch Studio"


class BatchPatchResponse(BaseModel):
    success: bool
    dry_run: bool
    applied_count: int
    files_affected: List[str]
    unified_diff: str
    patched_findings: List[str]
    audit_id: Optional[str] = None


class BatchPRRequest(BaseModel):
    finding_ids: List[str]
    pr_title: Optional[str] = None
    pr_body: Optional[str] = None
    target_branch: Optional[str] = "main"


# --- Webhook Integration Models ---
class WebhookConfigRequest(BaseModel):
    enabled: bool = True
    slack_webhook_url: Optional[str] = ""
    teams_webhook_url: Optional[str] = ""
    discord_webhook_url: Optional[str] = ""
    generic_webhook_url: Optional[str] = ""
    generic_secret: Optional[str] = ""
    notify_on_scan_completed: Optional[bool] = True
    notify_on_critical_finding: Optional[bool] = True
    notify_on_cisa_kev: Optional[bool] = True
    min_severity: Optional[str] = "HIGH"


class WebhookTestRequest(BaseModel):
    webhook_type: str = "slack"  # 'slack', 'teams', 'discord', 'generic'
    webhook_url: str
    secret: Optional[str] = ""


# --- DAST & Schedules Models ---
class DASTAuditRequest(BaseModel):
    target_url: str
    timeout: Optional[int] = 6
    project_id: Optional[str] = None


class ScheduleCreateRequest(BaseModel):
    id: Optional[str] = None
    name: str
    type: str = "threat_intel_sync"  # 'threat_intel_sync', 'project_scan'
    interval_hours: int = 24
    project_id: Optional[str] = None
    enabled: Optional[bool] = True
# --- SBOM, Rule Builder, Issue Tracker & RASP Models ---
class CustomRuleBuilderRequest(BaseModel):
    id: Optional[str] = None
    name: str
    type: str = "sast"  # sast, iac, secret
    severity: str = "HIGH"
    languages: List[str] = ["python"]
    cwe: Optional[str] = "CWE-89"
    owasp: Optional[str] = "OWASP:A03:2021"
    standards: List[str] = []
    regex: str
    description: str
    remediation: str
    test_snippet: Optional[str] = None
    project_id: Optional[str] = None


class RuleSandboxEvaluateRequest(BaseModel):
    regex: str
    test_snippet: str
    language: Optional[str] = "python"


class TrackerTicketCreateRequest(BaseModel):
    finding_id: str
    provider: str = "jira"  # jira, linear
    project_key: Optional[str] = None


class TrackerConfigRequest(BaseModel):
    provider: str  # jira, linear
    config: Dict[str, Any]


class RASPSimulateRequest(BaseModel):
    vector: str  # SQL_INJECTION, COMMAND_INJECTION, PATH_TRAVERSAL, SSRF, XXE_INJECTION, XSS_REFLECTED
    payload: Optional[str] = None


class RASPModeRequest(BaseModel):
    mode: str  # BLOCK, MONITOR


# --- Threat Model, Vault Manager, Container Scanner & Policy Studio Models ---
class ThreatModelGenerateRequest(BaseModel):
    project_id: Optional[str] = None


class VaultRotateRequest(BaseModel):
    finding_id: str
    provider: Optional[str] = "hashicorp_vault"  # hashicorp_vault, aws_secrets_manager, azure_key_vault


class VaultConfigRequest(BaseModel):
    active_provider: str
    providers: Dict[str, Any]


class ContainerScanRequest(BaseModel):
    dockerfile_content: Optional[str] = None
    project_id: Optional[str] = None


class PolicyStudioSaveRequest(BaseModel):
    policy_name: str
    rules: List[Dict[str, Any]]
    description: Optional[str] = None


class PolicyDryRunRequest(BaseModel):
    metrics: Optional[Dict[str, Any]] = None
    project_id: Optional[str] = None


# --- Attack Path, Compliance, API Fuzzer, LLM Sec, SBOM Drift & Sandbox Models ---
class AttackPathSimulateRequest(BaseModel):
    finding_id: str


class ComplianceExportRequest(BaseModel):
    framework: Optional[str] = "all"


class APIFuzzerScanRequest(BaseModel):
    openapi_spec: Optional[str] = None
    base_url: Optional[str] = "http://127.0.0.1:8000"


class LLMProbeRequest(BaseModel):
    system_prompt: str
    user_test_input: Optional[str] = None


class LLMCodeScanRequest(BaseModel):
    file_contents: Optional[Dict[str, str]] = None


class SBOMAttestationRequest(BaseModel):
    project_name: Optional[str] = "sentinel-appsec"
    commit_sha: Optional[str] = "d7a4b89c01f3e2"


class PlaygroundRunRequest(BaseModel):
    challenge_id: str
    user_code: str
    test_payload: Optional[str] = None


class IDEScanFileRequest(BaseModel):
    file_path: str
    content: str
    project_id: Optional[str] = None

