from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional
from app.models.scan import ScanStatus, SeverityLevel


# --- Scan Schemas ---

class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source code to scan")
    language: Optional[str] = Field(None, description="Programming language (auto-detected if None)")


class VulnerabilityResponse(BaseModel):
    id: int
    severity: SeverityLevel
    title: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    fix_suggestion: Optional[str] = None
    cwe_id: Optional[str] = None
    category: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: int
    code_hash: str
    language: str
    status: ScanStatus
    created_at: datetime
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    vulnerabilities: list[VulnerabilityResponse] = []

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    id: int
    language: str
    status: ScanStatus
    created_at: datetime
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanListItem]
    total: int
    page: int
    page_size: int


# --- Live Review Schemas ---

class LiveReviewRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: Optional[str] = None


class LiveReviewIssue(BaseModel):
    line: int
    severity: SeverityLevel
    message: str
    suggestion: Optional[str] = None


class LiveReviewResponse(BaseModel):
    issues: list[LiveReviewIssue]
    language: str
    overall_score: str = Field(description="Security grade A-F")


# --- Repo Audit Schemas ---

class RepoAuditRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL")


class RepoFileResultResponse(BaseModel):
    id: int
    file_path: str
    language: str
    vulnerability_count: int
    issues: Optional[str] = None

    model_config = {"from_attributes": True}


class RepoAuditResponse(BaseModel):
    id: int
    repo_url: str
    status: ScanStatus
    security_score: Optional[str] = None
    created_at: datetime
    total_files: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    file_results: list[RepoFileResultResponse] = []

    model_config = {"from_attributes": True}


class RepoAuditStatusResponse(BaseModel):
    id: int
    repo_url: str
    status: ScanStatus
    security_score: Optional[str] = None
    progress: int = Field(0, description="Progress percentage 0-100")

    model_config = {"from_attributes": True}


# --- Health ---

class HealthResponse(BaseModel):
    status: str
    version: str
    gemini_configured: bool
