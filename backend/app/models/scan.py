import enum
from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, ForeignKey, Enum, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code_hash: Mapped[str] = mapped_column(String(64), index=True)
    language: Mapped[str] = mapped_column(String(50))
    code: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"))
    severity: Mapped[str] = mapped_column(Enum(SeverityLevel))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    line_number: Mapped[int] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[str] = mapped_column(Text, nullable=True)
    fix_suggestion: Mapped[str] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str] = mapped_column(String(20), nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="vulnerabilities")


class RepoScan(Base):
    __tablename__ = "repo_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_url: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    security_score: Mapped[str] = mapped_column(String(2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    total_files: Mapped[int] = mapped_column(Integer, default=0)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    file_results: Mapped[list["RepoFileResult"]] = relationship(
        back_populates="repo_scan", cascade="all, delete-orphan"
    )


class RepoFileResult(Base):
    __tablename__ = "repo_file_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("repo_scans.id"))
    file_path: Mapped[str] = mapped_column(String(500))
    language: Mapped[str] = mapped_column(String(50))
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    issues: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string

    repo_scan: Mapped["RepoScan"] = relationship(back_populates="file_results")
