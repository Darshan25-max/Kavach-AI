from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.schemas.scan import (
    RepoAuditRequest, RepoAuditResponse, RepoAuditStatusResponse,
)
from app.services.repo import create_repo_audit, get_repo_audit_status
from app.models.scan import RepoScan

router = APIRouter()


@router.post("/analyze", response_model=RepoAuditResponse)
async def analyze_repo(request: RepoAuditRequest, db: AsyncSession = Depends(get_db)):
    """Submit a GitHub repository URL for security audit."""
    repo_scan = await create_repo_audit(request.repo_url, db)

    # MUST use selectinload — lazy loading crashes with async SQLAlchemy
    result = await db.execute(
        select(RepoScan)
        .options(selectinload(RepoScan.file_results))
        .where(RepoScan.id == repo_scan.id)
    )
    repo_scan = result.scalar_one()
    return RepoAuditResponse.model_validate(repo_scan)


@router.get("/{repo_scan_id}", response_model=RepoAuditResponse)
async def get_repo_audit_results(repo_scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get repository audit results."""
    result = await db.execute(
        select(RepoScan)
        .options(selectinload(RepoScan.file_results))
        .where(RepoScan.id == repo_scan_id)
    )
    repo_scan = result.scalar_one_or_none()
    if not repo_scan:
        raise HTTPException(status_code=404, detail="Repository audit not found")
    return RepoAuditResponse.model_validate(repo_scan)


@router.get("/{repo_scan_id}/status", response_model=RepoAuditStatusResponse)
async def get_repo_status(repo_scan_id: int, db: AsyncSession = Depends(get_db)):
    """Check repository audit progress."""
    status = await get_repo_audit_status(repo_scan_id, db)
    if not status:
        raise HTTPException(status_code=404, detail="Repository audit not found")
    return status