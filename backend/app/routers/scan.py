import asyncio
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    ScanListResponse,
    LiveReviewRequest,
    LiveReviewResponse,
)
from app.services.scanner import (
    create_scan,
    get_scan,
    list_scans,
    perform_live_review,
)

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_code(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    """Submit code for security + bug scanning."""

    # create_scan saves the record AND kicks off perform_scan as a background task.
    # Do NOT call analyze_code here — that would double-run the analysis.
    scan = await create_scan(request, db)

    # Poll until the background task finishes (max 60 s, check every 0.5 s)
    for _ in range(120):
        await asyncio.sleep(0.5)
        result = await db.execute(
            select(Scan)
            .options(selectinload(Scan.vulnerabilities))
            .where(Scan.id == scan.id)
        )
        scan = result.scalar_one()
        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            break

    if scan.status == ScanStatus.FAILED:
        raise HTTPException(status_code=500, detail="Scan failed during analysis")

    return ScanResponse.model_validate(scan)


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_results(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get scan results by ID."""
    scan = await get_scan(scan_id, db)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.get("/scans", response_model=ScanListResponse)
async def get_scans(
    page: int = 1,
    page_size: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List all scans with pagination."""
    return await list_scans(db, page, page_size)


@router.post("/live-review", response_model=LiveReviewResponse)
async def live_review(
    request: LiveReviewRequest,
    db: AsyncSession = Depends(get_db),
):
    """Perform real-time code security + bug review."""
    return await perform_live_review(request, db)