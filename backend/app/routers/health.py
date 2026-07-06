from fastapi import APIRouter
from app.schemas.scan import HealthResponse
from app.config import settings

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        gemini_configured=bool(settings.GEMINI_API_KEY),
    )
