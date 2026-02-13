"""
Health Check Router
GET /api/health - Check if API is running and Supabase is connected
"""

from fastapi import APIRouter, HTTPException
from backend.services.supabase_service import get_supabase_client
from backend.config import settings
from datetime import datetime

router = APIRouter()

@router.get("/health")
async def health_check():
    """
    Health check endpoint - verifies API and Supabase connection
    
    Returns:
        dict: Health status, timestamp, and service statuses
    """
    
    # Check Supabase connection
    supabase_status = "unknown"
    try:
        if settings.SUPABASE_URL and settings.SUPABASE_KEY:
            supabase = get_supabase_client()
            # Try a simple query to verify connection
            result = supabase.table('predictions').select('id').limit(1).execute()
            supabase_status = "connected"
        else:
            supabase_status = "not_configured"
    except Exception as e:
        supabase_status = f"error: {str(e)[:50]}"
    
    # Check ML API connection
    ml_api_status = "configured"
    if not settings.ML_API_URL:
        ml_api_status = "not_configured"
    
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "environment": settings.ENVIRONMENT,
        "services": {
            "supabase": supabase_status,
            "ml_api": ml_api_status,
            "ml_api_url": settings.ML_API_URL
        }
    }