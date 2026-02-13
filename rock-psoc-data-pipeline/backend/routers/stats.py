"""
Statistics Router
GET /api/stats - Get dashboard statistics from Supabase
"""

from fastapi import APIRouter, HTTPException
from backend.services.supabase_service import get_dashboard_stats

router = APIRouter()

@router.get("/stats")
async def get_stats():
    """
    Get dashboard statistics
    
    Returns:
        - Total threats count
        - Threats by severity
        - Threats by type
        - Recent activity counts
        - Model performance metrics
    """
    try:
        stats = get_dashboard_stats()
        return stats
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch statistics: {str(e)}"
        )

@router.get("/stats/severity")
async def get_severity_breakdown():
    """
    Get threat count breakdown by severity level
    
    Returns:
        Dictionary with counts for each severity level
    """
    try:
        from backend.services.supabase_service import get_supabase_client
        
        supabase = get_supabase_client()
        
        # Count by severity
        result = supabase.table('predictions').select('severity').execute()
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for record in result.data:
            severity = record.get('severity', '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "severity_breakdown": severity_counts,
            "total": sum(severity_counts.values())
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch severity breakdown: {str(e)}"
        )

@router.get("/stats/timeline")
async def get_timeline_stats():
    """
    Get threat detection timeline (last 30 days)
    
    Returns:
        Daily threat counts for the past 30 days
    """
    try:
        from backend.services.supabase_service import get_supabase_client
        from datetime import datetime, timedelta
        
        supabase = get_supabase_client()
        
        # Get threats from last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        
        result = supabase.table('predictions')\
            .select('created_at')\
            .gte('created_at', thirty_days_ago)\
            .execute()
        
        # Group by date
        daily_counts = {}
        for record in result.data:
            date = record['created_at'][:10]  # Extract YYYY-MM-DD
            daily_counts[date] = daily_counts.get(date, 0) + 1
        
        # Convert to list of {date, count}
        timeline = [
            {"date": date, "count": count}
            for date, count in sorted(daily_counts.items())
        ]
        
        return {
            "timeline": timeline,
            "total_days": len(timeline),
            "total_threats": sum(daily_counts.values())
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch timeline: {str(e)}"
        )