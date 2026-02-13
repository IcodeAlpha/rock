"""
Supabase Service
Database operations for threat predictions and statistics
"""

from supabase import create_client, Client
from backend.config import settings
from typing import Optional, List, Dict
from functools import lru_cache

@lru_cache()
def get_supabase_client() -> Client:
    """
    Get cached Supabase client instance
    
    Returns:
        Supabase client
    """
    if not settings.SUPABASE_URL or not settings.SUPABASE_KEY:
        raise ValueError("Supabase credentials not configured in .env file")
    
    return create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def get_all_threats(
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    status: Optional[str] = None
) -> List[Dict]:
    """
    Fetch threats from database with optional filtering
    
    Parameters:
        limit: Maximum number of results
        offset: Number of results to skip
        severity: Filter by severity level
        status: Filter by status
    
    Returns:
        List of threat records
    """
    supabase = get_supabase_client()
    
    # Build query
    query = supabase.table('predictions').select('*')
    
    # Apply filters
    if severity:
        query = query.eq('severity', severity)
    
    if status:
        query = query.eq('status', status)
    
    # Apply pagination and ordering
    query = query.order('created_at', desc=True).range(offset, offset + limit - 1)
    
    # Execute
    result = query.execute()
    
    return result.data

def get_threat_by_id(threat_id: str) -> Optional[Dict]:
    """
    Get a single threat by ID
    
    Parameters:
        threat_id: Threat record ID
    
    Returns:
        Threat record or None if not found
    """
    supabase = get_supabase_client()
    
    result = supabase.table('predictions')\
        .select('*')\
        .eq('id', threat_id)\
        .execute()
    
    if result.data:
        return result.data[0]
    return None

def create_threat(threat_data: Dict) -> Dict:
    """
    Create a new threat record
    
    Parameters:
        threat_data: Threat data dictionary
    
    Returns:
        Created threat record with ID
    """
    supabase = get_supabase_client()
    
    result = supabase.table('predictions').insert(threat_data).execute()
    
    return result.data[0]

def update_threat(threat_id: str, update_data: Dict) -> Optional[Dict]:
    """
    Update an existing threat
    
    Parameters:
        threat_id: Threat record ID
        update_data: Fields to update
    
    Returns:
        Updated threat record or None if not found
    """
    supabase = get_supabase_client()
    
    result = supabase.table('predictions')\
        .update(update_data)\
        .eq('id', threat_id)\
        .execute()
    
    if result.data:
        return result.data[0]
    return None

def delete_threat(threat_id: str) -> bool:
    """
    Delete a threat record
    
    Parameters:
        threat_id: Threat record ID
    
    Returns:
        True if deleted, False if not found
    """
    supabase = get_supabase_client()
    
    result = supabase.table('predictions')\
        .delete()\
        .eq('id', threat_id)\
        .execute()
    
    return len(result.data) > 0

def get_dashboard_stats() -> Dict:
    """
    Get dashboard statistics
    
    Returns:
        Dictionary with various statistics
    """
    supabase = get_supabase_client()
    
    # Get all threats
    all_threats = supabase.table('predictions').select('severity, title').execute()
    
    # Count by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    
    # Count by title
    title_counts = {}
    
    for threat in all_threats.data:
        # Severity
        severity = threat.get('severity', '').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Title
        title = threat.get('title', 'Unknown')
        title_counts[title] = title_counts.get(title, 0) + 1
    
    # Get recent count (last 24 hours)
    from datetime import datetime, timedelta
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    
    recent = supabase.table('predictions')\
        .select('id')\
        .gte('created_at', yesterday)\
        .execute()
    
    return {
        "total_threats": len(all_threats.data),
        "by_severity": severity_counts,
        "by_title": title_counts,
        "recent_24h": len(recent.data),
        "top_titles": sorted(
            title_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
    }