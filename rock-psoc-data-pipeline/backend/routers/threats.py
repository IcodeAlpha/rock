"""
Threats Router
GET /api/threats - Fetch all threats from database
POST /api/threats - Create new threat
GET /api/threats/{id} - Get single threat
PUT /api/threats/{id} - Update threat
DELETE /api/threats/{id} - Delete threat
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime

from backend.services.supabase_service import (
    get_all_threats,
    get_threat_by_id,
    create_threat,
    update_threat,
    delete_threat
)

router = APIRouter()

# Request/Response schemas
class ThreatCreate(BaseModel):
    title: str = Field(..., description="Threat title")
    description: Optional[str] = Field(None, description="Threat description")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    probability: float = Field(..., ge=0, le=1, description="Probability score 0-1")
    confidence: Optional[float] = Field(None, ge=0, le=1, description="Model confidence 0-1")
    confidence_score: Optional[float] = Field(None, ge=0, le=1, description="Confidence score 0-1")
    impact: Optional[str] = Field(None, description="Impact assessment")
    timeframe: Optional[str] = Field(None, description="Timeframe for threat")
    predicted_timeframe: Optional[str] = Field(None, description="Predicted timeframe")
    affected_systems: Optional[str] = Field(None, description="Affected systems")
    status: Optional[str] = Field(default="active", description="Status")
    indicators: Optional[dict] = Field(None, description="Threat indicators as JSON")
    source: str = Field(default="Manual Entry", description="Data source")
    organization_id: Optional[int] = Field(None, description="Organization ID")

class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    probability: Optional[float] = None
    confidence: Optional[float] = None
    confidence_score: Optional[float] = None
    impact: Optional[str] = None
    timeframe: Optional[str] = None
    predicted_timeframe: Optional[str] = None
    affected_systems: Optional[str] = None
    status: Optional[str] = None
    indicators: Optional[dict] = None

@router.get("/threats")
async def list_threats(
    limit: int = Query(100, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status")
):
    """
    Get all threats from database with optional filtering
    
    Parameters:
        limit: Maximum number of results (default 100, max 1000)
        offset: Number of results to skip for pagination
        severity: Filter by severity level (low, medium, high, critical)
        threat_type: Filter by threat type
    
    Returns:
        List of threat records with metadata
    """
    try:
        threats = get_all_threats(
            limit=limit,
            offset=offset,
            severity=severity,
            status=status
        )
        
        return {
            "data": threats,
            "count": len(threats),
            "limit": limit,
            "offset": offset
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threats: {str(e)}")

@router.get("/threats/{threat_id}")
async def get_threat(threat_id: str):
    """
    Get a single threat by ID
    
    Parameters:
        threat_id: Threat record ID
    
    Returns:
        Threat record
    """
    try:
        threat = get_threat_by_id(threat_id)
        
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
        
        return threat
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch threat: {str(e)}")

@router.post("/threats", status_code=201)
async def add_threat(threat: ThreatCreate):
    """
    Create a new threat record
    
    Parameters:
        threat: Threat data (ThreatCreate schema)
    
    Returns:
        Created threat record with ID
    """
    try:
        new_threat = create_threat(threat.model_dump())
        return new_threat
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create threat: {str(e)}")

@router.put("/threats/{threat_id}")
async def modify_threat(threat_id: str, threat: ThreatUpdate):
    """
    Update an existing threat
    
    Parameters:
        threat_id: Threat record ID
        threat: Updated threat data
    
    Returns:
        Updated threat record
    """
    try:
        # Filter out None values
        update_data = {k: v for k, v in threat.model_dump().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No update data provided")
        
        updated_threat = update_threat(threat_id, update_data)
        
        if not updated_threat:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
        
        return updated_threat
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update threat: {str(e)}")

@router.delete("/threats/{threat_id}", status_code=204)
async def remove_threat(threat_id: str):
    """
    Delete a threat record
    
    Parameters:
        threat_id: Threat record ID
    
    Returns:
        204 No Content on success
    """
    try:
        success = delete_threat(threat_id)
        
        if not success:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
        
        return None
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete threat: {str(e)}")