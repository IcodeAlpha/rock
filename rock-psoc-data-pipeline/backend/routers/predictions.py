"""
Predictions Router
POST /api/predict - Make ML prediction (proxies to prediction API on port 8000)
POST /api/predict/batch - Batch predictions
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, List, Optional

from backend.services.ml_service import (
    predict_intrusion,
    predict_phishing,
    predict_vulnerability
)

router = APIRouter()

# Request schemas
class IntrusionPredictRequest(BaseModel):
    features: Dict[str, float] = Field(
        ...,
        description="Network traffic features",
        example={
            "src_bytes": 1032,
            "dst_bytes": 0,
            "wrong_fragment": 8,
            "protocol": 373,
            "service": 647
        }
    )

class PhishingPredictRequest(BaseModel):
    features: Dict[str, float] = Field(
        ...,
        description="URL features (20 features)",
        example={
            "url_length": 189,
            "num_dots": 8,
            "has_ip": 1,
            "has_https": 0,
            "domain_length": 85
        }
    )

class VulnerabilityPredictRequest(BaseModel):
    features: Dict[str, float] = Field(
        ...,
        description="Vulnerability features",
        example={
            "days_since_added": 5,
            "is_ransomware": 1,
            "has_due_date": 1
        }
    )

@router.post("/predict/intrusion")
async def predict_network_intrusion(request: IntrusionPredictRequest):
    """
    Predict network intrusion type
    
    Calls the ML prediction API (port 8000) to classify network traffic.
    
    Parameters:
        request: Network traffic features
    
    Returns:
        Prediction with attack type, severity, and confidence
    """
    try:
        result = await predict_intrusion(request.features)
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )

@router.post("/predict/phishing")
async def predict_phishing_url(request: PhishingPredictRequest):
    """
    Predict if URL is phishing
    
    Calls the ML prediction API (port 8000) to classify URL.
    
    Parameters:
        request: URL features (20 features)
    
    Returns:
        Prediction with phishing/legitimate label and probability
    """
    try:
        result = await predict_phishing(request.features)
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )

@router.post("/predict/vulnerability")
async def predict_vulnerability_risk(request: VulnerabilityPredictRequest):
    """
    Predict vulnerability risk score and severity
    
    Calls the ML prediction API (port 8000) to score vulnerability.
    
    Parameters:
        request: Vulnerability features
    
    Returns:
        Risk score (0-100) and severity classification
    """
    try:
        result = await predict_vulnerability(request.features)
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )

@router.post("/predict/batch")
async def batch_predict(requests: List[Dict]):
    """
    Make multiple predictions in one request
    
    Parameters:
        requests: List of prediction requests with 'type' and 'features'
        Example: [
            {"type": "intrusion", "features": {...}},
            {"type": "phishing", "features": {...}}
        ]
    
    Returns:
        List of predictions
    """
    results = []
    
    for idx, req in enumerate(requests):
        try:
            pred_type = req.get("type")
            features = req.get("features", {})
            
            if pred_type == "intrusion":
                result = await predict_intrusion(features)
            elif pred_type == "phishing":
                result = await predict_phishing(features)
            elif pred_type == "vulnerability":
                result = await predict_vulnerability(features)
            else:
                result = {"error": f"Unknown prediction type: {pred_type}"}
            
            results.append({
                "index": idx,
                "type": pred_type,
                "prediction": result
            })
            
        except Exception as e:
            results.append({
                "index": idx,
                "type": req.get("type"),
                "error": str(e)
            })
    
    return {"predictions": results, "total": len(results)}