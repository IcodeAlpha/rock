"""
ML Service
Proxies requests to the ML prediction API (port 8000)
"""

import httpx
from typing import Dict
from backend.config import settings

async def predict_intrusion(features: Dict[str, float]) -> Dict:
    """
    Call ML API to predict network intrusion
    
    Parameters:
        features: Network traffic features
    
    Returns:
        Prediction result from ML API
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ML_API_URL}/predict/intrusion",
            json={"features": features},
            timeout=10.0
        )
        response.raise_for_status()
        return response.json()

async def predict_phishing(features: Dict[str, float]) -> Dict:
    """
    Call ML API to predict phishing URL
    
    Parameters:
        features: URL features (20 features)
    
    Returns:
        Prediction result from ML API
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ML_API_URL}/predict/phishing",
            json={"features": features},
            timeout=10.0
        )
        response.raise_for_status()
        return response.json()

async def predict_vulnerability(features: Dict[str, float]) -> Dict:
    """
    Call ML API to predict vulnerability risk
    
    Parameters:
        features: Vulnerability features
    
    Returns:
        Prediction result from ML API
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ML_API_URL}/predict/vulnerability",
            json={"features": features},
            timeout=10.0
        )
        response.raise_for_status()
        return response.json()