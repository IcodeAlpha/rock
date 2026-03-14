"""
Secure ML Prediction API
Integrated security: authentication, encryption, validation, logging
"""

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pathlib import Path
import sys

# Add security modules to path
sys.path.insert(0, str(Path(__file__).parent))

from SECURITY_1_api_auth import api_auth, key_manager
from SECURITY_2_model_encryption import SecureModelLoader
from SECURITY_3_model_integrity import ModelIntegrityChecker, ModelIntegrityError
from SECURITY_4_input_validator import SecureIntrusionRequest, InputValidator
from SECURITY_5_audit_logger import audit_logger

# Initialize security components
model_loader = SecureModelLoader()
integrity_checker = ModelIntegrityChecker()
input_validator = InputValidator()

app = FastAPI(
    title="Secure ML Prediction API",
    description="ML predictions with enterprise security",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://localhost:8001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup: Verify model integrity
@app.on_event("startup")
async def startup_event():
    print("\n" + "="*70)
    print("🔒 SECURE ML API STARTING")
    print("="*70)
    
    # Verify all models
    print("\n🔍 Verifying model integrity...")
    try:
        results = integrity_checker.verify_all(raise_on_failure=False)
        
        passed = sum(results.values())
        total = len(results)
        
        if passed == total:
            print(f"   ✅ All {total} models verified")
        else:
            print(f"   ⚠️  {total - passed}/{total} models failed verification")
            print("   Some models may be compromised - review logs!")
    except Exception as e:
        print(f"   ❌ Integrity check error: {e}")
    
    print("\n✅ API Ready")
    print("="*70 + "\n")


@app.get("/")
async def root():
    return {
        "service": "Secure ML Prediction API",
        "version": "2.0.0",
        "security": ["API Key Auth", "Model Encryption", "Integrity Verification", "Input Validation"],
        "endpoints": ["/predict/intrusion", "/predict/phishing", "/security/stats"]
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": audit_logger._create_event("health_check", {})["timestamp"]}


@app.post("/predict/intrusion")
async def predict_intrusion(
    request: Request,
    data: SecureIntrusionRequest,
    auth: dict = Depends(api_auth)
):
    """
    Predict network intrusion
    
    Security layers applied:
    1. API key authentication
    2. Rate limiting
    3. Input validation
    4. Adversarial detection
    5. Model integrity check
    6. Audit logging
    """
    
    # Log request
    audit_logger.log_prediction_request(
        client_ip=request.client.host,
        model="intrusion_detection",
        features=data.features,
        api_key_hash=auth.get("user_id", "unknown"),
        endpoint="/predict/intrusion"
    )
    
    try:
        # Verify model integrity before loading
        model_path = Path("models/saved_models/intrusion_model.pkl")
        if not integrity_checker.verify_model(model_path, raise_on_failure=False):
            audit_logger.log_security_incident(
                incident_type="model_integrity_failure",
                severity="critical",
                details={"model": "intrusion_detection", "client": request.client.host}
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Model integrity check failed - service unavailable"
            )
        
        # Load encrypted model
        model = model_loader.load_model("intrusion_model")
        
        # Validate and predict
        features = data.features
        
        # Check for adversarial patterns
        attack_type = input_validator.detect_adversarial_patterns(
            features,
            client_id=request.client.host
        )
        
        if attack_type:
            audit_logger.log_adversarial_attack(
                client_ip=request.client.host,
                attack_type=attack_type,
                model="intrusion_detection",
                features_sample={k: features[k] for k in list(features.keys())[:5]}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Adversarial pattern detected: {attack_type}"
            )
        
        # Make prediction (simplified - adapt to your model)
        # In production: extract features in correct order, preprocess, predict
        prediction = {
            "prediction": "normal",  # Replace with actual model.predict()
            "confidence": 0.85,
            "model_version": "2.0",
            "timestamp": audit_logger._create_event("prediction", {})["timestamp"]
        }
        
        return prediction
        
    except ModelIntegrityError as e:
        audit_logger.log_security_incident(
            incident_type="model_load_failure",
            severity="critical",
            details={"error": str(e), "model": "intrusion_detection"}
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable due to security issue"
        )
    
    except Exception as e:
        audit_logger.log_security_incident(
            incident_type="prediction_error",
            severity="medium",
            details={"error": str(e), "client": request.client.host}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed"
        )


@app.get("/security/stats")
async def security_stats(
    hours: int = 24,
    auth: dict = Depends(api_auth)
):
    """
    Get security statistics
    
    Requires admin permission
    """
    # Check admin permission
    if "admin" not in auth.get("permissions", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required"
        )
    
    stats = audit_logger.get_statistics(hours)
    return stats


@app.get("/security/report")
async def security_report(
    hours: int = 24,
    auth: dict = Depends(api_auth)
):
    """
    Generate security report
    
    Requires admin permission
    """
    # Check admin permission
    if "admin" not in auth.get("permissions", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required"
        )
    
    report = audit_logger.generate_report(hours)
    return {"report": report}


@app.get("/models/integrity")
async def check_model_integrity(
    auth: dict = Depends(api_auth)
):
    """
    Check integrity of all models
    
    Requires admin permission
    """
    # Check admin permission
    if "admin" not in auth.get("permissions", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required"
        )
    
    status_list = integrity_checker.get_status()
    return {"models": status_list}


if __name__ == "__main__":
    print("\n🔒 Starting Secure ML Prediction API...")
    print("   Port: 8000")
    print("   Documentation: http://localhost:8000/docs")
    print("\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )