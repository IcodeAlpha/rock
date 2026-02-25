"""
Cybersecurity ML Prediction API
Updated to use UNSW-NB15 v2 models with multi-class attack detection
"""

import os
import sys
import json
import pickle
import joblib
import warnings
import argparse
import numpy as np
warnings.filterwarnings('ignore')

parser = argparse.ArgumentParser()
parser.add_argument('--save-only', action='store_true')
parser.add_argument('--host', default='0.0.0.0')
parser.add_argument('--port', type=int, default=8000)
parser.add_argument('--reload', action='store_true')
args = parser.parse_args()

print("=" * 70)
print("CYBERSECURITY ML PREDICTION API")
print("=" * 70)

BASE_MODELS = "models/saved_models"

def load_pkl(path, label):
    """Load pickle file, falling back to joblib if needed."""
    if os.path.exists(path):
        # Try standard pickle first
        try:
            with open(path, 'rb') as f:
                obj = pickle.load(f)
            print(f"   ✅ Loaded: {label}")
            return obj
        except Exception:
            pass
        # Fall back to joblib
        try:
            obj = joblib.load(path)
            print(f"   ✅ Loaded: {label} (joblib)")
            return obj
        except Exception as e:
            print(f"   ⚠️  Failed to load: {label} ({e})")
            return None
    print(f"   ⚠️  Missing: {label}  ({path})")
    return None

# ── Load v2 intrusion model (UNSW-NB15 multi-class) ──────────────────────────
print("\n   --- Intrusion Detection (UNSW-NB15 v2) ---")
intrusion_model    = load_pkl(f"{BASE_MODELS}/intrusion_model.pkl", "intrusion model")
intrusion_le       = load_pkl(f"{BASE_MODELS}/intrusion_label_encoder.pkl", "intrusion label encoder")
intrusion_features = load_pkl(f"{BASE_MODELS}/intrusion_features.pkl", "intrusion features")

# ── Load phishing model ───────────────────────────────────────────────────────
print("\n   --- Phishing Detection ---")
phishing_model    = load_pkl(f"{BASE_MODELS}/phishing_detection/best_model.pkl", "phishing model")
phishing_scaler   = None
phishing_features = []

if os.path.exists("models/preprocessors/phishing_scaler.pkl"):
    phishing_scaler = load_pkl("models/preprocessors/phishing_scaler.pkl", "phishing scaler")
if os.path.exists("models/preprocessors/phishing_feature_names.json"):
    with open("models/preprocessors/phishing_feature_names.json") as f:
        phishing_features = json.load(f)
    print(f"   ✅ Loaded: phishing feature names")

# ── Load vulnerability model ──────────────────────────────────────────────────
print("\n   --- Vulnerability Scoring ---")
vuln_reg_model  = load_pkl(f"{BASE_MODELS}/vulnerability_scoring/rf_regressor.pkl", "vuln regressor")
vuln_clf_model  = load_pkl(f"{BASE_MODELS}/vulnerability_scoring/rf_classifier.pkl", "vuln classifier")
vuln_scaler     = load_pkl("models/preprocessors/vulnerability_scaler.pkl", "vuln scaler")
vuln_sev_enc    = load_pkl("models/preprocessors/severity_encoder.pkl", "severity encoder")
vuln_features   = []
if os.path.exists("models/preprocessors/vulnerability_feature_names.json"):
    with open("models/preprocessors/vulnerability_feature_names.json") as f:
        vuln_features = json.load(f)

print("\n✅ Model loading complete")

# ── Severity mapping for UNSW-NB15 attack types ───────────────────────────────
SEVERITY_MAP = {
    "Normal":          "none",
    "Generic":         "high",
    "Exploits":        "critical",
    "Fuzzers":         "medium",
    "DoS":             "high",
    "Reconnaissance":  "medium",
    "Analysis":        "low",
    "Backdoor":        "critical",
    "Shellcode":       "critical",
    "Worms":           "critical",
    "attack":          "high",
    "normal":          "none",
}

# ============================================
# PREDICTOR CLASS
# ============================================
class CyberSecurityPredictor:

    def __init__(self):
        self.intrusion_model    = intrusion_model
        self.intrusion_le       = intrusion_le
        self.intrusion_features = intrusion_features or []
        self.phishing_model     = phishing_model
        self.phishing_scaler    = phishing_scaler
        self.phishing_features  = phishing_features or []
        self.vuln_reg_model     = vuln_reg_model
        self.vuln_clf_model     = vuln_clf_model
        self.vuln_scaler        = vuln_scaler
        self.vuln_sev_enc       = vuln_sev_enc
        self.vuln_features      = vuln_features or []

    @staticmethod
    def _to_array(features: dict, feature_names: list) -> np.ndarray:
        row = [float(features.get(f, 0)) for f in feature_names]
        return np.array(row).reshape(1, -1)

    def predict_intrusion(self, features: dict) -> dict:
        if self.intrusion_model is None:
            return {"error": "Intrusion detection model not loaded"}
        if not self.intrusion_features:
            return {"error": "Intrusion feature names not loaded"}

        X = self._to_array(features, self.intrusion_features)
        pred  = int(self.intrusion_model.predict(X)[0])
        proba = self.intrusion_model.predict_proba(X)[0]
        conf  = float(np.max(proba))

        label   = self.intrusion_le.inverse_transform([pred])[0] if self.intrusion_le else str(pred)
        classes = list(self.intrusion_le.classes_) if self.intrusion_le else []
        severity = SEVERITY_MAP.get(label, "medium")

        return {
            "attack_type":   label,
            "attack_index":  pred,
            "severity":      severity,
            "confidence":    round(conf, 4),
            "probabilities": [round(p, 4) for p in proba],
            "all_classes":   classes,
        }

    def predict_phishing(self, features: dict) -> dict:
        if self.phishing_model is None:
            return {"error": "Phishing detection model not loaded"}

        X = self._to_array(features, self.phishing_features)
        if self.phishing_scaler:
            X = self.phishing_scaler.transform(X)

        pred  = int(self.phishing_model.predict(X)[0])
        proba = self.phishing_model.predict_proba(X)[0]
        conf  = float(np.max(proba))
        label = "Phishing" if pred == 1 else "Legitimate"
        phishing_prob = proba[1] if len(proba) > 1 else conf

        return {
            "label":                label,
            "is_phishing":          bool(pred == 1),
            "confidence":           round(conf, 4),
            "phishing_probability": round(float(phishing_prob), 4),
        }

    def predict_vulnerability(self, features: dict) -> dict:
        result = {}
        X = self._to_array(features, self.vuln_features)
        if self.vuln_scaler:
            X = self.vuln_scaler.transform(X)

        if self.vuln_reg_model is not None:
            score = float(self.vuln_reg_model.predict(X)[0])
            result["risk_score"] = round(float(np.clip(score, 0, 100)), 2)
        else:
            result["risk_score"] = None

        if self.vuln_clf_model is not None:
            pred  = int(self.vuln_clf_model.predict(X)[0])
            proba = self.vuln_clf_model.predict_proba(X)[0]
            conf  = float(np.max(proba))
            label = self.vuln_sev_enc.inverse_transform([pred])[0] if self.vuln_sev_enc else str(pred)
            result["severity"]       = label
            result["severity_index"] = pred
            result["confidence"]     = round(conf, 4)
        else:
            result["severity"] = None

        return result

    def model_status(self) -> dict:
        return {
            "intrusion_detection": {
                "loaded":   self.intrusion_model is not None,
                "classes":  list(self.intrusion_le.classes_) if self.intrusion_le else [],
                "features": len(self.intrusion_features),
            },
            "phishing_detection": {
                "loaded": self.phishing_model is not None,
            },
            "vulnerability_scoring": {
                "regressor_loaded":  self.vuln_reg_model is not None,
                "classifier_loaded": self.vuln_clf_model is not None,
            },
        }


predictor = CyberSecurityPredictor()
print("✅ CyberSecurityPredictor instantiated")

# Smoke test
print("\n   Running smoke test...")
r1 = predictor.predict_intrusion({})
if "error" not in r1:
    print(f"   Intrusion test — attack_type: {r1['attack_type']}, classes: {r1['all_classes']}")
else:
    print(f"   ⚠️  {r1['error']}")

os.makedirs("models", exist_ok=True)
with open("models/predictor.pkl", "wb") as f:
    pickle.dump(predictor, f)
print("✅ Saved predictor → models/predictor.pkl")

# ============================================
# FASTAPI APP
# ============================================
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    from typing import Dict
    import uvicorn
except ImportError:
    print("❌ FastAPI not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)

app = FastAPI(
    title="Cybersecurity ML Prediction API",
    description="Predict network intrusions, phishing URLs, and vulnerability risk scores.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IntrusionRequest(BaseModel):
    features: Dict[str, float] = Field(default={})

class PhishingRequest(BaseModel):
    features: Dict[str, float] = Field(default={})

class VulnerabilityRequest(BaseModel):
    features: Dict[str, float] = Field(default={})

@app.get("/health", tags=["Status"])
def health():
    return {"status": "ok", "models_loaded": predictor.model_status()}

@app.get("/models", tags=["Status"])
def models_info():
    return predictor.model_status()

@app.post("/predict/intrusion", tags=["Prediction"])
def predict_intrusion(req: IntrusionRequest):
    """
    **Network Intrusion Detection** (UNSW-NB15)

    Send UNSW-NB15 style numeric features and receive:
    - `attack_type` — Normal, DoS, Exploits, Fuzzers, Reconnaissance, Backdoor, Shellcode, Worms, Generic, Analysis
    - `severity` — `none | low | medium | high | critical`
    - `confidence` — model confidence 0 → 1
    - `probabilities` — per-class probability list

    **Example features:** `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sttl`, `dttl`, `sload`, `dload` …
    """
    if predictor.intrusion_model is None:
        raise HTTPException(status_code=503, detail="Intrusion model not loaded")
    result = predictor.predict_intrusion(req.features)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result

@app.post("/predict/phishing", tags=["Prediction"])
def predict_phishing(req: PhishingRequest):
    """**Phishing URL Detection**"""
    if predictor.phishing_model is None:
        raise HTTPException(status_code=503, detail="Phishing model not loaded")
    result = predictor.predict_phishing(req.features)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result

@app.post("/predict/vulnerability", tags=["Prediction"])
def predict_vulnerability(req: VulnerabilityRequest):
    """**Vulnerability Risk Scoring** (CISA KEV)"""
    return predictor.predict_vulnerability(req.features)

@app.post("/predict/all", tags=["Prediction"])
def predict_all(req: IntrusionRequest):
    """Run all three models on the same feature dict."""
    return {
        "intrusion":     predictor.predict_intrusion(req.features),
        "phishing":      predictor.predict_phishing(req.features),
        "vulnerability": predictor.predict_vulnerability(req.features),
    }

@app.on_event("startup")
async def startup_banner():
    status = predictor.model_status()
    print("\n" + "=" * 70)
    print("🚀 CYBERSECURITY ML API IS RUNNING")
    print("=" * 70)
    print(f"   Docs:   http://localhost:{args.port}/docs")
    print(f"   Health: http://localhost:{args.port}/health")
    print(f"   Intrusion classes: {status['intrusion_detection'].get('classes', [])}")
    print("=" * 70 + "\n")

if args.save_only:
    print("✅ --save-only. Exiting.")
    sys.exit(0)

print(f"\nStarting server on http://{args.host}:{args.port} ...")
uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, log_level="info")