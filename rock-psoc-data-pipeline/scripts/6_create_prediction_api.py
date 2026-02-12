"""
Cybersecurity ML Prediction API
Script: 6_create_prediction_api.py

Loads all trained models and launches a FastAPI server exposing:
  POST /predict/intrusion      → Network Intrusion Detection (NSL-KDD)
  POST /predict/phishing       → Phishing URL Detection
  POST /predict/vulnerability  → Vulnerability Risk Score + Severity (CISA KEV)
  GET  /health                 → Health check
  GET  /models                 → Loaded model info

Each endpoint uses the BEST model per task (determined during training).
All preprocessors (scalers, encoders) are loaded automatically.

Usage:
    pip install fastapi uvicorn joblib tensorflow scikit-learn xgboost
    python 6_create_prediction_api.py

    OR just save the predictor without starting the server:
    python 6_create_prediction_api.py --save-only
"""

import os
import sys
import json
import warnings
import argparse
import numpy as np
import joblib
warnings.filterwarnings('ignore')

# ============================================
# 0. ARGUMENT PARSING
# ============================================
parser = argparse.ArgumentParser(description='Cybersecurity ML Prediction API')
parser.add_argument('--save-only', action='store_true',
                    help='Save predictor.pkl only, do not start server')
parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
parser.add_argument('--port', type=int, default=8000, help='Port to bind (default: 8000)')
parser.add_argument('--reload', action='store_true', help='Enable auto-reload (dev mode)')
args = parser.parse_args()

print("=" * 70)
print("CYBERSECURITY ML PREDICTION API")
print("=" * 70)

# ============================================
# 1. LOAD ALL SAVED MODELS & PREPROCESSORS
# ============================================
print("\n[1/3] Loading trained models and preprocessors...")

BASE_MODELS   = "models/saved_models"
BASE_PREP     = "models/preprocessors"
BASE_EVAL     = "models/evaluation"

# ── helpers ──────────────────────────────────────────────────────────────────

def load_pkl(path, label):
    """Load a joblib pickle. Returns None and warns if missing."""
    if os.path.exists(path):
        obj = joblib.load(path)
        print(f"   ✅ Loaded: {label}")
        return obj
    print(f"   ⚠️  Missing: {label}  ({path})")
    return None


def load_keras(path, label):
    """Load a Keras/TF model. Returns None and warns if missing."""
    if not os.path.exists(path):
        print(f"   ⚠️  Missing: {label}  ({path})")
        return None
    try:
        import tensorflow as tf
        model = tf.keras.models.load_model(path)
        print(f"   ✅ Loaded: {label}")
        return model
    except Exception as e:
        print(f"   ⚠️  Failed to load {label}: {str(e)[:60]}")
        return None


def load_json(path, label):
    """Load a JSON file. Returns None and warns if missing."""
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        print(f"   ✅ Loaded: {label}")
        return data
    print(f"   ⚠️  Missing: {label}  ({path})")
    return None


def best_model_name(task_key):
    """
    Read the master evaluation report and return the name of the best model
    for a given task key ('Intrusion Detection', 'Phishing Detection',
    'Vulnerability Scoring').
    Returns None if report is unavailable.
    """
    report_path = os.path.join(BASE_EVAL, "master_evaluation_report.json")
    if not os.path.exists(report_path):
        return None
    with open(report_path) as f:
        report = json.load(f)
    detailed = report.get("detailed_metrics", {})
    task_data = detailed.get(task_key, {})
    return task_data.get("best_model") or task_data.get("best_classification_model")


def load_best_model(task_dir, task_key, keras_fallback=True):
    """
    Try to load best_model.pkl, then best_model.h5.
    Returns (model, model_type_str).
    """
    pkl_path = os.path.join(BASE_MODELS, task_dir, "best_model.pkl")
    h5_path  = os.path.join(BASE_MODELS, task_dir, "best_model.h5")

    if os.path.exists(pkl_path):
        model = load_pkl(pkl_path, f"{task_key} best model (pkl)")
        return model, "sklearn"
    if keras_fallback and os.path.exists(h5_path):
        model = load_keras(h5_path, f"{task_key} best model (h5)")
        return model, "keras"
    print(f"   ⚠️  No best model found for {task_key}")
    return None, None

# ── Intrusion Detection ───────────────────────────────────────────────────────
print("\n   --- Intrusion Detection ---")
intrusion_model, intrusion_model_type = load_best_model(
    "intrusion_detection", "Intrusion Detection")
intrusion_scaler  = load_pkl(
    os.path.join(BASE_PREP, "intrusion_scaler.pkl"), "intrusion scaler")
intrusion_le      = load_pkl(
    os.path.join(BASE_PREP, "intrusion_label_encoder.pkl"), "intrusion label encoder")
intrusion_features = load_json(
    os.path.join(BASE_PREP, "intrusion_feature_names.json"), "intrusion feature names")

# ── Phishing Detection ────────────────────────────────────────────────────────
print("\n   --- Phishing Detection ---")
phishing_model, phishing_model_type = load_best_model(
    "phishing_detection", "Phishing Detection")
phishing_scaler  = load_pkl(
    os.path.join(BASE_PREP, "phishing_scaler.pkl"), "phishing scaler")
phishing_features = load_json(
    os.path.join(BASE_PREP, "phishing_feature_names.json"), "phishing feature names")

# ── Vulnerability Scoring ─────────────────────────────────────────────────────
print("\n   --- Vulnerability Scoring ---")
# Best regression model
vuln_reg_path_pkl = os.path.join(BASE_MODELS, "vulnerability_scoring", "rf_regressor.pkl")
vuln_reg_path_xgb = os.path.join(BASE_MODELS, "vulnerability_scoring", "xgb_regressor.pkl")
vuln_reg_path_h5  = os.path.join(BASE_MODELS, "vulnerability_scoring", "nn_regressor.h5")

# Best classification model
vuln_clf_path_pkl = os.path.join(BASE_MODELS, "vulnerability_scoring", "rf_classifier.pkl")
vuln_clf_path_xgb = os.path.join(BASE_MODELS, "vulnerability_scoring", "xgb_classifier.pkl")
vuln_clf_path_h5  = os.path.join(BASE_MODELS, "vulnerability_scoring", "nn_classifier.h5")

def _pick_vuln_model(pkl, xgb_path, h5, label):
    """Load the vulnerability model that exists, preferring pkl > h5."""
    if os.path.exists(pkl):
        return load_pkl(pkl, label), "sklearn"
    if os.path.exists(xgb_path):
        return load_pkl(xgb_path, label + " (xgb)"), "sklearn"
    return load_keras(h5, label + " (keras)"), "keras"

vuln_reg_model, vuln_reg_type = _pick_vuln_model(
    vuln_reg_path_pkl, vuln_reg_path_xgb, vuln_reg_path_h5, "vuln regressor")
vuln_clf_model, vuln_clf_type = _pick_vuln_model(
    vuln_clf_path_pkl, vuln_clf_path_xgb, vuln_clf_path_h5, "vuln classifier")

vuln_scaler   = load_pkl(
    os.path.join(BASE_PREP, "vulnerability_scaler.pkl"), "vulnerability scaler")
vuln_sev_enc  = load_pkl(
    os.path.join(BASE_PREP, "severity_encoder.pkl"), "severity encoder")
vuln_features = load_json(
    os.path.join(BASE_PREP, "vulnerability_feature_names.json"), "vulnerability feature names")

print("\n✅ Model loading complete")

# ============================================
# 2. BUILD PREDICTOR CLASS
# ============================================
print("\n[2/3] Building predictor class...")

class CyberSecurityPredictor:
    """
    Unified predictor for all three cybersecurity ML tasks.
    Wraps best models + preprocessors for each task.
    """

    def __init__(self):
        # Intrusion Detection
        self.intrusion_model    = intrusion_model
        self.intrusion_type     = intrusion_model_type
        self.intrusion_scaler   = intrusion_scaler
        self.intrusion_le       = intrusion_le
        self.intrusion_features = intrusion_features or []

        # Phishing Detection
        self.phishing_model     = phishing_model
        self.phishing_type      = phishing_model_type
        self.phishing_scaler    = phishing_scaler
        self.phishing_features  = phishing_features or []

        # Vulnerability Scoring
        self.vuln_reg_model     = vuln_reg_model
        self.vuln_reg_type      = vuln_reg_type
        self.vuln_clf_model     = vuln_clf_model
        self.vuln_clf_type      = vuln_clf_type
        self.vuln_scaler        = vuln_scaler
        self.vuln_sev_enc       = vuln_sev_enc
        self.vuln_features      = vuln_features or []

    # ── internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _to_array(features: dict, feature_names: list) -> np.ndarray:
        """
        Build a 2-D numpy array from a feature dict, filling 0 for missing keys.
        """
        row = [float(features.get(f, 0)) for f in feature_names]
        return np.array(row).reshape(1, -1)

    @staticmethod
    def _sklearn_predict(model, X_scaled):
        pred   = int(model.predict(X_scaled)[0])
        proba  = model.predict_proba(X_scaled)[0]
        conf   = float(np.max(proba))
        return pred, conf, proba.tolist()

    @staticmethod
    def _keras_predict_clf(model, X_scaled):
        proba  = model.predict(X_scaled, verbose=0)[0]
        pred   = int(np.argmax(proba))
        conf   = float(np.max(proba))
        return pred, conf, proba.tolist()

    @staticmethod
    def _keras_predict_binary(model, X_scaled):
        prob   = float(model.predict(X_scaled, verbose=0)[0][0])
        pred   = int(prob > 0.5)
        conf   = prob if pred == 1 else 1 - prob
        return pred, conf, [1 - prob, prob]

    # ── public predict methods ─────────────────────────────────────────────────

    def predict_intrusion(self, features: dict) -> dict:
        """
        Predict network attack type from NSL-KDD style features.

        Parameters
        ----------
        features : dict
            Feature name → numeric value pairs.
            Any missing feature defaults to 0.
            Automatically remaps raw NSL-KDD names to ind_ prefix.

        Returns
        -------
        dict with keys:
            attack_type (str), attack_index (int),
            confidence (float), probabilities (list[float]),
            all_classes (list[str])
        """
        if self.intrusion_model is None:
            return {"error": "Intrusion detection model not loaded"}

        # Auto-remap: if user sends "src_bytes" but model expects "ind_src_bytes", fix it
        remapped_features = {}
        for key, value in features.items():
            # If key doesn't start with ind_ and ind_{key} exists in trained features, remap it
            if not key.startswith('ind_') and f'ind_{key}' in self.intrusion_features:
                remapped_features[f'ind_{key}'] = value
            else:
                remapped_features[key] = value
        
        X = self._to_array(remapped_features, self.intrusion_features)
        if self.intrusion_scaler:
            X = self.intrusion_scaler.transform(X)

        if self.intrusion_type == "sklearn":
            pred, conf, proba = self._sklearn_predict(self.intrusion_model, X)
        else:
            pred, conf, proba = self._keras_predict_clf(self.intrusion_model, X)

        label = (self.intrusion_le.inverse_transform([pred])[0]
                 if self.intrusion_le else str(pred))
        classes = (list(self.intrusion_le.classes_)
                   if self.intrusion_le else [])

        severity_map = {
            "DDoS Attack": "high",
            "Port Scan": "medium",
            "Other Attack": "medium",
        }
        severity = severity_map.get(label, "unknown")

        return {
            "attack_type":   label,
            "attack_index":  pred,
            "severity":      severity,
            "confidence":    round(conf, 4),
            "probabilities": [round(p, 4) for p in proba],
            "all_classes":   classes,
        }

    def predict_phishing(self, features: dict) -> dict:
        """
        Predict whether a URL is phishing or legitimate.

        Parameters
        ----------
        features : dict
            URL feature name → numeric value pairs.

        Returns
        -------
        dict with keys:
            label (str), is_phishing (bool),
            confidence (float), phishing_probability (float)
        """
        if self.phishing_model is None:
            return {"error": "Phishing detection model not loaded"}

        X = self._to_array(features, self.phishing_features)
        if self.phishing_scaler:
            X = self.phishing_scaler.transform(X)

        if self.phishing_type == "keras":
            pred, conf, proba = self._keras_predict_binary(self.phishing_model, X)
        else:
            pred, conf, proba = self._sklearn_predict(self.phishing_model, X)

        label = "Phishing" if pred == 1 else "Legitimate"
        phishing_prob = proba[1] if len(proba) > 1 else (conf if pred == 1 else 1 - conf)

        return {
            "label":               label,
            "is_phishing":         bool(pred == 1),
            "confidence":          round(conf, 4),
            "phishing_probability": round(float(phishing_prob), 4),
        }

    def predict_vulnerability(self, features: dict) -> dict:
        """
        Predict vulnerability risk score (0-100) and severity (Low/Med/High).

        Parameters
        ----------
        features : dict
            CISA KEV feature name → numeric value pairs.

        Returns
        -------
        dict with keys:
            risk_score (float), severity (str),
            severity_index (int), confidence (float)
        """
        result = {}

        X = self._to_array(features, self.vuln_features)
        if self.vuln_scaler:
            X = self.vuln_scaler.transform(X)

        # Regression: risk score
        if self.vuln_reg_model is not None:
            if self.vuln_reg_type == "keras":
                score = float(self.vuln_reg_model.predict(X, verbose=0)[0][0])
            else:
                score = float(self.vuln_reg_model.predict(X)[0])
            result["risk_score"] = round(float(np.clip(score, 0, 100)), 2)
        else:
            result["risk_score"] = None
            result["error_regression"] = "Regression model not loaded"

        # Classification: severity
        if self.vuln_clf_model is not None:
            if self.vuln_clf_type == "keras":
                pred, conf, proba = self._keras_predict_clf(self.vuln_clf_model, X)
            else:
                pred, conf, proba = self._sklearn_predict(self.vuln_clf_model, X)

            label = (self.vuln_sev_enc.inverse_transform([pred])[0]
                     if self.vuln_sev_enc else str(pred))
            result["severity"]       = label
            result["severity_index"] = pred
            result["confidence"]     = round(conf, 4)
        else:
            result["severity"] = None
            result["error_classification"] = "Classification model not loaded"

        return result

    def model_status(self) -> dict:
        """Return a summary of which models are loaded."""
        return {
            "intrusion_detection": {
                "loaded": self.intrusion_model is not None,
                "type":   self.intrusion_type,
                "classes": (list(self.intrusion_le.classes_)
                            if self.intrusion_le else []),
            },
            "phishing_detection": {
                "loaded": self.phishing_model is not None,
                "type":   self.phishing_type,
            },
            "vulnerability_scoring": {
                "regressor_loaded":  self.vuln_reg_model is not None,
                "classifier_loaded": self.vuln_clf_model is not None,
                "severity_classes": (list(self.vuln_sev_enc.classes_)
                                     if self.vuln_sev_enc else []),
            },
        }


predictor = CyberSecurityPredictor()
print("✅ CyberSecurityPredictor instantiated")

# ── Quick smoke tests ──────────────────────────────────────────────────────────
print("\n   Running smoke tests...")

print("\n   [TEST 1] Intrusion Detection — normal traffic")
r1 = predictor.predict_intrusion({})
if "error" not in r1:
    print(f"   Prediction:  {r1['attack_type']}")
    print(f"   Severity:    {r1['severity']}")
    print(f"   Confidence:  {r1['confidence']}")
else:
    print(f"   ⚠️  {r1['error']}")

print("\n   [TEST 2] Phishing Detection — all-zero features (baseline)")
r2 = predictor.predict_phishing({})
if "error" not in r2:
    print(f"   Prediction:           {r2['label']}")
    print(f"   Phishing probability: {r2['phishing_probability']}")
    print(f"   Confidence:           {r2['confidence']}")
else:
    print(f"   ⚠️  {r2['error']}")

print("\n   [TEST 3] Vulnerability Scoring — baseline")
r3 = predictor.predict_vulnerability({})
if "risk_score" in r3:
    print(f"   Risk Score:  {r3.get('risk_score')}")
    print(f"   Severity:    {r3.get('severity')}")
    print(f"   Confidence:  {r3.get('confidence')}")

# ── Save predictor ─────────────────────────────────────────────────────────────
os.makedirs("models", exist_ok=True)
joblib.dump(predictor, "models/predictor.pkl")
print("\n✅ Saved predictor instance → models/predictor.pkl")

# ============================================
# 3. BUILD FASTAPI APP
# ============================================
print("\n[3/3] Building FastAPI application...")

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    from typing import Optional, Dict, Any
    import uvicorn
except ImportError:
    print("❌ FastAPI / uvicorn not installed.")
    print("   Run:  pip install fastapi uvicorn")
    if args.save_only:
        print("✅ Predictor saved. Exiting (--save-only mode).")
        sys.exit(0)
    sys.exit(1)

app = FastAPI(
    title="Cybersecurity ML Prediction API",
    description=(
        "Predict network intrusions, phishing URLs, and vulnerability risk scores "
        "using trained ML models (Random Forest / XGBoost / Neural Network)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic schemas ───────────────────────────────────────────────────────────

class FeaturesRequest(BaseModel):
    features: Dict[str, float] = Field(
        default={},
        description="Feature name → numeric value. Missing features default to 0.",
        example={
            "duration": 0.0,
            "src_bytes": 491,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
        },
    )
    model_override: Optional[str] = Field(
        default=None,
        description="Unused (best model is always used). Reserved for future use.",
    )

class IntrusionRequest(FeaturesRequest):
    pass

class PhishingRequest(FeaturesRequest):
    pass

class VulnerabilityRequest(FeaturesRequest):
    pass

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Status"])
def health():
    """API health check."""
    return {
        "status": "ok",
        "models_loaded": {
            k: v.get("loaded", v.get("regressor_loaded", False))
            for k, v in predictor.model_status().items()
        },
    }


@app.get("/models", tags=["Status"])
def models_info():
    """Detailed info on all loaded models and their status."""
    return predictor.model_status()


@app.post("/predict/intrusion", tags=["Prediction"])
def predict_intrusion(req: IntrusionRequest):
    """
    **Network Intrusion Detection** (NSL-KDD)

    Send NSL-KDD style numeric features and receive:
    - `attack_type` — e.g. *Normal*, *DoS*, *Probe*, *R2L*, *U2R*
    - `severity` — `none | low | medium | high | critical`
    - `confidence` — model confidence 0 → 1
    - `probabilities` — per-class probability list

    **Example features:** `duration`, `src_bytes`, `dst_bytes`,
    `land`, `wrong_fragment`, `urgent`, `hot`, `num_failed_logins`, …
    """
    if predictor.intrusion_model is None:
        raise HTTPException(
            status_code=503,
            detail="Intrusion detection model not loaded. Run training scripts first.",
        )
    result = predictor.predict_intrusion(req.features)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@app.post("/predict/phishing", tags=["Prediction"])
def predict_phishing(req: PhishingRequest):
    """
    **Phishing URL Detection**

    Send URL-derived numeric features and receive:
    - `label` — *Phishing* or *Legitimate*
    - `is_phishing` — boolean flag
    - `phishing_probability` — probability of being phishing (0 → 1)
    - `confidence` — model confidence 0 → 1

    **Example features:** `url_length`, `num_dots`, `has_ip`,
    `has_at_symbol`, `num_subdomains`, `has_https`, …
    """
    if predictor.phishing_model is None:
        raise HTTPException(
            status_code=503,
            detail="Phishing detection model not loaded. Run training scripts first.",
        )
    result = predictor.predict_phishing(req.features)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@app.post("/predict/vulnerability", tags=["Prediction"])
def predict_vulnerability(req: VulnerabilityRequest):
    """
    **Vulnerability Risk Scoring** (CISA KEV)

    Send CISA KEV derived features and receive:
    - `risk_score` — numeric risk score 0 → 100
    - `severity` — *Low*, *Medium*, or *High*
    - `confidence` — classification model confidence 0 → 1

    **Example features:** `days_since_added`, `is_ransomware`,
    `has_due_date`, `days_until_due`, `vendor_encoded`, …
    """
    result = predictor.predict_vulnerability(req.features)
    return result


@app.post("/predict/all", tags=["Prediction"])
def predict_all(req: FeaturesRequest):
    """
    **Run all three models** on the same feature dict.

    Useful for testing or when features overlap across tasks.
    Returns a combined response with results from all three endpoints.
    """
    return {
        "intrusion":    predictor.predict_intrusion(req.features),
        "phishing":     predictor.predict_phishing(req.features),
        "vulnerability": predictor.predict_vulnerability(req.features),
    }


# ── Startup banner ─────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_banner():
    status = predictor.model_status()
    print("\n" + "=" * 70)
    print("🚀 CYBERSECURITY ML API IS RUNNING")
    print("=" * 70)
    print(f"   Docs:       http://localhost:{args.port}/docs")
    print(f"   Health:     http://localhost:{args.port}/health")
    print(f"   Models:     http://localhost:{args.port}/models")
    print()
    for task, info in status.items():
        loaded = info.get("loaded", info.get("regressor_loaded", False))
        icon = "✅" if loaded else "⚠️ "
        print(f"   {icon}  {task.replace('_', ' ').title()}")
    print("=" * 70 + "\n")


# ============================================
# ENTRY POINT
# ============================================
print("✅ FastAPI app built")
print("\n" + "=" * 70)
print("SETUP COMPLETE")
print("=" * 70)

print("""
📁 Generated files:
   ✅ models/predictor.pkl          — Production-ready predictor instance

🌐 API Endpoints:
   GET  /health                     — Health check
   GET  /models                     — Loaded model info
   POST /predict/intrusion          — Network Intrusion Detection
   POST /predict/phishing           — Phishing URL Detection
   POST /predict/vulnerability      — Vulnerability Risk Scoring
   POST /predict/all                — All three models at once

📖 Interactive Docs (once running):
   http://localhost:8000/docs       — Swagger UI
   http://localhost:8000/redoc      — ReDoc
""")

if args.save_only:
    print("✅ --save-only flag set. Predictor saved. Not starting server.")
    sys.exit(0)

print(f"Starting server on http://{args.host}:{args.port} ...")
print("   (Press CTRL+C to stop)\n")

uvicorn.run(
    app,
    host=args.host,
    port=args.port,
    reload=args.reload,
    log_level="info",
)