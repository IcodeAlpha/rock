"""
Train Threat Detection Models — Ransomware, Malware, Credential Attacks
Mirrors the style of 4_train_intrusion_detection.py in this project.

Trains Random Forest, XGBoost, and Neural Network classifiers on the
processed threat dataset and saves the best model for API serving.

Usage:
    python scripts/train_threat_models.py
"""

import json
import os
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection  import train_test_split
from sklearn.ensemble         import RandomForestClassifier
from sklearn.preprocessing    import LabelEncoder, StandardScaler
from sklearn.metrics          import (
    accuracy_score, f1_score, precision_score,
    recall_score, confusion_matrix, classification_report
)
from imblearn.over_sampling   import SMOTE
from xgboost                  import XGBClassifier
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.parent
PROCESSED_DIR = BASE_DIR / 'data' / 'processed'
MODEL_DIR     = BASE_DIR / 'models' / 'saved_models'  / 'threat_detection'
PREP_DIR      = BASE_DIR / 'models' / 'preprocessors'
EVAL_DIR      = BASE_DIR / 'models' / 'evaluation'

for d in (MODEL_DIR, PREP_DIR, EVAL_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ─── Helpers ─────────────────────────────────────────────────────────────────
def print_header(text):
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}\n")

def print_ok(text):   print(f"   ✅ {text}")
def print_warn(text): print(f"   ⚠️  {text}")
def print_err(text):  print(f"   ❌ {text}")
def print_info(text): print(f"   ℹ️  {text}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. LOAD PROCESSED DATA
# ─────────────────────────────────────────────────────────────────────────────
print_header("1/7  LOADING PROCESSED THREAT DATA")

data_path = PROCESSED_DIR / 'threat_predictions.json'
if not data_path.exists():
    print_err(f"File not found: {data_path}")
    print("   Run process_threat_datasets.py first.")
    raise SystemExit(1)

with open(data_path) as f:
    data = json.load(f)

print_ok(f"Loaded {len(data):,} threat records")


# ─────────────────────────────────────────────────────────────────────────────
# 2. FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
print_header("2/7  EXTRACTING FEATURES")

rows = []
for rec in data:
    indicators = rec.get('indicators', {})
    row = {
        'severity':        rec.get('severity',         'medium'),
        'probability':     rec.get('probability',       0.5),
        'confidence_score': rec.get('confidence_score', 0.5),
    }
    if isinstance(indicators, dict):
        for k, v in indicators.items():
            if isinstance(v, (int, float)):
                row[f'ind_{k}'] = v
            elif isinstance(v, bool):
                row[f'ind_{k}'] = int(v)
            elif isinstance(v, str):
                row[f'ind_{k}'] = hash(v) % 1000
    row['threat_type'] = rec.get('threat_type', 'Unknown')
    rows.append(row)

df = pd.DataFrame(rows)
print_ok(f"Feature matrix: {df.shape[0]} samples × {df.shape[1] - 1} features")


# ─────────────────────────────────────────────────────────────────────────────
# 3. HANDLE CLASS IMBALANCE — MERGE RARE CLASSES
# ─────────────────────────────────────────────────────────────────────────────
print_header("3/7  CLASS BALANCE CHECK")

counts = df['threat_type'].value_counts()
print(f"   Class distribution:\n{counts.to_string()}\n")

MIN_SAMPLES = 10
rare = counts[counts < MIN_SAMPLES].index.tolist()
if rare:
    print_warn(f"Combining {len(rare)} rare class(es) → 'Other Threat': {rare}")
    df['threat_type'] = df['threat_type'].replace({c: 'Other Threat' for c in rare})
    print_info(f"Updated distribution:\n{df['threat_type'].value_counts().to_string()}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. ENCODE + SCALE
# ─────────────────────────────────────────────────────────────────────────────
print_header("4/7  ENCODING LABELS & SCALING FEATURES")

X = df.drop('threat_type', axis=1)
y = df['threat_type']

# Encode categoricals
for col in X.select_dtypes(include='object').columns:
    le_col = LabelEncoder()
    X[col] = le_col.fit_transform(X[col].astype(str))

X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

le = LabelEncoder()
y_enc = le.fit_transform(y)
num_classes = len(le.classes_)
print_ok(f"Classes ({num_classes}): {list(le.classes_)}")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print_ok(f"Features scaled — shape: {X_scaled.shape}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. SMOTE
# ─────────────────────────────────────────────────────────────────────────────
print_header("5/7  SMOTE OVERSAMPLING")

min_n = pd.Series(y_enc).value_counts().min()
if min_n >= 6:
    k = min(5, min_n - 1)
    sm = SMOTE(random_state=42, k_neighbors=k)
    X_res, y_res = sm.fit_resample(X_scaled, y_enc)
    print_ok(f"SMOTE applied (k={k}) — {X_scaled.shape[0]} → {X_res.shape[0]} samples")
else:
    print_warn(f"Too few samples (min={min_n}) for SMOTE — skipping")
    X_res, y_res = X_scaled, y_enc


# ─────────────────────────────────────────────────────────────────────────────
# 6. TRAIN / TEST SPLIT
# ─────────────────────────────────────────────────────────────────────────────
print_header("6/7  TRAIN / TEST SPLIT")

min_cls = pd.Series(y_res).value_counts().min()
stratify = y_res if min_cls >= 2 else None

X_train, X_test, y_train, y_test = train_test_split(
    X_res, y_res, test_size=0.2, random_state=42, stratify=stratify
)

min_train = pd.Series(y_train).value_counts().min()
X_tr_nn, X_val_nn, y_tr_nn, y_val_nn = train_test_split(
    X_train, y_train, test_size=0.2, random_state=42,
    stratify=y_train if min_train >= 2 else None
)

print_ok(f"Train: {len(X_train):,}  Test: {len(X_test):,}  Val (NN): {len(X_val_nn):,}")


# ─────────────────────────────────────────────────────────────────────────────
# 7. TRAIN MODELS
# ─────────────────────────────────────────────────────────────────────────────
results = {}

# ── Random Forest ─────────────────────────────────────────────────────────────
print_header("MODEL 1 — RANDOM FOREST")

rf = RandomForestClassifier(
    n_estimators=200, max_depth=20, min_samples_split=2,
    min_samples_leaf=1, random_state=42,
    class_weight='balanced', n_jobs=-1
)
print("   Training Random Forest (200 trees)...")
rf.fit(X_train, y_train)

rf_pred = rf.predict(X_test)
results['Random Forest'] = {
    'accuracy':  accuracy_score(y_test, rf_pred),
    'precision': precision_score(y_test, rf_pred, average='weighted', zero_division=0),
    'recall':    recall_score(y_test, rf_pred, average='weighted', zero_division=0),
    'f1_score':  f1_score(y_test, rf_pred, average='weighted', zero_division=0),
}
r = results['Random Forest']
print_ok(
    f"Accuracy {r['accuracy']:.4f}  |  Precision {r['precision']:.4f}  |  "
    f"Recall {r['recall']:.4f}  |  F1 {r['f1_score']:.4f}"
)

# Top features
feat_imp = pd.DataFrame({
    'feature':    X.columns,
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=False)
print_info("Top 5 features:")
for _, row in feat_imp.head(5).iterrows():
    print(f"      {row['feature']}: {row['importance']:.4f}")


# ── XGBoost ──────────────────────────────────────────────────────────────────
print_header("MODEL 2 — XGBOOST")

xgb = XGBClassifier(
    n_estimators=200, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    random_state=42, eval_metric='mlogloss',
    use_label_encoder=False, verbosity=0
)
print("   Training XGBoost (200 rounds)...")
xgb.fit(X_train, y_train, verbose=False)

xgb_pred = xgb.predict(X_test)
results['XGBoost'] = {
    'accuracy':  accuracy_score(y_test, xgb_pred),
    'precision': precision_score(y_test, xgb_pred, average='weighted', zero_division=0),
    'recall':    recall_score(y_test, xgb_pred, average='weighted', zero_division=0),
    'f1_score':  f1_score(y_test, xgb_pred, average='weighted', zero_division=0),
}
r = results['XGBoost']
print_ok(
    f"Accuracy {r['accuracy']:.4f}  |  Precision {r['precision']:.4f}  |  "
    f"Recall {r['recall']:.4f}  |  F1 {r['f1_score']:.4f}"
)


# ── Neural Network ────────────────────────────────────────────────────────────
print_header("MODEL 3 — NEURAL NETWORK")

y_tr_cat  = keras.utils.to_categorical(y_tr_nn,  num_classes)
y_val_cat = keras.utils.to_categorical(y_val_nn, num_classes)
y_te_cat  = keras.utils.to_categorical(y_test,   num_classes)

nn = keras.Sequential([
    layers.Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
    layers.BatchNormalization(),
    layers.Dropout(0.3),
    layers.Dense(64, activation='relu'),
    layers.Dropout(0.2),
    layers.Dense(32, activation='relu'),
    layers.Dense(num_classes, activation='softmax'),
], name='ThreatDetectionNN')

nn.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.001),
    loss='categorical_crossentropy',
    metrics=['accuracy']
)

print_info(f"Architecture: {X_train.shape[1]} → 128 → 64 → 32 → {num_classes}")
print_info(f"Parameters: {nn.count_params():,}")

early_stop = keras.callbacks.EarlyStopping(
    monitor='val_loss', patience=20,
    restore_best_weights=True, verbose=0
)
batch_size = min(32, max(4, len(X_tr_nn) // 10))

print("   Training Neural Network...")
history = nn.fit(
    X_tr_nn, y_tr_cat,
    validation_data=(X_val_nn, y_val_cat),
    epochs=100, batch_size=batch_size,
    callbacks=[early_stop], verbose=0
)
print_ok(f"Converged in {len(history.history['loss'])} epochs")

nn_pred = np.argmax(nn.predict(X_test, verbose=0), axis=1)
results['Neural Network'] = {
    'accuracy':  accuracy_score(y_test, nn_pred),
    'precision': precision_score(y_test, nn_pred, average='weighted', zero_division=0),
    'recall':    recall_score(y_test, nn_pred, average='weighted', zero_division=0),
    'f1_score':  f1_score(y_test, nn_pred, average='weighted', zero_division=0),
}
r = results['Neural Network']
print_ok(
    f"Accuracy {r['accuracy']:.4f}  |  Precision {r['precision']:.4f}  |  "
    f"Recall {r['recall']:.4f}  |  F1 {r['f1_score']:.4f}"
)


# ─────────────────────────────────────────────────────────────────────────────
# COMPARISON + BEST MODEL SELECTION
# ─────────────────────────────────────────────────────────────────────────────
print_header("MODEL COMPARISON")

comp = pd.DataFrame(results).T
print(comp.to_string())

best_name = max(results, key=lambda x: results[x]['f1_score'])
best_f1   = results[best_name]['f1_score']
print(f"\n   🏆 Best model: {best_name}  (F1 = {best_f1:.4f})")


# ─────────────────────────────────────────────────────────────────────────────
# SAVE EVERYTHING
# ─────────────────────────────────────────────────────────────────────────────
print_header("SAVING MODELS & ARTIFACTS")

# Individual models
joblib.dump(rf,  MODEL_DIR / 'rf_model.pkl');   print_ok("Saved rf_model.pkl")
joblib.dump(xgb, MODEL_DIR / 'xgb_model.pkl'); print_ok("Saved xgb_model.pkl")
nn.save(MODEL_DIR / 'nn_model.h5');             print_ok("Saved nn_model.h5")

# Best model (what the API will load)
if best_name == 'Neural Network':
    nn.save(MODEL_DIR / 'best_model.h5')
    (MODEL_DIR / 'best_model_type.txt').write_text('neural_network')
    print_ok("Saved best_model.h5 (Neural Network)")
elif best_name == 'Random Forest':
    joblib.dump(rf, MODEL_DIR / 'best_model.pkl')
    (MODEL_DIR / 'best_model_type.txt').write_text('random_forest')
    print_ok("Saved best_model.pkl (Random Forest)")
else:
    joblib.dump(xgb, MODEL_DIR / 'best_model.pkl')
    (MODEL_DIR / 'best_model_type.txt').write_text('xgboost')
    print_ok("Saved best_model.pkl (XGBoost)")

# Preprocessors
joblib.dump(scaler, PREP_DIR / 'threat_scaler.pkl')
joblib.dump(le,     PREP_DIR / 'threat_label_encoder.pkl')
(PREP_DIR / 'threat_feature_names.json').write_text(
    json.dumps(list(X.columns))
)
print_ok("Saved threat_scaler.pkl, threat_label_encoder.pkl, threat_feature_names.json")

# Evaluation metadata
eval_data = {
    'models':            results,
    'best_model':        best_name,
    'num_classes':       num_classes,
    'class_names':       list(le.classes_),
    'training_samples':  int(len(X_train)),
    'test_samples':      int(len(X_test)),
    'trained_at':        pd.Timestamp.now().isoformat(),
}
(EVAL_DIR / 'threat_detection_metrics.json').write_text(
    json.dumps(eval_data, indent=2)
)

# Confusion matrix
best_pred = {'Random Forest': rf_pred, 'XGBoost': xgb_pred, 'Neural Network': nn_pred}[best_name]
cm = confusion_matrix(y_test, best_pred).tolist()
(EVAL_DIR / 'threat_detection_confusion_matrix.json').write_text(
    json.dumps({'confusion_matrix': cm, 'class_names': list(le.classes_)}, indent=2)
)
print_ok("Saved evaluation metrics + confusion matrix")


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print_header("TRAINING COMPLETE")

print(f"   Dataset : CIC-MalMem-2022 + CIC-IDS2017 Credential Subset")
print(f"   Records : {len(data):,} total  →  {X_res.shape[0]:,} after SMOTE")
print(f"   Features: {X.shape[1]}")
print(f"   Classes : {num_classes}  ({', '.join(le.classes_)})")
print()
print(f"   Models  : Random Forest  ·  XGBoost  ·  Neural Network")
print(f"   🏆 Best : {best_name}  (F1 = {best_f1:.4f})")
print()
print(f"   Saved to: models/saved_models/threat_detection/")
print()
print("▶️   Next step: python scripts/integrate_threat_router.py")
print("             (or restart your FastAPI backend to pick up the new router)")