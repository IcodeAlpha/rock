"""
Train Phishing URL Detection Models - FIXED FOR OVERFITTING
Script: 5_train_phishing_detection.py

Tests 3 algorithms: Random Forest, XGBoost, and Neural Network
Binary classification: Phishing vs Legitimate URLs

CHANGES FROM ORIGINAL:
- Added regularization to prevent 100% accuracy overfitting
- Reduced max_depth, increased min_samples to force generalization
- Added max_features to limit feature combinations
"""

import pandas as pd
import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

print("=" * 70)
print("PHISHING URL DETECTION MODEL TRAINING (REGULARIZED)")
print("=" * 70)

# ============================================
# 1. LOAD PROCESSED DATA
# ============================================
print("\n[1/6] Loading processed phishing URL data...")

try:
    with open('data/processed/processed_phishing_urls.json', 'r') as f:
        data = json.load(f)
    
    df = pd.DataFrame(data)
    print(f"✅ Loaded {len(df)} URL records")
    print(f"   Features: {len(df.columns)} columns")
    
except FileNotFoundError:
    print("❌ Error: processed_phishing_urls.json not found!")
    print("   Run '3b_process_phishing.py' first")
    exit(1)

# Identify label column
label_cols = ['label', 'phishing', 'class', 'target']
label_col = None
for col in label_cols:
    if col in df.columns:
        label_col = col
        break

if label_col is None:
    print("❌ Error: No label column found!")
    print(f"   Expected one of: {label_cols}")
    exit(1)

print(f"   Label column: '{label_col}'")

# Separate features and target
X = df.drop([label_col], axis=1)
y = df[label_col]

# Ensure binary labels (0 and 1)
if y.nunique() > 2:
    print(f"   ⚠️  Found {y.nunique()} unique labels, converting to binary...")
    # Assuming -1 or other values represent phishing
    y = (y != 0).astype(int)

print(f"\n   Class distribution:")
print(f"      Legitimate (0): {(y == 0).sum()}")
print(f"      Phishing (1): {(y == 1).sum()}")

# Handle any remaining non-numeric columns
categorical_cols = X.select_dtypes(include=['object']).columns
if len(categorical_cols) > 0:
    print(f"   Encoding {len(categorical_cols)} categorical features...")
    from sklearn.preprocessing import LabelEncoder
    for col in categorical_cols:
        le_cat = LabelEncoder()
        X[col] = le_cat.fit_transform(X[col].astype(str))

# Convert all to numeric
X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

print(f"✅ Features: {X.shape[1]} numeric columns")

# ============================================
# 2. SCALE FEATURES
# ============================================
print("\n[2/6] Scaling features...")

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print(f"✅ Features scaled using StandardScaler")

# ============================================
# 3. TRAIN/TEST SPLIT
# ============================================
print("\n[3/6] Splitting data...")

# Check if we can stratify (need at least 2 samples per class)
min_class_count = y.value_counts().min()
can_stratify = min_class_count >= 2

if can_stratify:
    print(f"   Using stratified split")
    stratify_param = y
else:
    print(f"   ⚠️  Cannot stratify (min class has {min_class_count} samples)")
    stratify_param = None

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y,
    test_size=0.2,
    random_state=42,
    stratify=stratify_param
)

# Check for validation split
min_train_count = pd.Series(y_train).value_counts().min()
can_stratify_val = min_train_count >= 2

# Additional validation split for neural network
X_train_nn, X_val_nn, y_train_nn, y_val_nn = train_test_split(
    X_train, y_train,
    test_size=0.2,
    random_state=42,
    stratify=y_train if can_stratify_val else None
)

print(f"✅ Split complete")
print(f"   Training: {X_train.shape[0]} samples")
print(f"   Testing: {X_test.shape[0]} samples")
print(f"   Validation (NN): {X_val_nn.shape[0]} samples")

# ============================================
# 4. TRAIN MODELS
# ============================================
results = {}

# ============================================
# MODEL 1: RANDOM FOREST (WITH REGULARIZATION)
# ============================================
print("\n" + "=" * 70)
print("MODEL 1: RANDOM FOREST (REGULARIZED)")
print("=" * 70)

rf_model = RandomForestClassifier(
    n_estimators=100,        # Reduced from 200
    max_depth=8,             # Reduced from 15 - PREVENTS OVERFITTING
    min_samples_split=20,    # Increased from 5 - REQUIRES MORE DATA BEFORE SPLIT
    min_samples_leaf=10,     # Increased from 2 - PREVENTS TINY LEAF NODES
    max_features='sqrt',     # NEW - Only consider sqrt(n) features per split
    random_state=42,
    n_jobs=-1,
    class_weight='balanced',
    verbose=0
)

print("Training Random Forest with regularization...")
print("   Parameters:")
print(f"      max_depth: 8 (prevents memorization)")
print(f"      min_samples_split: 20 (requires more data before split)")
print(f"      min_samples_leaf: 10 (prevents tiny leaves)")
print(f"      max_features: sqrt (reduces feature combinations)")

rf_model.fit(X_train, y_train)

print("Evaluating...")
rf_pred = rf_model.predict(X_test)
rf_pred_proba = rf_model.predict_proba(X_test)[:, 1]

rf_accuracy = accuracy_score(y_test, rf_pred)
rf_precision = precision_score(y_test, rf_pred, zero_division=0)
rf_recall = recall_score(y_test, rf_pred, zero_division=0)
rf_f1 = f1_score(y_test, rf_pred, zero_division=0)
rf_auc = roc_auc_score(y_test, rf_pred_proba)

results['Random Forest'] = {
    'accuracy': rf_accuracy,
    'precision': rf_precision,
    'recall': rf_recall,
    'f1_score': rf_f1,
    'auc_roc': rf_auc
}

print(f"\n✅ Random Forest Results:")
print(f"   Accuracy:  {rf_accuracy:.4f}")
print(f"   Precision: {rf_precision:.4f}")
print(f"   Recall:    {rf_recall:.4f}")
print(f"   F1-Score:  {rf_f1:.4f}")
print(f"   AUC-ROC:   {rf_auc:.4f}")

if rf_accuracy == 1.0:
    print("\n   ⚠️  WARNING: Still achieving 100% accuracy!")
    print("   Model may still be overfitted - consider:")
    print("      - Reducing max_depth further")
    print("      - Increasing min_samples_split/leaf")
    print("      - Adding noise to training data")

# Feature importance
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': rf_model.feature_importances_
}).sort_values('importance', ascending=False)

print(f"\n   Top 5 Important Features:")
for idx, row in feature_importance.head(5).iterrows():
    print(f"      {row['feature']}: {row['importance']:.4f}")

# ============================================
# MODEL 2: XGBOOST (WITH REGULARIZATION)
# ============================================
print("\n" + "=" * 70)
print("MODEL 2: XGBOOST (REGULARIZED)")
print("=" * 70)

# Calculate scale_pos_weight for imbalanced data
scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()

xgb_model = XGBClassifier(
    n_estimators=100,        # Reduced from 200
    max_depth=5,             # Reduced from 8 - PREVENTS OVERFITTING
    learning_rate=0.05,      # Reduced from 0.1 - SLOWER, MORE CAREFUL LEARNING
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,      # NEW - Requires minimum samples in leaf
    gamma=1,                 # NEW - Minimum loss reduction for split
    reg_alpha=0.1,           # NEW - L1 regularization
    reg_lambda=1,            # NEW - L2 regularization
    scale_pos_weight=scale_pos_weight,
    random_state=42,
    eval_metric='logloss',
    use_label_encoder=False,
    verbosity=0
)

print("Training XGBoost with regularization...")
print("   Parameters:")
print(f"      max_depth: 5 (shallow trees)")
print(f"      learning_rate: 0.05 (slower learning)")
print(f"      min_child_weight: 5 (minimum samples per leaf)")
print(f"      gamma: 1 (pruning threshold)")
print(f"      reg_alpha: 0.1, reg_lambda: 1 (L1/L2 regularization)")

xgb_model.fit(X_train, y_train, verbose=False)

print("Evaluating...")
xgb_pred = xgb_model.predict(X_test)
xgb_pred_proba = xgb_model.predict_proba(X_test)[:, 1]

xgb_accuracy = accuracy_score(y_test, xgb_pred)
xgb_precision = precision_score(y_test, xgb_pred, zero_division=0)
xgb_recall = recall_score(y_test, xgb_pred, zero_division=0)
xgb_f1 = f1_score(y_test, xgb_pred, zero_division=0)
xgb_auc = roc_auc_score(y_test, xgb_pred_proba)

results['XGBoost'] = {
    'accuracy': xgb_accuracy,
    'precision': xgb_precision,
    'recall': xgb_recall,
    'f1_score': xgb_f1,
    'auc_roc': xgb_auc
}

print(f"\n✅ XGBoost Results:")
print(f"   Accuracy:  {xgb_accuracy:.4f}")
print(f"   Precision: {xgb_precision:.4f}")
print(f"   Recall:    {xgb_recall:.4f}")
print(f"   F1-Score:  {xgb_f1:.4f}")
print(f"   AUC-ROC:   {xgb_auc:.4f}")

# ============================================
# MODEL 3: NEURAL NETWORK (WITH REGULARIZATION)
# ============================================
print("\n" + "=" * 70)
print("MODEL 3: NEURAL NETWORK (REGULARIZED)")
print("=" * 70)

# Build architecture with MORE dropout
nn_model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
    layers.BatchNormalization(),
    layers.Dropout(0.5),     # Increased from 0.3
    
    layers.Dense(32, activation='relu'),
    layers.BatchNormalization(),
    layers.Dropout(0.4),     # Increased from 0.2
    
    layers.Dense(16, activation='relu'),
    layers.Dropout(0.3),     # Increased from 0.2
    
    layers.Dense(1, activation='sigmoid')
], name='PhishingDetectionNN')

nn_model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.0005),  # Reduced from 0.001
    loss='binary_crossentropy',
    metrics=['accuracy', tf.keras.metrics.AUC(name='auc')]
)

print(f"\n🧠 Neural Network Architecture:")
print(f"   Input: {X_train.shape[1]} features")
print(f"   Hidden Layers: 64 → 32 → 16 neurons")
print(f"   Dropout: 0.5 → 0.4 → 0.3 (HIGH regularization)")
print(f"   Output: 1 neuron (sigmoid)")
print(f"   Total Parameters: {nn_model.count_params():,}")

# Callbacks
early_stop = keras.callbacks.EarlyStopping(
    monitor='val_loss',
    patience=15,
    restore_best_weights=True,
    verbose=0
)

reduce_lr = keras.callbacks.ReduceLROnPlateau(
    monitor='val_loss',
    factor=0.5,
    patience=5,
    min_lr=0.00001,
    verbose=0
)

print("\nTraining Neural Network...")
history = nn_model.fit(
    X_train_nn, y_train_nn,
    validation_data=(X_val_nn, y_val_nn),
    epochs=100,
    batch_size=128,
    callbacks=[early_stop, reduce_lr],
    verbose=0
)

print(f"✅ Training completed in {len(history.history['loss'])} epochs")

# Evaluate
print("Evaluating...")
nn_pred_proba = nn_model.predict(X_test, verbose=0).flatten()
nn_pred = (nn_pred_proba > 0.5).astype(int)

nn_accuracy = accuracy_score(y_test, nn_pred)
nn_precision = precision_score(y_test, nn_pred, zero_division=0)
nn_recall = recall_score(y_test, nn_pred, zero_division=0)
nn_f1 = f1_score(y_test, nn_pred, zero_division=0)
nn_auc = roc_auc_score(y_test, nn_pred_proba)

results['Neural Network'] = {
    'accuracy': nn_accuracy,
    'precision': nn_precision,
    'recall': nn_recall,
    'f1_score': nn_f1,
    'auc_roc': nn_auc
}

print(f"\n✅ Neural Network Results:")
print(f"   Accuracy:  {nn_accuracy:.4f}")
print(f"   Precision: {nn_precision:.4f}")
print(f"   Recall:    {nn_recall:.4f}")
print(f"   F1-Score:  {nn_f1:.4f}")
print(f"   AUC-ROC:   {nn_auc:.4f}")

# ============================================
# 5. COMPARE MODELS
# ============================================
print("\n" + "=" * 70)
print("MODEL COMPARISON")
print("=" * 70)

comparison_df = pd.DataFrame(results).T
print("\n" + comparison_df.to_string())

# Select best based on AUC-ROC (best for binary classification)
best_model_name = max(results, key=lambda x: results[x]['auc_roc'])
best_auc = results[best_model_name]['auc_roc']

print(f"\n🏆 BEST MODEL: {best_model_name}")
print(f"   AUC-ROC: {best_auc:.4f}")

# Check for overfitting
print(f"\n🔍 Overfitting Check:")
for model_name, metrics in results.items():
    if metrics['accuracy'] >= 0.99:
        print(f"   ⚠️  {model_name}: {metrics['accuracy']:.4f} accuracy (likely overfit)")
    else:
        print(f"   ✅  {model_name}: {metrics['accuracy']:.4f} accuracy (reasonable)")

# ============================================
# 6. SAVE MODELS
# ============================================
print("\n[6/6] Saving models...")

# Create directories
os.makedirs('models/saved_models/phishing_detection', exist_ok=True)
os.makedirs('models/preprocessors', exist_ok=True)
os.makedirs('models/evaluation', exist_ok=True)

# Save all models
joblib.dump(rf_model, 'models/saved_models/phishing_detection/rf_model.pkl')
print("✅ Saved: rf_model.pkl")

joblib.dump(xgb_model, 'models/saved_models/phishing_detection/xgb_model.pkl')
print("✅ Saved: xgb_model.pkl")

nn_model.save('models/saved_models/phishing_detection/nn_model.h5')
print("✅ Saved: nn_model.h5")

# Save best model
if best_model_name == 'Neural Network':
    nn_model.save('models/saved_models/phishing_detection/best_model.h5')
    print("✅ Saved: best_model.h5 (Neural Network)")
elif best_model_name == 'Random Forest':
    joblib.dump(rf_model, 'models/saved_models/phishing_detection/best_model.pkl')
    print("✅ Saved: best_model.pkl (Random Forest)")
else:
    joblib.dump(xgb_model, 'models/saved_models/phishing_detection/best_model.pkl')
    print("✅ Saved: best_model.pkl (XGBoost)")

# Save preprocessors
joblib.dump(scaler, 'models/preprocessors/phishing_scaler.pkl')
print("✅ Saved: preprocessor (scaler)")

# Save feature names
with open('models/preprocessors/phishing_feature_names.json', 'w') as f:
    json.dump(list(X.columns), f)

# Save evaluation metrics
evaluation_data = {
    'models': results,
    'best_model': best_model_name,
    'training_samples': len(X_train),
    'test_samples': len(X_test),
    'class_distribution': {
        'legitimate': int((y == 0).sum()),
        'phishing': int((y == 1).sum())
    }
}

with open('models/evaluation/phishing_detection_metrics.json', 'w') as f:
    json.dump(evaluation_data, f, indent=4)

print("✅ Saved: evaluation metrics")

# Save confusion matrix
if best_model_name == 'Random Forest':
    best_pred = rf_pred
elif best_model_name == 'XGBoost':
    best_pred = xgb_pred
else:
    best_pred = nn_pred

cm = confusion_matrix(y_test, best_pred)
cm_data = {
    'confusion_matrix': cm.tolist(),
    'class_names': ['Legitimate', 'Phishing']
}

with open('models/evaluation/phishing_detection_confusion_matrix.json', 'w') as f:
    json.dump(cm_data, f, indent=4)

print("✅ Saved: confusion matrix")

# ============================================
# FINAL SUMMARY
# ============================================
print("\n" + "=" * 70)
print("TRAINING COMPLETE!")
print("=" * 70)

print(f"\n📊 Summary:")
print(f"   Dataset: Phishing URL Detection")
print(f"   Samples: {len(df)}")
print(f"   Features: {X.shape[1]}")
print(f"   Task: Binary Classification")
print(f"\n   Models Trained: 3")
print(f"      ✓ Random Forest (REGULARIZED)")
print(f"      ✓ XGBoost (REGULARIZED)")
print(f"      ✓ Neural Network (REGULARIZED)")
print(f"\n   🏆 Best Model: {best_model_name} (AUC: {best_auc:.4f})")

print(f"\n📁 Saved to:")
print(f"   models/saved_models/phishing_detection/")
print(f"   models/preprocessors/")
print(f"   models/evaluation/")

print(f"\n✅ Next Step: Restart API and test again")