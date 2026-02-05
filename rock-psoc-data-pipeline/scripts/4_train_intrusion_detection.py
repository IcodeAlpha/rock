"""
Train Network Intrusion Detection Models (NSL-KDD Dataset) - FIXED VERSION v2
Script: 4_train_intrusion_detection.py

Handles extreme class imbalance by combining rare attack types
"""

import pandas as pd
import json
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE
from sklearn.metrics import (
    classification_report, 
    accuracy_score, 
    f1_score, 
    precision_score, 
    recall_score,
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
print("NETWORK INTRUSION DETECTION MODEL TRAINING")
print("=" * 70)

# ============================================
# 1. LOAD AND EXTRACT FEATURES FROM THREAT DATA
# ============================================
print("\n[1/7] Loading NSL-KDD processed data...")

try:
    with open('data/processed/predictions_from_nsl_kdd.json', 'r') as f:
        data = json.load(f)
    
    print(f"✅ Loaded {len(data)} network traffic records")
    
except FileNotFoundError:
    print("❌ Error: predictions_from_nsl_kdd.json not found!")
    print("   Run '2_process_nsl_kdd.py' first")
    exit(1)

# ============================================
# 2. EXTRACT FEATURES FROM THREAT RECORDS
# ============================================
print("\n[2/7] Extracting features from threat indicators...")

features_list = []

for record in data:
    try:
        indicators = record.get('indicators', {})
        label = record.get('threat_type', 'unknown')
        
        features = {
            'severity': record.get('severity', 'medium'),
            'probability': record.get('probability', 0.5),
            'confidence_score': record.get('confidence_score', 0.5),
        }
        
        if isinstance(indicators, dict):
            for key, value in indicators.items():
                if isinstance(value, (int, float)):
                    features[f'ind_{key}'] = value
                elif isinstance(value, bool):
                    features[f'ind_{key}'] = int(value)
                elif isinstance(value, str):
                    features[f'ind_{key}'] = hash(value) % 1000
        
        features['attack_type'] = label
        features_list.append(features)
        
    except Exception as e:
        continue

df = pd.DataFrame(features_list)

print(f"✅ Extracted features from {len(df)} records")
print(f"   Total features: {len(df.columns) - 1}")

if 'attack_type' not in df.columns:
    print("\n❌ Error: Could not extract attack labels from data")
    exit(1)

# ============================================
# 3. HANDLE CLASS IMBALANCE - COMBINE RARE CLASSES
# ============================================
print("\n[3/7] Handling extreme class imbalance...")

# Check class distribution
class_counts = df['attack_type'].value_counts()
print(f"\n   Original class distribution:")
for attack, count in class_counts.items():
    print(f"      {attack}: {count}")

# Combine classes with < 10 samples into "Other Attack"
MIN_SAMPLES = 10
rare_classes = class_counts[class_counts < MIN_SAMPLES].index.tolist()

if rare_classes:
    print(f"\n   ⚠️  Found {len(rare_classes)} rare classes (< {MIN_SAMPLES} samples)")
    print(f"   Combining into 'Other Attack': {rare_classes}")
    
    df['attack_type_original'] = df['attack_type']  # Keep original for reference
    df.loc[df['attack_type'].isin(rare_classes), 'attack_type'] = 'Other Attack'
    
    print(f"\n   Updated class distribution:")
    for attack, count in df['attack_type'].value_counts().items():
        print(f"      {attack}: {count}")

# ============================================
# 4. ENCODE LABELS AND PREPARE DATA
# ============================================
print("\n[4/7] Encoding labels and preparing features...")

target_col = 'attack_type'
X = df.drop([target_col, 'attack_type_original'], axis=1, errors='ignore')
y = df[target_col]

# Encode categorical features
categorical_cols = X.select_dtypes(include=['object']).columns
if len(categorical_cols) > 0:
    print(f"   Encoding {len(categorical_cols)} categorical features...")
    for col in categorical_cols:
        le_cat = LabelEncoder()
        X[col] = le_cat.fit_transform(X[col].astype(str))

# Convert all to numeric
X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

# Encode target labels
le = LabelEncoder()
y_encoded = le.fit_transform(y)
num_classes = len(le.classes_)

print(f"✅ Encoded {num_classes} attack classes: {list(le.classes_)}")

# Feature scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print(f"✅ Features scaled")
print(f"   Final feature matrix: {X_scaled.shape[0]} samples × {X_scaled.shape[1]} features")

# ============================================
# 5. APPLY SMOTE IF POSSIBLE
# ============================================
print("\n[5/7] Applying SMOTE for class balancing...")

try:
    min_samples = y.value_counts().min()
    
    if min_samples >= 6:  # SMOTE needs at least 6 samples (k_neighbors=5)
        k_neighbors = min(5, min_samples - 1)
        smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
        X_resampled, y_resampled = smote.fit_resample(X_scaled, y_encoded)
        
        print(f"✅ Applied SMOTE with k_neighbors={k_neighbors}")
        print(f"   Before: {X_scaled.shape[0]} samples")
        print(f"   After: {X_resampled.shape[0]} samples")
        
        print(f"\n   Balanced class distribution:")
        for class_idx in range(num_classes):
            class_name = le.classes_[class_idx]
            count = (y_resampled == class_idx).sum()
            print(f"      {class_name}: {count}")
    else:
        print(f"⚠️  Insufficient samples (min={min_samples}) for SMOTE")
        print(f"   Continuing without SMOTE...")
        X_resampled, y_resampled = X_scaled, y_encoded
        
except Exception as e:
    print(f"⚠️  SMOTE failed: {str(e)[:100]}")
    print(f"   Continuing without SMOTE...")
    X_resampled, y_resampled = X_scaled, y_encoded

# ============================================
# 6. TRAIN/TEST SPLIT (NO STRATIFY IF STILL TOO IMBALANCED)
# ============================================
print("\n[6/7] Splitting data...")

# Check if we can stratify
min_class_samples = pd.Series(y_resampled).value_counts().min()
can_stratify = min_class_samples >= 2

if can_stratify:
    print(f"   Using stratified split (min class samples: {min_class_samples})")
    stratify_param = y_resampled
else:
    print(f"   ⚠️  Cannot stratify (min class samples: {min_class_samples})")
    print(f"   Using random split instead")
    stratify_param = None

X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, 
    test_size=0.2, 
    random_state=42,
    stratify=stratify_param
)

# Additional split for neural network validation
min_train_samples = pd.Series(y_train).value_counts().min()
can_stratify_nn = min_train_samples >= 2

X_train_nn, X_val_nn, y_train_nn, y_val_nn = train_test_split(
    X_train, y_train, 
    test_size=0.2, 
    random_state=42,
    stratify=y_train if can_stratify_nn else None
)

print(f"✅ Split complete")
print(f"   Training: {X_train.shape[0]} samples")
print(f"   Testing: {X_test.shape[0]} samples")
print(f"   Validation (NN): {X_val_nn.shape[0]} samples")

# ============================================
# 7. TRAIN MODELS
# ============================================
results = {}

# ============================================
# MODEL 1: RANDOM FOREST
# ============================================
print("\n" + "=" * 70)
print("MODEL 1: RANDOM FOREST")
print("=" * 70)

rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=2,  # Reduced for small dataset
    min_samples_leaf=1,   # Reduced for small dataset
    random_state=42,
    class_weight='balanced',  # Handle any remaining imbalance
    n_jobs=-1,
    verbose=0
)

print("Training Random Forest (200 trees)...")
rf_model.fit(X_train, y_train)

print("Evaluating...")
rf_pred = rf_model.predict(X_test)
rf_pred_proba = rf_model.predict_proba(X_test)

rf_accuracy = accuracy_score(y_test, rf_pred)
rf_precision = precision_score(y_test, rf_pred, average='weighted', zero_division=0)
rf_recall = recall_score(y_test, rf_pred, average='weighted', zero_division=0)
rf_f1 = f1_score(y_test, rf_pred, average='weighted', zero_division=0)

results['Random Forest'] = {
    'accuracy': rf_accuracy,
    'precision': rf_precision,
    'recall': rf_recall,
    'f1_score': rf_f1
}

print(f"\n✅ Random Forest Results:")
print(f"   Accuracy:  {rf_accuracy:.4f}")
print(f"   Precision: {rf_precision:.4f}")
print(f"   Recall:    {rf_recall:.4f}")
print(f"   F1-Score:  {rf_f1:.4f}")

# Feature importance
if X.shape[1] > 0:
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\n   Top 5 Important Features:")
    for idx, row in feature_importance.head(5).iterrows():
        print(f"      {row['feature']}: {row['importance']:.4f}")

# ============================================
# MODEL 2: XGBOOST
# ============================================
print("\n" + "=" * 70)
print("MODEL 2: XGBOOST")
print("=" * 70)

xgb_model = XGBClassifier(
    n_estimators=200,
    max_depth=6,  # Reduced for small dataset
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric='mlogloss',
    use_label_encoder=False,
    verbosity=0
)

print("Training XGBoost (200 boosting rounds)...")
xgb_model.fit(X_train, y_train, verbose=False)

print("Evaluating...")
xgb_pred = xgb_model.predict(X_test)
xgb_pred_proba = xgb_model.predict_proba(X_test)

xgb_accuracy = accuracy_score(y_test, xgb_pred)
xgb_precision = precision_score(y_test, xgb_pred, average='weighted', zero_division=0)
xgb_recall = recall_score(y_test, xgb_pred, average='weighted', zero_division=0)
xgb_f1 = f1_score(y_test, xgb_pred, average='weighted', zero_division=0)

results['XGBoost'] = {
    'accuracy': xgb_accuracy,
    'precision': xgb_precision,
    'recall': xgb_recall,
    'f1_score': xgb_f1
}

print(f"\n✅ XGBoost Results:")
print(f"   Accuracy:  {xgb_accuracy:.4f}")
print(f"   Precision: {xgb_precision:.4f}")
print(f"   Recall:    {xgb_recall:.4f}")
print(f"   F1-Score:  {xgb_f1:.4f}")

# ============================================
# MODEL 3: NEURAL NETWORK
# ============================================
print("\n" + "=" * 70)
print("MODEL 3: NEURAL NETWORK")
print("=" * 70)

# Convert labels to categorical
y_train_cat = keras.utils.to_categorical(y_train_nn, num_classes)
y_val_cat = keras.utils.to_categorical(y_val_nn, num_classes)
y_test_cat = keras.utils.to_categorical(y_test, num_classes)

# Build simpler architecture for small dataset
nn_model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
    layers.Dropout(0.3),
    
    layers.Dense(32, activation='relu'),
    layers.Dropout(0.2),
    
    layers.Dense(num_classes, activation='softmax')
], name='IntrusionDetectionNN')

nn_model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=0.001),
    loss='categorical_crossentropy',
    metrics=['accuracy']
)

print(f"\n🧠 Neural Network Architecture:")
print(f"   Input: {X_train.shape[1]} features")
print(f"   Hidden Layers: 64 → 32 neurons")
print(f"   Output: {num_classes} classes")
print(f"   Total Parameters: {nn_model.count_params():,}")

# Early stopping
early_stop = keras.callbacks.EarlyStopping(
    monitor='val_loss',
    patience=20,
    restore_best_weights=True,
    verbose=0
)

print("\nTraining Neural Network...")
batch_size = min(32, max(4, len(X_train_nn) // 10))  # Adaptive batch size
history = nn_model.fit(
    X_train_nn, y_train_cat,
    validation_data=(X_val_nn, y_val_cat),
    epochs=100,
    batch_size=batch_size,
    callbacks=[early_stop],
    verbose=0
)

print(f"✅ Training completed in {len(history.history['loss'])} epochs")

# Evaluate
print("Evaluating...")
nn_pred_probs = nn_model.predict(X_test, verbose=0)
nn_pred = np.argmax(nn_pred_probs, axis=1)

nn_accuracy = accuracy_score(y_test, nn_pred)
nn_precision = precision_score(y_test, nn_pred, average='weighted', zero_division=0)
nn_recall = recall_score(y_test, nn_pred, average='weighted', zero_division=0)
nn_f1 = f1_score(y_test, nn_pred, average='weighted', zero_division=0)

results['Neural Network'] = {
    'accuracy': nn_accuracy,
    'precision': nn_precision,
    'recall': nn_recall,
    'f1_score': nn_f1
}

print(f"\n✅ Neural Network Results:")
print(f"   Accuracy:  {nn_accuracy:.4f}")
print(f"   Precision: {nn_precision:.4f}")
print(f"   Recall:    {nn_recall:.4f}")
print(f"   F1-Score:  {nn_f1:.4f}")

# ============================================
# 8. COMPARE MODELS AND SELECT BEST
# ============================================
print("\n" + "=" * 70)
print("MODEL COMPARISON")
print("=" * 70)

comparison_df = pd.DataFrame(results).T
print("\n" + comparison_df.to_string())

# Select best based on F1-score
best_model_name = max(results, key=lambda x: results[x]['f1_score'])
best_f1 = results[best_model_name]['f1_score']

print(f"\n🏆 BEST MODEL: {best_model_name}")
print(f"   F1-Score: {best_f1:.4f}")

# ============================================
# 9. SAVE MODELS
# ============================================
print("\n[7/7] Saving models...")

# Create directories
os.makedirs('models/saved_models/intrusion_detection', exist_ok=True)
os.makedirs('models/preprocessors', exist_ok=True)
os.makedirs('models/evaluation', exist_ok=True)

# Save all models
joblib.dump(rf_model, 'models/saved_models/intrusion_detection/rf_model.pkl')
print("✅ Saved: rf_model.pkl")

joblib.dump(xgb_model, 'models/saved_models/intrusion_detection/xgb_model.pkl')
print("✅ Saved: xgb_model.pkl")

nn_model.save('models/saved_models/intrusion_detection/nn_model.h5')
print("✅ Saved: nn_model.h5")

# Save best model
if best_model_name == 'Neural Network':
    nn_model.save('models/saved_models/intrusion_detection/best_model.h5')
    print("✅ Saved: best_model.h5 (Neural Network)")
elif best_model_name == 'Random Forest':
    joblib.dump(rf_model, 'models/saved_models/intrusion_detection/best_model.pkl')
    print("✅ Saved: best_model.pkl (Random Forest)")
else:
    joblib.dump(xgb_model, 'models/saved_models/intrusion_detection/best_model.pkl')
    print("✅ Saved: best_model.pkl (XGBoost)")

# Save preprocessors
joblib.dump(scaler, 'models/preprocessors/intrusion_scaler.pkl')
joblib.dump(le, 'models/preprocessors/intrusion_label_encoder.pkl')
print("✅ Saved: preprocessors (scaler, label_encoder)")

# Save feature names
with open('models/preprocessors/intrusion_feature_names.json', 'w') as f:
    json.dump(list(X.columns), f)

# Save evaluation metrics
evaluation_data = {
    'models': results,
    'best_model': best_model_name,
    'num_classes': num_classes,
    'class_names': list(le.classes_),
    'training_samples': len(X_train),
    'test_samples': len(X_test)
}

with open('models/evaluation/intrusion_detection_metrics.json', 'w') as f:
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
    'class_names': list(le.classes_)
}

with open('models/evaluation/intrusion_detection_confusion_matrix.json', 'w') as f:
    json.dump(cm_data, f, indent=4)

print("✅ Saved: confusion matrix")

# ============================================
# FINAL SUMMARY
# ============================================
print("\n" + "=" * 70)
print("TRAINING COMPLETE!")
print("=" * 70)

print(f"\n📊 Summary:")
print(f"   Dataset: NSL-KDD Network Intrusion Detection")
print(f"   Original samples: {len(data)}")
print(f"   After preprocessing: {len(X_resampled)}")
print(f"   Features: {X.shape[1]}")
print(f"   Classes: {num_classes} attack types")
print(f"\n   Models Trained: 3")
print(f"      ✓ Random Forest")
print(f"      ✓ XGBoost")
print(f"      ✓ Neural Network")
print(f"\n   🏆 Best Model: {best_model_name} (F1: {best_f1:.4f})")

print(f"\n📁 Saved to:")
print(f"   models/saved_models/intrusion_detection/")
print(f"   models/preprocessors/")
print(f"   models/evaluation/")

print(f"\n✅ Next Step: Run 5_train_phishing_detection.py")