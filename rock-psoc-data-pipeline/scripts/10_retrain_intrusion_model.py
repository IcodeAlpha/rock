"""
Script 10: Retrain Intrusion Detection Model using UNSW-NB15 (multi-class)
Predicts specific attack types: Normal, DoS, Generic, Exploits, etc.
"""

import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'processed'
RAW_DIR = BASE_DIR / 'data' / 'raw' / 'unsw_nb15'
MODEL_DIR = BASE_DIR / 'models' / 'saved_models'
EVAL_DIR = BASE_DIR / 'models' / 'evaluation'

MODEL_DIR.mkdir(parents=True, exist_ok=True)
EVAL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("🤖 RETRAINING INTRUSION DETECTION MODEL (V2 - MULTI-CLASS)")
print("=" * 70)

# Load raw training + testing sets (they have attack_cat column)
print("\n📥 Loading UNSW-NB15 with attack categories...")

train_file = RAW_DIR / 'UNSW_NB15_training-set.csv'
test_file = RAW_DIR / 'UNSW_NB15_testing-set.csv'

if train_file.exists() and test_file.exists():
    train_df = pd.read_csv(train_file)
    test_df = pd.read_csv(test_file)
    df = pd.concat([train_df, test_df], ignore_index=True)
    print(f"   Rows: {len(df):,}  Columns: {len(df.columns)}")
else:
    print("❌ Raw UNSW-NB15 files not found!")
    print(f"   Expected: {train_file}")
    exit(1)

# Use attack_cat as the label (specific attack types)
print("\n🎯 Attack category distribution:")
print(df['attack_cat'].value_counts())

# Clean up label - strip whitespace
df['attack_cat'] = df['attack_cat'].str.strip()

# Drop label columns, keep attack_cat as target
drop_cols = [c for c in ['attack_cat', 'label', 'Label', 'id'] if c in df.columns]
X = df.drop(columns=drop_cols, errors='ignore')
y = df['attack_cat']

# Drop non-numeric columns
non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
if non_numeric:
    print(f"\n   Dropping non-numeric columns: {non_numeric}")
    X = X.drop(columns=non_numeric)

# Clean data
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median())

print(f"\n   Features: {X.shape[1]}")
print(f"   Samples: {len(X):,}")

# Encode labels
print("\n🔢 Encoding labels...")
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
print(f"   Classes: {list(label_encoder.classes_)}")

# Train/test split
print("\n✂️  Splitting dataset (80% train, 20% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"   Training: {len(X_train):,}  Testing: {len(X_test):,}")

# Train model
print("\n🚀 Training Random Forest Model (v2 multi-class)...")
model = RandomForestClassifier(
    n_estimators=200, max_depth=30, min_samples_split=5,
    random_state=42, n_jobs=-1, verbose=1
)

start_time = datetime.now()
model.fit(X_train, y_train)
training_time = (datetime.now() - start_time).total_seconds()
print(f"\n✅ Training completed in {training_time:.1f} seconds")

# Evaluate
print("\n📊 Evaluating model...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

print(f"\n   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"   Precision: {precision:.4f}")
print(f"   Recall:    {recall:.4f}")
print(f"   F1 Score:  {f1:.4f}")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, digits=4, zero_division=0))

# Feature importance
print("\n🎯 Top 15 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)
for _, row in feature_importance.head(15).iterrows():
    print(f"   {row['feature'][:30]:30s}: {row['importance']:.4f}")
feature_importance.to_csv(EVAL_DIR / 'intrusion_v2_feature_importance.csv', index=False)

# Confusion matrix
print("\n📈 Generating confusion matrix...")
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(14, 12))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_)
plt.title('Intrusion Detection Model v2 - Confusion Matrix (Multi-Class)')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig(EVAL_DIR / 'intrusion_v2_confusion_matrix.png', dpi=150)
plt.close()

# Save model files
print("\n💾 Saving model...")
with open(MODEL_DIR / 'intrusion_model_v2.pkl', 'wb') as f: pickle.dump(model, f)
with open(MODEL_DIR / 'intrusion_label_encoder_v2.pkl', 'wb') as f: pickle.dump(label_encoder, f)
with open(MODEL_DIR / 'intrusion_features_v2.pkl', 'wb') as f: pickle.dump(list(X.columns), f)
with open(MODEL_DIR / 'intrusion_model_v2_metadata.pkl', 'wb') as f:
    pickle.dump({
        'model_version': '2.0',
        'dataset': 'UNSW-NB15',
        'training_samples': len(X_train),
        'testing_samples': len(X_test),
        'num_features': X.shape[1],
        'num_classes': len(label_encoder.classes_),
        'classes': list(label_encoder.classes_),
        'accuracy': float(accuracy),
        'trained_at': datetime.now().isoformat(),
    }, f)

print("\n" + "=" * 70)
print("✅ MODEL RETRAINING COMPLETE")
print("=" * 70)
print(f"\nAccuracy: {accuracy*100:.2f}%")
print(f"Classes: {list(label_encoder.classes_)}")
print(f"Model saved to: {MODEL_DIR}")
print("\nNext steps:")
print("   1. Run: python scripts/11_update_api_models.py")
print("   2. Restart your prediction API")