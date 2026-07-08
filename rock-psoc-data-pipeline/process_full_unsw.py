"""
Process full UNSW-NB15 dataset from all 4 CSV files (2.5M samples)
and retrain the intrusion detection model
"""
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

BASE_DIR = Path(__file__).parent
RAW_DIR = BASE_DIR / 'data/raw/unsw_nb15'
PROCESSED_DIR = BASE_DIR / 'data/processed'
MODEL_DIR = BASE_DIR / 'models/saved_models'
EVAL_DIR = BASE_DIR / 'models/evaluation'

MODEL_DIR.mkdir(parents=True, exist_ok=True)
EVAL_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("🔄 PROCESSING FULL UNSW-NB15 DATASET (2.5M samples)")
print("=" * 70)

# Load feature names
feat_df = pd.read_csv(RAW_DIR / 'NUSW-NB15_features.csv', encoding='latin1')
col_names = feat_df['Name'].tolist()

# Load all 4 CSV files
dfs = []
for i in range(1, 5):
    f = RAW_DIR / f'UNSW-NB15_{i}.csv'
    print(f"📥 Loading {f.name}...")
    df = pd.read_csv(f, header=None, names=col_names, low_memory=False)
    print(f"   Rows: {len(df):,}")
    dfs.append(df)

combined = pd.concat(dfs, ignore_index=True)
print(f"\n✅ Combined: {len(combined):,} rows")

# Clean attack_cat — strip whitespace, fill NaN normals
combined['attack_cat'] = combined['attack_cat'].str.strip()
combined.loc[combined['Label'] == 0, 'attack_cat'] = combined.loc[
    combined['Label'] == 0, 'attack_cat'].fillna('Normal')
combined.loc[combined['Label'] == 1, 'attack_cat'] = combined.loc[
    combined['Label'] == 1, 'attack_cat'].fillna('Generic')

# Drop rows still missing attack_cat
combined = combined.dropna(subset=['attack_cat'])
print(f"   After cleaning: {len(combined):,} rows")

print(f"\n🎯 Attack category distribution:")
print(combined['attack_cat'].value_counts())

# Drop non-useful columns
drop_cols = ['srcip', 'dstip', 'sport', 'dsport', 'Stime', 'Ltime',
             'attack_cat', 'Label', 'proto', 'state', 'service']
X = combined.drop(columns=[c for c in drop_cols if c in combined.columns], errors='ignore')

# Fix column name with space
X.columns = X.columns.str.strip()
y = combined['attack_cat']

# Keep only numeric columns
non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
if non_numeric:
    print(f"\n   Dropping non-numeric: {non_numeric}")
    X = X.drop(columns=non_numeric)

# Clean data
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median())

print(f"\n   Features: {X.shape[1]}")
print(f"   Feature names: {list(X.columns)}")
print(f"   Samples: {len(X):,}")

# Sample if too large (use 500K for speed)
if len(X) > 500000:
    print(f"\n⚡ Sampling 500K rows for faster training...")
    idx = X.sample(500000, random_state=42).index
    X = X.loc[idx]
    y = y.loc[idx]
    print(f"   Sampled: {len(X):,} rows")

# Encode labels
print("\n🔢 Encoding labels...")
le = LabelEncoder()
y_enc = le.fit_transform(y)
print(f"   Classes: {list(le.classes_)}")

# Split
print("\n✂️  Splitting dataset (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)
print(f"   Train: {len(X_train):,}  Test: {len(X_test):,}")

# Train
print("\n🚀 Training Random Forest (300 trees, balanced)...")
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=30,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1,
    verbose=1,
    class_weight='balanced'
)

start = datetime.now()
model.fit(X_train, y_train)
elapsed = (datetime.now() - start).total_seconds()
print(f"\n✅ Training completed in {elapsed:.1f} seconds")

# Evaluate
print("\n📊 Evaluating...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n   Accuracy: {accuracy*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=le.classes_, digits=4, zero_division=0))

# Feature importance
print("\n🎯 Top 15 Features:")
fi = pd.DataFrame({'feature': X.columns, 'importance': model.feature_importances_})
fi = fi.sort_values('importance', ascending=False)
for _, row in fi.head(15).iterrows():
    print(f"   {row['feature']:30s}: {row['importance']:.4f}")

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(14, 12))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=le.classes_, yticklabels=le.classes_)
plt.title('Intrusion Detection - Full UNSW-NB15')
plt.tight_layout()
plt.savefig(EVAL_DIR / 'intrusion_v2_confusion_matrix.png', dpi=150)
plt.close()

# Save
print("\n💾 Saving model...")
with open(MODEL_DIR / 'intrusion_model_v2.pkl', 'wb') as f: pickle.dump(model, f)
with open(MODEL_DIR / 'intrusion_label_encoder_v2.pkl', 'wb') as f: pickle.dump(le, f)
with open(MODEL_DIR / 'intrusion_features_v2.pkl', 'wb') as f: pickle.dump(list(X.columns), f)

print(f"\n✅ Done! Accuracy: {accuracy*100:.2f}%")
print("Run: python scripts/11_update_api_models.py")