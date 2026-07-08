"""
Batch test - predict on real samples directly using the model
"""
import pandas as pd
import numpy as np
import pickle
from pathlib import Path

BASE_DIR = Path(__file__).parent
RAW_DIR = BASE_DIR / 'data/raw/unsw_nb15'
MODEL_DIR = BASE_DIR / 'models/saved_models'

# Load model
print("Loading model...")
with open(MODEL_DIR / 'intrusion_model.pkl', 'rb') as f: model = pickle.load(f)
with open(MODEL_DIR / 'intrusion_label_encoder.pkl', 'rb') as f: le = pickle.load(f)
with open(MODEL_DIR / 'intrusion_features.pkl', 'rb') as f: features = pickle.load(f)

print(f"Model features: {features}")

# Load full CSV files
print("\nLoading full dataset...")
feat_df = pd.read_csv(RAW_DIR / 'NUSW-NB15_features.csv', encoding='latin1')
col_names = feat_df['Name'].tolist()

dfs = []
for i in range(1, 5):
    f = RAW_DIR / f'UNSW-NB15_{i}.csv'
    df = pd.read_csv(f, header=None, names=col_names, low_memory=False, nrows=50000)
    dfs.append(df)

combined = pd.concat(dfs, ignore_index=True)
combined['attack_cat'] = combined['attack_cat'].str.strip()
combined.loc[combined['Label'] == 0, 'attack_cat'] = combined.loc[
    combined['Label'] == 0, 'attack_cat'].fillna('Normal')

# Fix column name with space
combined.columns = combined.columns.str.strip()

print(f"Columns: {list(combined.columns)}")
print(f"\nAttack distribution:\n{combined['attack_cat'].value_counts()}")

# Prepare features
X = combined.copy()
drop_cols = ['srcip', 'dstip', 'sport', 'dsport', 'Stime', 'Ltime',
             'attack_cat', 'Label', 'proto', 'state', 'service', 'ct_ftp_cmd']
X = X.drop(columns=[c for c in drop_cols if c in X.columns], errors='ignore')
X.columns = X.columns.str.strip()
X = X.select_dtypes(include=[np.number])
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

print(f"\nAvailable features: {list(X.columns)}")
print(f"\nModel expects: {features}")

# Align features
missing = [f for f in features if f not in X.columns]
extra = [f for f in X.columns if f not in features]
print(f"\nMissing from data: {missing}")
print(f"Extra in data: {extra[:5]}")

# Test per class
print("\n" + "=" * 60)
print("BATCH PREDICTION TEST (10 samples per class)")
print("=" * 60)

for attack in ['Normal', 'DoS', 'Reconnaissance', 'Backdoor', 'Exploits', 'Generic', 'Fuzzers']:
    samples = combined[combined['attack_cat'] == attack]
    if len(samples) == 0:
        print(f"\n{attack}: NOT FOUND")
        continue

    sample_X = samples.head(10).copy()
    sample_X = sample_X.drop(columns=[c for c in drop_cols if c in sample_X.columns], errors='ignore')
    sample_X.columns = sample_X.columns.str.strip()
    sample_X = sample_X.select_dtypes(include=[np.number])
    sample_X = sample_X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Add missing columns as 0
    for f in features:
        if f not in sample_X.columns:
            sample_X[f] = 0.0

    sample_X = sample_X[features]
    preds = le.inverse_transform(model.predict(sample_X))
    correct = sum(p == attack for p in preds)
    print(f"\n{attack}: {correct}/10 correct")
    print(f"  Predictions: {list(preds)}")