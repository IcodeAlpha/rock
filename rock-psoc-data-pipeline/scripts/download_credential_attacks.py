"""
Download & Process Credential Attack Dataset
Covers: Brute Force, Credential Stuffing, Password Spraying
"""
import subprocess
import pandas as pd
import numpy as np
from pathlib import Path
import sys

BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / 'data/raw/credential_attacks'
PROCESSED_DIR = BASE_DIR / 'data/processed'
RAW_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("📥 DOWNLOADING CREDENTIAL ATTACK DATASET")
print("=" * 70)

# Download brute force dataset from Kaggle
print("\n🔽 Downloading credential attack dataset...")
result = subprocess.run([
    'kaggle', 'datasets', 'download',
    '-d', 'hassan06/nslkdd',
    '-p', str(RAW_DIR),
    '--unzip'
], capture_output=False, check=False)

# Also try CICIDS2017 which has brute force
result2 = subprocess.run([
    'kaggle', 'datasets', 'download',
    '-d', 'dhoogla/unswnb15',
    '-p', str(RAW_DIR),
    '--unzip'
], capture_output=False, check=False)

files = list(RAW_DIR.glob('*.csv'))
print(f"\n📁 Downloaded files:")
for f in files:
    print(f"   {f.name}: {f.stat().st_size / (1024*1024):.1f} MB")

if not files:
    print("❌ No files downloaded!")
    sys.exit(1)

# Process
print("\n📊 Processing credential attack data...")
dfs = []
for f in files[:3]:
    try:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        print(f"   Loaded {f.name}: {len(df):,} rows")
    except Exception as e:
        print(f"   ⚠️  {f.name}: {e}")

if dfs:
    combined = pd.concat(dfs, ignore_index=True)
    
    # Find label column
    label_col = next((c for c in ['Label', 'label', 'attack_cat', 'class']
                      if c in combined.columns), None)
    
    if label_col:
        print(f"\n   Labels:\n{combined[label_col].value_counts().head(15)}")
        
        # Filter credential attacks
        cred_keywords = ['brute', 'force', 'ssh', 'ftp', 'password', 'login',
                        'credential', 'auth', 'dict']
        cred_labels = [l for l in combined[label_col].unique()
                      if any(kw in str(l).lower() for kw in cred_keywords)]
        print(f"\n   Credential attack labels: {cred_labels}")

    out = PROCESSED_DIR / 'credential_attacks.csv'
    combined.to_csv(out, index=False)
    print(f"\n💾 Saved to: {out}")
    print(f"   Rows: {len(combined):,}")

print("\n✅ Credential attack dataset ready!")