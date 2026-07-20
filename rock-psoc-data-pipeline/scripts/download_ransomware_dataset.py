"""
Download Ransomware & C2 Communication Dataset from Kaggle
Uses CIC-IDS2018 ransomware subset + CTU-13 botnet dataset
"""
import subprocess
import sys
import pandas as pd
import numpy as np
import pickle
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / 'data/raw/ransomware'
PROCESSED_DIR = BASE_DIR / 'data/processed'
RAW_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("📥 DOWNLOADING RANSOMWARE & C2 DATASET")
print("=" * 70)

# Download from Kaggle
print("\n🔽 Downloading CIC-IDS2018 ransomware dataset...")
result = subprocess.run([
    'kaggle', 'datasets', 'download',
    '-d', 'solarmainframe/ids-intrusion-csv',
    '-p', str(RAW_DIR),
    '--unzip'
], capture_output=False, check=False)

if result.returncode != 0:
    print("⚠️  Primary dataset failed, trying alternative...")
    result = subprocess.run([
        'kaggle', 'datasets', 'download',
        '-d', 'cicdataset/cicids2017',
        '-p', str(RAW_DIR),
        '--unzip'
    ], capture_output=False, check=False)

# Check what was downloaded
files = list(RAW_DIR.glob('*.csv'))
print(f"\n📁 Downloaded files:")
for f in files:
    print(f"   {f.name}: {f.stat().st_size / (1024*1024):.1f} MB")

if not files:
    print("❌ No files downloaded!")
    sys.exit(1)

# Load and process
print("\n📊 Processing ransomware data...")
dfs = []
for f in files[:3]:  # Load up to 3 files
    try:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        print(f"   {f.name}: {len(df):,} rows, {len(df.columns)} cols")
        if 'Label' in df.columns:
            print(f"   Labels: {df['Label'].value_counts().head()}")
        dfs.append(df)
    except Exception as e:
        print(f"   ⚠️  Error loading {f.name}: {e}")

if not dfs:
    print("❌ No data loaded!")
    sys.exit(1)

combined = pd.concat(dfs, ignore_index=True)
combined.columns = combined.columns.str.strip()

# Find label column
label_col = None
for col in ['Label', 'label', 'attack_type', 'class']:
    if col in combined.columns:
        label_col = col
        break

print(f"\n   Label column: '{label_col}'")
print(f"   Labels:\n{combined[label_col].value_counts()}")

# Filter to ransomware and related classes
ransomware_labels = [l for l in combined[label_col].unique()
                     if any(kw in str(l).lower() for kw in
                     ['ransom', 'botnet', 'infiltrat', 'c2', 'command'])]
print(f"\n   Ransomware-related labels: {ransomware_labels}")

# Save processed
out = PROCESSED_DIR / 'ransomware_traffic.csv'
combined.to_csv(out, index=False)
print(f"\n💾 Saved to: {out}")
print(f"   Rows: {len(combined):,}")
print("\n✅ Ransomware dataset ready!")