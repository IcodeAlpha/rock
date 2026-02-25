"""
Script 9: Process UNSW-NB15 Dataset (already downloaded)
"""

import pandas as pd
import numpy as np
from pathlib import Path

# Setup paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
RAW_DIR = DATA_DIR / 'raw' / 'unsw_nb15'
PROCESSED_DIR = DATA_DIR / 'processed'

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("🔄 PROCESSING UNSW-NB15 DATASET")
print("=" * 70)

# Use the pre-split training and testing sets (fastest option)
train_file = RAW_DIR / 'UNSW_NB15_training-set.csv'
test_file = RAW_DIR / 'UNSW_NB15_testing-set.csv'

if train_file.exists() and test_file.exists():
    print(f"\n📥 Loading training set: {train_file.stat().st_size / (1024*1024):.1f} MB")
    train_df = pd.read_csv(train_file)
    print(f"   Rows: {len(train_df):,}  Columns: {len(train_df.columns)}")

    print(f"\n📥 Loading testing set: {test_file.stat().st_size / (1024*1024):.1f} MB")
    test_df = pd.read_csv(test_file)
    print(f"   Rows: {len(test_df):,}  Columns: {len(test_df.columns)}")

    combined_df = pd.concat([train_df, test_df], ignore_index=True)
    print(f"\n✅ Combined: {len(combined_df):,} rows")

else:
    # Fall back to the 4 main CSV files
    print("\n📥 Loading from main CSV files...")
    csv_files = sorted(RAW_DIR.glob('UNSW-NB15_*.csv'))
    csv_files = [f for f in csv_files if 'LIST' not in f.name and 'features' not in f.name.lower()]

    # Load feature names
    feature_file = RAW_DIR / 'NUSW-NB15_features.csv'
    if feature_file.exists():
        feat_df = pd.read_csv(feature_file, encoding='latin1')
        col_names = feat_df['Name'].tolist()
        print(f"   Found {len(col_names)} feature names")
    else:
        col_names = None

    dfs = []
    for f in csv_files:
        print(f"   Loading {f.name} ({f.stat().st_size / (1024*1024):.1f} MB)...")
        try:
            df = pd.read_csv(f, header=None if col_names else 0,
                             names=col_names if col_names else None,
                             low_memory=False)
            dfs.append(df)
        except Exception as e:
            print(f"   ⚠️  Skipping {f.name}: {e}")

    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"\n✅ Combined: {len(combined_df):,} rows")

# Print columns to diagnose
print(f"\n📋 Columns: {list(combined_df.columns[:10])} ...")

# Identify label column
label_col = None
for candidate in ['label', 'Label', 'attack_cat', 'class', 'Class']:
    if candidate in combined_df.columns:
        label_col = candidate
        break

if label_col:
    print(f"\n🎯 Label column: '{label_col}'")
    print(f"   Values: {combined_df[label_col].value_counts().to_dict()}")
    combined_df['attack_type'] = combined_df[label_col].apply(
        lambda x: 'normal' if str(x).strip() in ['0', 'Normal', 'normal'] else 'attack'
    )
else:
    print("⚠️  No label column found — creating dummy 'normal' label")
    combined_df['attack_type'] = 'normal'

# Clean data
print("\n🧹 Cleaning data...")
combined_df = combined_df.replace([np.inf, -np.inf], np.nan)
before = len(combined_df)
combined_df = combined_df.dropna(thresh=int(len(combined_df.columns) * 0.5))
combined_df = combined_df.drop_duplicates()
print(f"   Removed {before - len(combined_df):,} bad rows. Remaining: {len(combined_df):,}")

# Fill remaining NaN
numeric_cols = combined_df.select_dtypes(include=[np.number]).columns
for col in numeric_cols:
    if combined_df[col].isna().any():
        combined_df[col].fillna(combined_df[col].median(), inplace=True)

# Save
output_file = PROCESSED_DIR / 'unsw_nb15_processed.csv'
print(f"\n💾 Saving to: {output_file}")
combined_df.to_csv(output_file, index=False)

size_mb = output_file.stat().st_size / (1024*1024)
print(f"\n✅ Done!")
print(f"   File: {output_file}")
print(f"   Size: {size_mb:.1f} MB")
print(f"   Rows: {len(combined_df):,}")
print(f"   Features: {len(combined_df.columns)}")
print(f"   Attack distribution: {combined_df['attack_type'].value_counts().to_dict()}")

# Save feature list
features = [c for c in combined_df.columns if c not in ['attack_type', 'label', 'Label', 'attack_cat']]
feat_out = PROCESSED_DIR / 'unsw_nb15_features.txt'
with open(feat_out, 'w') as f:
    f.write('\n'.join(features))
print(f"   Feature list saved: {feat_out}")