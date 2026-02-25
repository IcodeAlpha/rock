"""
Script 12: Download Latest CISA KEV Dataset
Downloads Known Exploited Vulnerabilities catalog (updated daily)
Replaces old CISA data with fresh vulnerabilities
"""

import pandas as pd
import requests
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
RAW_DIR = DATA_DIR / 'raw'
PROCESSED_DIR = DATA_DIR / 'processed'

RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("📥 DOWNLOADING LATEST CISA KEV DATASET")
print("=" * 70)

# CISA KEV URL (official, updated daily)
KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

print(f"\n🌐 Fetching from: {KEV_URL}")
print("   This dataset is updated daily by CISA")

try:
    # Download CSV
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    
    # Save raw file
    raw_file = RAW_DIR / f'cisa_kev_{datetime.now().strftime("%Y%m%d")}.csv'
    raw_file.write_bytes(response.content)
    print(f"\n✅ Downloaded: {raw_file}")
    print(f"   Size: {len(response.content) / 1024:.1f} KB")
    
    # Load and process
    df = pd.read_csv(raw_file)
    print(f"\n📊 Dataset Info:")
    print(f"   Total CVEs: {len(df):,}")
    print(f"   Columns: {len(df.columns)}")
    
    # Show columns
    print("\n   Available columns:")
    for col in df.columns:
        print(f"      - {col}")
    
    # Show date range
    if 'dateAdded' in df.columns:
        df['dateAdded'] = pd.to_datetime(df['dateAdded'])
        print(f"\n   Date range:")
        print(f"      Oldest: {df['dateAdded'].min().date()}")
        print(f"      Newest: {df['dateAdded'].max().date()}")
    
    # Show vendors
    if 'vendorProject' in df.columns:
        print(f"\n   Top 10 vendors:")
        for vendor, count in df['vendorProject'].value_counts().head(10).items():
            print(f"      {vendor}: {count}")
    
    # Feature engineering for ML model
    print("\n🔧 Engineering features for vulnerability model...")
    
    # Days since added
    if 'dateAdded' in df.columns:
        df['days_since_added'] = (datetime.now() - df['dateAdded']).dt.days
    
    # Has due date
    if 'dueDate' in df.columns:
        df['has_due_date'] = df['dueDate'].notna().astype(int)
        df['dueDate'] = pd.to_datetime(df['dueDate'], errors='coerce')
        df['days_until_due'] = (df['dueDate'] - datetime.now()).dt.days
        df['days_until_due'] = df['days_until_due'].fillna(0).clip(lower=0)
    
    # Is ransomware related
    if 'shortDescription' in df.columns:
        df['is_ransomware'] = df['shortDescription'].str.contains(
            'ransomware|ransom', 
            case=False, 
            na=False
        ).astype(int)
    
    # Description length
    if 'shortDescription' in df.columns:
        df['description_length'] = df['shortDescription'].str.len().fillna(0)
    
    # Vendor and product encoding (for ML)
    if 'vendorProject' in df.columns:
        df['vendor_encoded'] = pd.factorize(df['vendorProject'])[0]
    
    if 'product' in df.columns:
        df['product_encoded'] = pd.factorize(df['product'])[0]
    
    # Save processed data
    processed_file = PROCESSED_DIR / 'cisa_kev_latest.csv'
    df.to_csv(processed_file, index=False)
    print(f"\n💾 Processed data saved to: {processed_file}")
    
    # Statistics
    print("\n📈 Feature Statistics:")
    if 'days_since_added' in df.columns:
        print(f"   Days since added: {df['days_since_added'].mean():.1f} (avg)")
    if 'is_ransomware' in df.columns:
        ransomware_count = df['is_ransomware'].sum()
        print(f"   Ransomware-related: {ransomware_count} ({ransomware_count/len(df)*100:.1f}%)")
    if 'has_due_date' in df.columns:
        due_count = df['has_due_date'].sum()
        print(f"   With due dates: {due_count} ({due_count/len(df)*100:.1f}%)")
    
    print("\n" + "=" * 70)
    print("✅ CISA KEV DATASET READY")
    print("=" * 70)
    
    print("\nNext steps:")
    print("   1. Use this data to retrain vulnerability model")
    print("   2. Run: python scripts/13_retrain_vulnerability_model.py")
    
except requests.RequestException as e:
    print(f"\n❌ Download failed: {e}")
    print("   Check your internet connection")
    print("   Or download manually from:")
    print("   https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
except Exception as e:
    print(f"\n❌ Processing failed: {e}")