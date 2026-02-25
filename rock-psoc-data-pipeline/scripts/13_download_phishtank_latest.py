"""
Script 13: Download Fresh PhishTank Dataset
Downloads latest phishing URLs (updated hourly)
Replaces old phishing data with fresh samples
"""

import pandas as pd
import requests
from pathlib import Path
from datetime import datetime
import time

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
RAW_DIR = DATA_DIR / 'raw'
PROCESSED_DIR = DATA_DIR / 'processed'

RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("📥 DOWNLOADING FRESH PHISHTANK DATASET")
print("=" * 70)

# PhishTank URL (updated hourly)
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"

print(f"\n🌐 Fetching from: {PHISHTANK_URL}")
print("   This dataset is updated hourly by PhishTank community")

try:
    # Download CSV
    print("\n⏳ Downloading... (this may take a minute)")
    response = requests.get(PHISHTANK_URL, timeout=60)
    response.raise_for_status()
    
    # Save raw file
    raw_file = RAW_DIR / f'phishtank_{datetime.now().strftime("%Y%m%d_%H%M")}.csv'
    raw_file.write_bytes(response.content)
    print(f"\n✅ Downloaded: {raw_file}")
    print(f"   Size: {len(response.content) / (1024*1024):.1f} MB")
    
    # Load and process
    df = pd.read_csv(raw_file)
    print(f"\n📊 Dataset Info:")
    print(f"   Total phishing URLs: {len(df):,}")
    print(f"   Columns: {len(df.columns)}")
    
    # Show columns
    print("\n   Available columns:")
    for col in df.columns:
        print(f"      - {col}")
    
    # Feature engineering
    print("\n🔧 Engineering URL features for phishing detection...")
    
    # Extract URL features
    if 'url' in df.columns:
        df['url_length'] = df['url'].str.len()
        df['num_dots'] = df['url'].str.count('\.')
        df['num_hyphens'] = df['url'].str.count('-')
        df['num_underscores'] = df['url'].str.count('_')
        df['num_slashes'] = df['url'].str.count('/')
        df['num_at_symbols'] = df['url'].str.count('@')
        df['num_question_marks'] = df['url'].str.count('\?')
        
        # Protocol features
        df['has_https'] = df['url'].str.contains('https://', na=False).astype(int)
        df['has_http'] = df['url'].str.contains('http://', na=False).astype(int)
        
        # Domain features
        df['has_ip'] = df['url'].str.contains(
            r'\d+\.\d+\.\d+\.\d+', 
            regex=True, 
            na=False
        ).astype(int)
        
        # Suspicious patterns
        df['has_suspicious_tld'] = df['url'].str.contains(
            r'\.(tk|ml|ga|cf|gq)/', 
            regex=True, 
            na=False
        ).astype(int)
        
        df['has_url_shortener'] = df['url'].str.contains(
            r'(bit\.ly|goo\.gl|tinyurl|ow\.ly)', 
            regex=True, 
            na=False
        ).astype(int)
        
        df['has_suspicious_keyword'] = df['url'].str.contains(
            r'(verify|update|secure|login|account|confirm|banking|paypal)', 
            regex=True, 
            case=False,
            na=False
        ).astype(int)
        
        # Subdomain count
        df['num_subdomains'] = df['url'].str.extract(r'https?://([^/]+)')[0].str.count('\.')
        
        # Domain length
        df['domain_length'] = df['url'].str.extract(r'https?://([^/]+)')[0].str.len()
        
        # Path features
        df['has_double_slash_in_path'] = df['url'].str.contains(
            r'//[^/]', 
            regex=True, 
            na=False
        ).astype(int)
        
        # Digit ratio
        df['digit_ratio'] = df['url'].apply(
            lambda x: sum(c.isdigit() for c in str(x)) / len(str(x)) if len(str(x)) > 0 else 0
        )
    
    # Label (1 = phishing, 0 = legitimate)
    # All PhishTank URLs are phishing
    df['is_phishing'] = 1
    
    # For training, we need negative samples (legitimate URLs)
    # Note: You'd need to add legitimate URLs from another source
    # For now, we're marking these as phishing
    
    print(f"\n📊 Feature Statistics:")
    if 'url_length' in df.columns:
        print(f"   Avg URL length: {df['url_length'].mean():.1f}")
        print(f"   Avg dots: {df['num_dots'].mean():.1f}")
        print(f"   HTTPS: {df['has_https'].sum()} ({df['has_https'].mean()*100:.1f}%)")
        print(f"   Has IP: {df['has_ip'].sum()} ({df['has_ip'].mean()*100:.1f}%)")
        print(f"   Suspicious keywords: {df['has_suspicious_keyword'].sum()} ({df['has_suspicious_keyword'].mean()*100:.1f}%)")
    
    # Save processed data
    processed_file = PROCESSED_DIR / 'phishtank_latest.csv'
    df.to_csv(processed_file, index=False)
    print(f"\n💾 Processed data saved to: {processed_file}")
    
    print("\n" + "=" * 70)
    print("✅ PHISHTANK DATASET READY")
    print("=" * 70)
    
    print("\n⚠️  Important Note:")
    print("   PhishTank only contains phishing URLs (positive samples)")
    print("   For model training, you also need legitimate URLs (negative samples)")
    print("   Consider adding Alexa Top 1M or similar dataset for balance")
    
    print("\nNext steps:")
    print("   1. Add legitimate URL dataset")
    print("   2. Combine phishing + legitimate URLs")
    print("   3. Run: python scripts/14_retrain_phishing_model.py")
    
except requests.RequestException as e:
    print(f"\n❌ Download failed: {e}")
    print("   Check your internet connection")
    print("   Or download manually from:")
    print("   http://www.phishtank.com/developer_info.php")
except Exception as e:
    print(f"\n❌ Processing failed: {e}")