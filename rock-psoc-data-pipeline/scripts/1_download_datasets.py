"""
This script downloads cybersecurity datasets from the internet
and saves them to the data/raw folder.
"""

import requests
import pandas as pd
from pathlib import Path

# Create data folders if they don't exist
Path('data/raw').mkdir(parents=True, exist_ok=True)

print("=" * 50)
print("DATASET DOWNLOADER")
print("=" * 50)

# Dataset 1: NSL-KDD (Network Intrusion Detection)
print("\n1. Downloading NSL-KDD dataset...")
print("   This contains 125,000+ records of network attacks")

try:
    # Download the training dataset
    url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    
    print("   Downloading... (this may take 1-2 minutes)")
    response = requests.get(url)
    
    # Save to file
    with open('data/raw/nsl_kdd_train.csv', 'wb') as f:
        f.write(response.content)
    
    print("   ✅ Downloaded: data/raw/nsl_kdd_train.csv")
    
    # Read it to show you what's inside
    df = pd.read_csv('data/raw/nsl_kdd_train.csv', header=None)
    print(f"   📊 Dataset size: {len(df)} rows, {len(df.columns)} columns")
    print(f"   👀 First row preview:")
    print(f"      {df.iloc[0][:5].tolist()}...")  # Show first 5 values
    
except Exception as e:
    print(f"   ❌ Error: {e}")

# Dataset 2: CISA Known Exploited Vulnerabilities
print("\n2. Downloading CISA KEV catalog...")
print("   This contains real vulnerabilities hackers are exploiting")

try:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    print("   Downloading...")
    response = requests.get(url)
    data = response.json()
    
    # Convert to CSV for easier processing
    df = pd.DataFrame(data['vulnerabilities'])
    df.to_csv('data/raw/cisa_kev.csv', index=False)
    
    print("   ✅ Downloaded: data/raw/cisa_kev.csv")
    print(f"   📊 Dataset size: {len(df)} vulnerabilities")
    print(f"   👀 Sample vulnerability:")
    print(f"      CVE: {df.iloc[0]['cveID']}")
    print(f"      Name: {df.iloc[0]['vulnerabilityName']}")
    
except Exception as e:
    print(f"   ❌ Error: {e}")

# Dataset 3: Phishing URLs
print("\n3. Downloading Phishing URLs dataset...")
print("   This contains 11,000+ phishing website URLs")

try:
    # This dataset is from a GitHub repo
    url = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_full.csv"
    
    print("   Downloading...")
    df = pd.read_csv(url)
    df.to_csv('data/raw/phishing_urls.csv', index=False)
    
    print("   ✅ Downloaded: data/raw/phishing_urls.csv")
    print(f"   📊 Dataset size: {len(df)} URLs")
    print(f"   👀 Sample URL: {df.iloc[0]['url']}")
    
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n" + "=" * 50)
print("DOWNLOAD COMPLETE!")
print("=" * 50)
print("\nYour datasets are in: data/raw/")
print("Next step: Run 2_process_nsl_kdd.py")