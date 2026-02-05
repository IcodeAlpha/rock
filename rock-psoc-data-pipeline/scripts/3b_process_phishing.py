"""
Process Feature-Engineered Phishing URLs dataset into threat intelligence records
Script: 3b_process_phishing.py

Extracts features from raw phishing URLs and creates processed dataset for ML training
"""

import pandas as pd
import json
import re
from datetime import datetime, timedelta
import random
import os

print("=" * 50)
print("PROCESSING PHISHING URLS DATASET")
print("=" * 50)

# ============================================
# FEATURE EXTRACTION FUNCTIONS
# ============================================

def extract_url_features(url):
    """Extract meaningful features from a URL for phishing detection"""
    
    features = {}
    
    # Basic metrics
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_at'] = url.count('@')
    features['num_ampersand'] = url.count('&')
    features['num_hash'] = url.count('#')
    features['num_percent'] = url.count('%')
    
    # Character analysis
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
    
    # Protocol and security
    features['has_https'] = int(url.startswith('https://'))
    features['has_http'] = int(url.startswith('http://'))
    
    # IP address in URL (suspicious)
    features['has_ip'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    
    # Parse URL components
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['num_subdomains'] = parsed.netloc.count('.') - 1 if '.' in parsed.netloc else 0
        features['has_port'] = int(':' in parsed.netloc and not parsed.netloc.startswith('['))
    except:
        features['domain_length'] = 0
        features['path_length'] = 0
        features['num_subdomains'] = 0
        features['has_port'] = 0
    
    # Suspicious patterns
    features['has_double_slash_in_path'] = int('//' in url[8:])  # After protocol
    features['has_shortened_url'] = int(any(shortener in url for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']))
    
    return features

# ============================================
# LOAD AND ANALYZE DATA
# ============================================

print("\nReading Phishing URLs data...")
df = pd.read_csv('data/raw/phishing_urls.csv')

print(f"✅ Loaded {len(df)} records")
print(f"📊 Dataset has {len(df.columns)} columns")

# Check dataset structure
print("\n🔍 Analyzing dataset structure...")
print(f"   Columns: {list(df.columns[:10])}...")  # Show first 10 columns

# Check if this is already feature-engineered or raw URLs
if 'url' in df.columns:
    print("   ✅ Found 'url' column - will extract features")
    needs_feature_extraction = True
    url_column = 'url'
elif any('qty' in col.lower() or 'length' in col.lower() for col in df.columns):
    print("   ✅ Dataset appears to be feature-engineered already")
    needs_feature_extraction = False
else:
    print("   ⚠️  Unexpected dataset format")
    needs_feature_extraction = False

# Check for label column
label_column = None
for possible_label in ['phishing', 'label', 'class', 'target']:
    if possible_label in df.columns:
        label_column = possible_label
        print(f"   ✅ Found label column: '{label_column}'")
        print(f"   Distribution: {df[label_column].value_counts().to_dict()}")
        break

# ============================================
# FEATURE EXTRACTION (if needed)
# ============================================

if needs_feature_extraction and 'url' in df.columns:
    print("\n🔧 Extracting features from URLs...")
    
    features_list = []
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"   Processed {idx}/{len(df)} URLs...")
        
        try:
            features = extract_url_features(row['url'])
            if label_column:
                features['label'] = row[label_column]
            features_list.append(features)
        except Exception as e:
            continue
    
    # Create new DataFrame with extracted features
    processed_df = pd.DataFrame(features_list)
    print(f"\n✅ Extracted {len(processed_df.columns)} features")
    
else:
    # Use existing features
    print("\n✅ Using existing feature-engineered dataset")
    processed_df = df.copy()
    
    # Rename label column if needed
    if label_column and label_column != 'label':
        processed_df['label'] = processed_df[label_column]

# ============================================
# SAVE PROCESSED DATA FOR ML TRAINING
# ============================================

print("\n💾 Saving processed data for ML training...")

# Ensure output directory exists
os.makedirs('data/processed', exist_ok=True)

# Save as JSON for ML training
processed_df.to_json('data/processed/processed_phishing_urls.json', orient='records', indent=2)

print(f"✅ Saved {len(processed_df)} records to: data/processed/processed_phishing_urls.json")
print(f"   Features: {len(processed_df.columns)}")

# ============================================
# CREATE THREAT INTELLIGENCE RECORDS
# ============================================

print("\n🔍 Creating threat intelligence records...")

# Identify suspicious URLs for threat database
threats = []

# Take sample for threat intelligence (actual phishing URLs or high suspicion scores)
if 'label' in processed_df.columns:
    # Get confirmed phishing URLs
    phishing_df = processed_df[processed_df['label'] == 1]  # Assuming 1 = phishing
    if len(phishing_df) == 0:
        phishing_df = processed_df[processed_df['label'] == -1]  # Try -1
    
    sample_size = min(150, len(phishing_df))
    if len(phishing_df) > 0:
        sample = phishing_df.sample(n=sample_size, random_state=42)
        print(f"   Found {len(phishing_df)} confirmed phishing URLs")
    else:
        print("   ⚠️  No confirmed phishing labels found, using statistical analysis...")
        sample = processed_df.sample(n=min(150, len(processed_df)), random_state=42)
else:
    sample = processed_df.sample(n=min(150, len(processed_df)), random_state=42)

# Create threat records
for idx, row in sample.iterrows():
    try:
        # Calculate suspicion score based on available features
        suspicion_score = 0
        indicators = []
        
        # Check common phishing indicators
        if 'url_length' in row.index and row['url_length'] > 75:
            suspicion_score += 1
            indicators.append(f"Long URL ({int(row['url_length'])} chars)")
        
        if 'num_dots' in row.index and row['num_dots'] > 4:
            suspicion_score += 2
            indicators.append(f"Excessive dots ({int(row['num_dots'])})")
        
        if 'has_ip' in row.index and row['has_ip'] == 1:
            suspicion_score += 3
            indicators.append("Uses IP address instead of domain")
        
        if 'has_https' in row.index and row['has_https'] == 0:
            suspicion_score += 2
            indicators.append("No HTTPS encryption")
        
        if 'has_shortened_url' in row.index and row['has_shortened_url'] == 1:
            suspicion_score += 2
            indicators.append("URL shortener detected")
        
        if 'num_hyphens' in row.index and row['num_hyphens'] > 3:
            suspicion_score += 1
            indicators.append(f"Multiple hyphens ({int(row['num_hyphens'])})")
        
        # Check feature-engineered columns if present
        if 'domain_in_ip' in row.index and row['domain_in_ip'] == 1:
            suspicion_score += 3
            indicators.append("Domain uses IP address")
        
        if 'tls_ssl_certificate' in row.index and row['tls_ssl_certificate'] == -1:
            suspicion_score += 3
            indicators.append("Invalid TLS/SSL certificate")
        
        # Skip if no indicators
        if suspicion_score == 0:
            continue
        
        # Determine severity
        if suspicion_score >= 6:
            severity = 'critical'
        elif suspicion_score >= 4:
            severity = 'high'
        elif suspicion_score >= 2:
            severity = 'medium'
        else:
            severity = 'low'
        
        relevance_score = round(min(0.95, 0.3 + (suspicion_score * 0.12)), 2)
        
        threat = {
            'threat_type': 'Suspicious URL Pattern',
            'title': f"Phishing URL Detection: {severity.upper()}",
            'description': f"Feature analysis detected suspicious URL characteristics. {' '.join(indicators[:2])}",
            'source': 'Phishing URL Dataset Analysis',
            'severity': severity,
            'relevance_score': relevance_score,
            'indicators': {
                'suspicion_score': int(suspicion_score),
                'detected_indicators': indicators[:5],
                'detection_date': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
            },
            'created_at': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        }
        
        threats.append(threat)
    except Exception as e:
        continue

# Save threat intelligence
with open('data/processed/threats_from_phishing_urls.json', 'w') as f:
    json.dump(threats, f, indent=2)

print(f"✅ Created {len(threats)} threat intelligence records")
print("✅ Saved to: data/processed/threats_from_phishing_urls.json")

# ============================================
# SUMMARY STATISTICS
# ============================================

print("\n" + "=" * 50)
print("PROCESSING COMPLETE!")
print("=" * 50)

print(f"\n📊 Dataset Summary:")
print(f"   Total records: {len(processed_df)}")
print(f"   Features extracted: {len(processed_df.columns)}")

if 'label' in processed_df.columns:
    print(f"\n   Label distribution:")
    for label, count in processed_df['label'].value_counts().items():
        print(f"      {label}: {count}")

if threats:
    print(f"\n🎯 Threat Intelligence:")
    print(f"   Total threats: {len(threats)}")
    
    severity_counts = {}
    for threat in threats:
        sev = threat['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"   Severity breakdown:")
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in severity_counts:
            print(f"      {severity}: {severity_counts[severity]}")

print("\n✅ Ready for ML training!")
print("   Next: Run 4_train_intrusion_detection.py")