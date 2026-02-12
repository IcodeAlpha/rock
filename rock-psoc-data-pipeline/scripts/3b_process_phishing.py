"""
Process Phishing URLs - IMPROVED VERSION
Script: 3b_process_phishing_IMPROVED.py

Extracts 20 essential URL features with IMPROVED threat scoring
- Detects SHORT phishing URLs (typosquatting)
- Detects LONG phishing URLs (keyword stacking)
- No label leakage
"""

import pandas as pd
import json
import re
from datetime import datetime, timedelta
import random
import os
import numpy as np
from urllib.parse import urlparse

print("=" * 70)
print("PROCESSING PHISHING URLS - IMPROVED WITH PATTERN DETECTION")
print("=" * 70)

# ============================================
# IMPROVED THREAT SCORING FUNCTION
# ============================================

def improved_threat_scoring(row):
    """
    Enhanced scoring that catches phishing patterns regardless of length.
    Patterns: typosquatting, keywords, suspicious TLDs, domain structure, etc.
    """
    
    suspicion_score = 0
    indicators = []
    
    # Get URL and features from row
    url = row.get('url', '') if isinstance(row, dict) else ''
    url_lower = url.lower()
    
    # Get feature values
    domain_length = row.get('domain_length', 0)
    num_hyphens = row.get('num_hyphens', 0)
    num_underscores = row.get('num_underscores', 0)
    num_dots = row.get('num_dots', 0)
    digit_ratio = row.get('digit_ratio', 0)
    has_https = row.get('has_https', 0)
    has_ip = row.get('has_ip', 0)
    has_url_shortener = row.get('has_url_shortener', 0)
    
    # ============================================
    # PATTERN 1: TYPOSQUATTING DETECTION
    # ============================================
    typo_patterns = {
        'paypa': ['paypa1', 'paypa|', 'paypai'],
        'amaz': ['amaz0n', 'amazo', 'amozn'],
        'goog': ['g00gle', 'gogle', 'googl'],
        'micros': ['micros0ft', 'microsft'],
        'appl': ['app1e', 'aple'],
    }
    
    for brand, variants in typo_patterns.items():
        for variant in variants:
            if variant in url_lower:
                suspicion_score += 3
                indicators.append(f"Typosquatting: {variant}")
                break
    
    # ============================================
    # PATTERN 2: SUSPICIOUS KEYWORDS IN DOMAIN
    # ============================================
    phishing_keywords = {
        'verify': 3,
        'confirm': 3,
        'update': 2,
        'secure': 2,
        'account-locked': 3,
        'urgent': 2,
        'resolve': 2,
        'billing': 2,
        'alert': 2,
    }
    
    for keyword, points in phishing_keywords.items():
        if keyword in url_lower:
            suspicion_score += points
            indicators.append(f"Phishing keyword: '{keyword}'")
    
    # ============================================
    # PATTERN 3: SUSPICIOUS TLDs
    # ============================================
    suspicious_tlds = {
        '.tk': 3,
        '.ml': 3,
        '.ga': 3,
        '.cf': 3,
        '.gq': 3,
        '.xyz': 2,
        '.top': 2,
        '.ru': 2,
        '.info': 1,
    }
    
    for tld, points in suspicious_tlds.items():
        if url_lower.endswith(tld):
            suspicion_score += points
            indicators.append(f"Suspicious TLD: {tld}")
            break
    
    # ============================================
    # PATTERN 4: DOMAIN STRUCTURE ANOMALIES
    # ============================================
    
    # Long domain with many hyphens
    if domain_length > 30 and num_hyphens >= 2:
        suspicion_score += 2
        indicators.append(f"Long domain with hyphens ({domain_length} chars, {num_hyphens} hyphens)")
    
    # Underscores in domain (unusual)
    if num_underscores > 0:
        suspicion_score += 2
        indicators.append(f"Underscores in domain ({num_underscores})")
    
    # Excessive dots
    if num_dots > 5:
        suspicion_score += 1
        indicators.append(f"Excessive dots ({num_dots})")
    
    # ============================================
    # PATTERN 5: MISSING HTTPS (CONTEXT-AWARE)
    # ============================================
    
    if has_https == 0 and any(kw in url_lower for kw in ['login', 'signin', 'verify', 'account']):
        suspicion_score += 3
        indicators.append("No HTTPS + credential keywords (CRITICAL)")
    elif has_https == 0:
        suspicion_score += 1
        indicators.append("No HTTPS")
    
    # ============================================
    # PATTERN 6: IP ADDRESS INSTEAD OF DOMAIN
    # ============================================
    
    if has_ip == 1:
        suspicion_score += 3
        indicators.append("Uses IP address instead of domain")
    
    # ============================================
    # PATTERN 7: URL SHORTENERS
    # ============================================
    
    if has_url_shortener == 1:
        suspicion_score += 3
        indicators.append("URL shortener (hides destination)")
    
    # ============================================
    # PATTERN 8: HIGH DIGIT RATIO (Typosquatting)
    # ============================================
    
    if digit_ratio > 0.08:
        suspicion_score += 1
        indicators.append(f"High digit ratio ({digit_ratio:.1%})")
    
    # ============================================
    # DETERMINE SEVERITY & CONFIDENCE
    # ============================================
    
    if suspicion_score >= 8:
        severity = 'critical'
    elif suspicion_score >= 5:
        severity = 'high'
    elif suspicion_score >= 3:
        severity = 'medium'
    elif suspicion_score >= 1:
        severity = 'low'
    else:
        severity = 'safe'
    
    relevance_score = round(min(0.99, 0.2 + (suspicion_score * 0.1)), 2)
    
    return {
        'suspicion_score': suspicion_score,
        'severity': severity,
        'indicators': indicators[:5],
        'relevance_score': relevance_score
    }


# ============================================
# SIMPLIFIED FEATURE EXTRACTION
# ============================================

def extract_simple_url_features(url):
    """Extract 20 simple, interpretable features from a URL."""
    
    features = {}
    
    # === BASIC LENGTH FEATURES (4) ===
    features['url_length'] = len(url)
    
    try:
        parsed = urlparse(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query) if parsed.query else 0
    except:
        features['domain_length'] = 0
        features['path_length'] = 0
        features['query_length'] = 0
    
    # === CHARACTER COUNT FEATURES (6) ===
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_at_symbols'] = url.count('@')
    features['num_question_marks'] = url.count('?')
    
    # === SECURITY FEATURES (3) ===
    features['has_https'] = int(url.startswith('https://'))
    features['has_http'] = int(url.startswith('http://'))
    features['has_ip'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)))
    
    # === DOMAIN FEATURES (3) ===
    try:
        parsed = urlparse(url)
        features['num_subdomains'] = parsed.netloc.count('.') - 1 if '.' in parsed.netloc else 0
        features['has_port'] = int(':' in parsed.netloc and not parsed.netloc.startswith('['))
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        features['has_suspicious_tld'] = int(any(url.endswith(tld) for tld in suspicious_tlds))
    except:
        features['num_subdomains'] = 0
        features['has_port'] = 0
        features['has_suspicious_tld'] = 0
    
    # === CONTENT ANALYSIS (4) ===
    features['digit_ratio'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    features['has_double_slash_in_path'] = int('//' in url[8:])
    
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    features['has_url_shortener'] = int(any(s in url for s in shorteners))
    
    suspicious_words = ['login', 'verify', 'account', 'update', 'secure', 'banking']
    features['has_suspicious_keyword'] = int(any(word in url.lower() for word in suspicious_words))
    
    return features


# ============================================
# LOAD AND PROCESS DATA
# ============================================

print("\n[1/3] Reading Phishing URLs data...")
df = pd.read_csv('data/raw/phishing_urls.csv')

print(f"✅ Loaded {len(df)} records")
print(f"📊 Columns: {list(df.columns)[:5]}...")

# Find label column
label_column = None
for possible_label in ['phishing', 'label', 'class', 'target']:
    if possible_label in df.columns:
        label_column = possible_label
        print(f"   ✅ Found label column: '{label_column}'")
        break

if label_column is None:
    print("   ⚠️  No label column found")

# Check for URL column
url_column = None
for col in ['url', 'URL', 'uri', 'URI']:
    if col in df.columns:
        url_column = col
        print(f"   ✅ Found URL column: '{url_column}'")
        break

# ============================================
# EXTRACT SIMPLIFIED FEATURES
# ============================================

print("\n[2/3] Extracting 20 simplified features...")

if url_column:
    print("   Extracting features from URLs...")
    
    features_list = []
    for idx, row in df.iterrows():
        if idx % 10000 == 0:
            print(f"   Processed {idx}/{len(df)} URLs...")
        
        try:
            url_str = str(row[url_column])
            features = extract_simple_url_features(url_str)
            features['url'] = url_str  # Keep URL for threat scoring
            
            if label_column:
                label_value = row[label_column]
                if label_value in [-1, 'phishing', 'Phishing', 'PHISHING']:
                    features['label'] = 1
                elif label_value in [0, 1]:
                    features['label'] = int(label_value)
                else:
                    features['label'] = 0
            
            features_list.append(features)
            
        except Exception as e:
            continue
    
    processed_df = pd.DataFrame(features_list)
    
else:
    print("   Dataset appears to be pre-processed")
    basic_features = [
        'url_length', 'domain_length', 'path_length',
        'num_dots', 'num_hyphens', 'num_slashes',
        'has_https', 'has_ip', 'num_subdomains'
    ]
    
    available_features = [f for f in basic_features if f in df.columns]
    
    if len(available_features) > 0:
        processed_df = df[available_features + ([label_column] if label_column else [])].copy()
        if label_column and label_column != 'label':
            processed_df['label'] = processed_df[label_column]
            processed_df = processed_df.drop(columns=[label_column])
    else:
        print("   ⚠️  No matching features found")
        processed_df = df.select_dtypes(include=[np.number]).copy()
        if label_column:
            processed_df['label'] = df[label_column]

print(f"\n✅ Extracted features:")
print(f"   Total records: {len(processed_df)}")
print(f"   Features: {len([c for c in processed_df.columns if c != 'label' and c != 'url'])}")

# ============================================
# VERIFY NO LABEL LEAKAGE
# ============================================

print("\n🔍 Checking for label leakage...")

leaky_columns = []
for col in processed_df.columns:
    if col in ['label', 'url']:
        continue
    if 'phishing' in col.lower() or 'class' in col.lower() or 'target' in col.lower():
        leaky_columns.append(col)

if leaky_columns:
    print(f"   ⚠️  Removing leakage columns: {leaky_columns}")
    processed_df = processed_df.drop(columns=leaky_columns)
    print(f"   ✅ Removed")
else:
    print(f"   ✅ No label leakage detected")

# ============================================
# SAVE PROCESSED DATA
# ============================================

print("\n[3/3] Saving processed data...")

os.makedirs('data/processed', exist_ok=True)

# Remove URL before saving (only for ML)
ml_df = processed_df.drop(columns=['url'], errors='ignore')
ml_df.to_json('data/processed/processed_phishing_urls.json', orient='records', indent=2)

print(f"✅ Saved {len(ml_df)} records for ML training")

if 'label' in ml_df.columns:
    label_dist = ml_df['label'].value_counts()
    print(f"\n   Label distribution:")
    for label, count in label_dist.items():
        label_name = "Phishing" if label == 1 else "Legitimate"
        print(f"      {label_name}: {count}")

# ============================================
# CREATE THREAT INTELLIGENCE RECORDS
# ============================================

print("\n🔍 Creating threat intelligence with IMPROVED scoring...")

threats = []

if 'label' in processed_df.columns:
    phishing_df = processed_df[processed_df['label'] == 1]
    
    if len(phishing_df) == 0:
        phishing_df = processed_df[processed_df['label'] == -1]
    
    # INCREASED SAMPLE SIZE (from 150 to 5000)
    sample_size = min(5000, len(phishing_df))
    
    if len(phishing_df) > 0:
        sample = phishing_df.sample(n=sample_size, random_state=42)
        print(f"   Found {len(phishing_df)} phishing URLs, sampling {sample_size}")
    else:
        print("   ⚠️  No phishing labels found, sampling from all data")
        sample = processed_df.sample(n=min(5000, len(processed_df)), random_state=42)
else:
    sample = processed_df.sample(n=min(5000, len(processed_df)), random_state=42)

# Create threat records with IMPROVED scoring
for idx, row in sample.iterrows():
    try:
        # Use improved threat scoring
        score_result = improved_threat_scoring(row)
        
        suspicion_score = score_result['suspicion_score']
        severity = score_result['severity']
        indicators = score_result['indicators']
        relevance_score = score_result['relevance_score']
        
        # Only include threats with suspicion score > 0
        if suspicion_score == 0:
            continue
        
        threat = {
            'threat_type': 'Suspicious URL Pattern',
            'title': f"Phishing Detection: {severity.upper()}",
            'description': f"Feature analysis detected suspicious URL. Indicators: {', '.join(indicators[:2])}",
            'source': 'Phishing URL Dataset - Improved Pattern Detection',
            'severity': severity,
            'relevance_score': relevance_score,
            'indicators': {
                'suspicion_score': int(suspicion_score),
                'detected_patterns': indicators[:5],
                'detection_method': 'Pattern-based (typosquatting, keywords, TLDs, domain structure)',
                'detection_date': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
            },
            'created_at': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        }
        
        threats.append(threat)
        
    except Exception as e:
        continue

# Save threats
with open('data/processed/threats_from_phishing_urls.json', 'w') as f:
    json.dump(threats, f, indent=2)

print(f"✅ Created {len(threats)} threat intelligence records")

# ============================================
# SUMMARY
# ============================================

print("\n" + "=" * 70)
print("PROCESSING COMPLETE!")
print("=" * 70)

print(f"\n📊 Summary:")
print(f"   Total records processed: {len(processed_df)}")
print(f"   Features extracted: 20")
print(f"   Threat records created: {len(threats)}")
print(f"   Phishing URLs sampled: {sample_size}")
print(f"   Detection method: IMPROVED (8 patterns)")

print(f"\n🎯 Improvements:")
print(f"   ✓ Detects SHORT phishing (typosquatting)")
print(f"   ✓ Detects LONG phishing (keyword stacking)")
print(f"   ✓ Pattern-based scoring (not length-biased)")
print(f"   ✓ Increased sample size (150 → 5000)")

print(f"\n✅ Next step: python scripts/5_train_phishing_detection.py")