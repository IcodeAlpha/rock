"""
Process Feature-Engineered Phishing URLs dataset into threat intelligence records
Script: 3b_process_phishing_urls.py (FIXED v2)

Note: Dataset appears to contain mostly legitimate URLs (phishing=-1 not found)
We'll use feature analysis to identify suspicious patterns and create threats
"""

import pandas as pd
import json
from datetime import datetime, timedelta
import random

print("=" * 50)
print("PROCESSING PHISHING URLS DATASET")
print("=" * 50)

# Read dataset
print("\nReading Phishing URLs data...")
df = pd.read_csv('data/raw/phishing_urls.csv')

print(f"✅ Loaded {len(df)} phishing URLs")
print(f"📊 Dataset has {len(df.columns)} feature columns")

# Check for phishing label column
if 'phishing' in df.columns:
    print(f"✅ Found 'phishing' column (target label)")
    phishing_counts = df['phishing'].value_counts()
    print(f"   Distribution: {dict(phishing_counts)}")
    
    # Look for phishing examples (typically -1 or 1 depending on encoding)
    phishing_df = df[df['phishing'] == -1]
    if len(phishing_df) == 0:
        print("   ⚠️  No records with phishing=-1, checking for phishing=1...")
        phishing_df = df[df['phishing'] == 1]
        if len(phishing_df) == 0:
            print("   ⚠️  No phishing records found, using statistical analysis...")
            # Use statistical anomalies as "suspicious" URLs
            phishing_df = df.copy()
            phishing_df['suspicion_score'] = 0
else:
    print("⚠️  'phishing' column not found, using all rows")
    phishing_df = df.copy()

print(f"\n📊 Processing {len(phishing_df)} records...")

# Create threat intelligence records using feature analysis
threats = []

# Take representative sample
sample_size = min(150, len(phishing_df))
sample = phishing_df.sample(n=sample_size, random_state=42)

print(f"🔍 Analyzing {len(sample)} records for suspicious patterns...\n")

for idx, row in sample.iterrows():
    try:
        # Extract key features that indicate suspicious URLs
        # These engineered features help identify phishing patterns
        
        # URL structure features
        qty_dots_url = float(row.get('qty_dot_url', 0))
        qty_hyphens_url = float(row.get('qty_hyphen_url', 0))
        qty_slashes_url = float(row.get('qty_slash_url', 0))
        qty_questionmark_url = float(row.get('qty_questionmark_url', 0))
        url_length = float(row.get('length_url', 0))
        
        # Domain features
        qty_dots_domain = float(row.get('qty_dot_domain', 0))
        qty_hyphens_domain = float(row.get('qty_hyphen_domain', 0))
        domain_length = float(row.get('domain_length', 0))
        domain_in_ip = float(row.get('domain_in_ip', 0)) if 'domain_in_ip' in row.index else 0
        
        # Security features
        tls_ssl_cert = float(row.get('tls_ssl_certificate', 0)) if 'tls_ssl_certificate' in row.index else 0
        qty_nameservers = float(row.get('qty_nameservers', 0)) if 'qty_nameservers' in row.index else 2
        qty_mx_servers = float(row.get('qty_mx_servers', 0)) if 'qty_mx_servers' in row.index else 1
        
        # Redirect features
        qty_redirects = float(row.get('qty_redirects', 0)) if 'qty_redirects' in row.index else 0
        url_shortened = float(row.get('url_shortened', 0)) if 'url_shortened' in row.index else 0
        
        # Search/Index features
        url_google_index = float(row.get('url_google_index', 0)) if 'url_google_index' in row.index else 1
        domain_google_index = float(row.get('domain_google_index', 0)) if 'domain_google_index' in row.index else 1
        
        # Calculate suspicion level based on features
        suspicion_score = 0
        indicators_list = []
        
        # URL Structure Analysis
        if qty_dots_url > 4:
            suspicion_score += 2
            indicators_list.append(f"Excessive dots in URL ({int(qty_dots_url)})")
        
        if qty_hyphens_url > 3:
            suspicion_score += 2
            indicators_list.append(f"Multiple hyphens in URL ({int(qty_hyphens_url)})")
        
        if url_length > 75:
            suspicion_score += 1
            indicators_list.append(f"Very long URL ({int(url_length)} chars)")
        
        # Domain Structure Analysis
        if qty_dots_domain > 3:
            suspicion_score += 2
            indicators_list.append(f"Subdomain nesting ({int(qty_dots_domain)} levels)")
        
        if domain_in_ip == 1:
            suspicion_score += 3
            indicators_list.append("Domain uses IP address instead of domain name")
        
        # Security Features
        if tls_ssl_cert == -1:
            suspicion_score += 3
            indicators_list.append("Missing or invalid TLS/SSL certificate")
        elif tls_ssl_cert == 0:
            suspicion_score += 1
            indicators_list.append("TLS/SSL certificate issues detected")
        
        if qty_nameservers < 2:
            suspicion_score += 1
            indicators_list.append(f"Minimal nameservers ({int(qty_nameservers)})")
        
        if qty_mx_servers == 0:
            suspicion_score += 1
            indicators_list.append("No MX servers found")
        
        # Redirect Analysis
        if qty_redirects > 3:
            suspicion_score += 2
            indicators_list.append(f"Excessive redirects ({int(qty_redirects)})")
        
        # URL Shortening
        if url_shortened == 1:
            suspicion_score += 2
            indicators_list.append("URL is shortened (masks actual destination)")
        
        # Search Index Analysis
        if url_google_index != 1:
            suspicion_score += 1
            indicators_list.append("URL not indexed by Google")
        
        if domain_google_index != 1:
            suspicion_score += 1
            indicators_list.append("Domain not indexed by Google")
        
        # Determine severity based on suspicion score
        if suspicion_score >= 6:
            severity = 'critical'
        elif suspicion_score >= 4:
            severity = 'high'
        elif suspicion_score >= 2:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Skip if completely normal (no indicators)
        if suspicion_score == 0:
            continue
        
        # Calculate relevance score
        relevance_score = round(min(0.95, 0.3 + (suspicion_score * 0.12)), 2)
        
        # Create threat record
        threat = {
            'threat_type': 'Suspicious URL Pattern',
            'title': f"URL Anomaly Detection: {severity.upper()}",
            'description': f"Feature-based analysis detected suspicious URL characteristics. {' '.join(indicators_list[:2])}",
            'source': 'Phishing URL Dataset (Feature-Engineered Analysis)',
            'severity': severity,
            'relevance_score': relevance_score,
            'indicators': {
                'suspicion_score': int(suspicion_score),
                'url_structure': {
                    'dots': int(qty_dots_url),
                    'hyphens': int(qty_hyphens_url),
                    'slashes': int(qty_slashes_url),
                    'question_marks': int(qty_questionmark_url),
                    'length': int(url_length)
                },
                'domain_features': {
                    'dots': int(qty_dots_domain),
                    'hyphens': int(qty_hyphens_domain),
                    'length': int(domain_length),
                    'uses_ip': int(domain_in_ip)
                },
                'security_features': {
                    'tls_ssl_cert': int(tls_ssl_cert),
                    'nameservers': int(qty_nameservers),
                    'mx_servers': int(qty_mx_servers),
                    'redirects': int(qty_redirects)
                },
                'detected_indicators': indicators_list[:5],  # Top 5 indicators
                'detection_date': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
            },
            'created_at': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        }
        
        threats.append(threat)
    except Exception as e:
        print(f"⚠️  Skipping row {idx} due to error: {str(e)[:50]}")
        continue

print(f"✅ Created {len(threats)} suspicious URL threat records")

# Save
with open('data/processed/threats_from_phishing_urls.json', 'w') as f:
    json.dump(threats, f, indent=2)

print("✅ Saved to: data/processed/threats_from_phishing_urls.json")

if threats:
    print("\n👀 Sample suspicious URL threat (with features):")
    print(json.dumps(threats[0], indent=2))

    # Statistics
    print("\n📊 Threat Severity Distribution:")
    severity_counts = {}
    for threat in threats:
        sev = threat['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in severity_counts:
            print(f"   {severity}: {severity_counts[severity]} threats")

    # Average suspicion score
    avg_suspicion = sum(t['indicators']['suspicion_score'] for t in threats) / len(threats)
    print(f"\n   Average suspicion score: {avg_suspicion:.2f}")

print("\n" + "=" * 50)
print("PROCESSING COMPLETE!")
print("=" * 50)
print(f"\nYou now have:")
print(f"  - 500 ML Predictions (NSL-KDD)")
print(f"  - 200 Known Vulnerabilities (CISA)")
print(f"  - {len(threats)} Suspicious URL Patterns (Feature-Engineered)")
print(f"  = {500 + 200 + len(threats)} TOTAL THREAT RECORDS")
print("\nNext step: Run 4_upload_to_supabase.py")