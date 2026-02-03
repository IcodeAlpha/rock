"""
This script reads the NSL-KDD dataset and converts attack records
into "predictions" that will appear in your dashboard.

Think of it like: "If we saw this attack before, we can predict similar ones"
"""

import pandas as pd
from datetime import datetime, timedelta
import random

print("=" * 50)
print("PROCESSING NSL-KDD DATASET")
print("=" * 50)

# Step 1: Read the CSV file
print("\nStep 1: Reading dataset...")
df = pd.read_csv('data/raw/nsl_kdd_train.csv', header=None)

# Add column names (the dataset doesn't have headers)
column_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'attack_type', 'difficulty'
]

df.columns = column_names

print(f"✅ Loaded {len(df)} records")
print(f"📊 Attack distribution:")
print(df['attack_type'].value_counts().head(10))

# Step 2: Map attack types to threat categories
print("\nStep 2: Categorizing attacks...")

attack_to_threat = {
    'neptune': 'DDoS Attack',
    'smurf': 'DDoS Attack',
    'pod': 'DDoS Attack',
    'teardrop': 'DDoS Attack',
    'back': 'DDoS Attack',
    'land': 'DDoS Attack',
    
    'satan': 'Port Scan',
    'ipsweep': 'Port Scan',
    'nmap': 'Port Scan',
    'portsweep': 'Port Scan',
    
    'warezclient': 'Unauthorized Access',
    'warezmaster': 'Unauthorized Access',
    'ftp_write': 'Unauthorized Access',
    'imap': 'Unauthorized Access',
    'multihop': 'Unauthorized Access',
    'phf': 'Unauthorized Access',
    'spy': 'Unauthorized Access',
    
    'guess_passwd': 'Brute Force Attack',
    
    'buffer_overflow': 'Buffer Overflow Exploit',
    'loadmodule': 'Privilege Escalation',
    'perl': 'Script Exploit',
    'rootkit': 'Rootkit Installation',
    
    'normal': None  # Skip normal traffic
}

# Step 3: Convert to predictions
print("\nStep 3: Creating predictions...")

predictions = []
sample_size = 500  # We'll create 500 predictions

# Filter to only attacks (not normal traffic)
attacks_df = df[df['attack_type'] != 'normal']

# Take random sample
sample = attacks_df.sample(n=min(sample_size, len(attacks_df)))

for idx, row in sample.iterrows():
    attack_type = row['attack_type']
    threat_type = attack_to_threat.get(attack_type, 'Unknown Threat')
    
    if threat_type is None:
        continue
    
    # Calculate severity based on attack characteristics
    severity = 'medium'
    
    if row['dst_bytes'] > 10000 or row['wrong_fragment'] > 0:
        severity = 'high'
    
    if row['num_failed_logins'] > 3 or row['root_shell'] > 0:
        severity = 'critical'
    
    if row['dst_bytes'] < 1000 and row['src_bytes'] < 1000:
        severity = 'low'
    
    # Calculate probability (higher for more severe attacks)
    base_probability = 0.65
    if severity == 'critical':
        base_probability = 0.85
    elif severity == 'high':
        base_probability = 0.75
    elif severity == 'low':
        base_probability = 0.55
    
    # Add some randomness
    probability = round(base_probability + random.uniform(-0.1, 0.1), 2)
    probability = max(0.5, min(0.99, probability))  # Keep between 0.5 and 0.99
    
    # Create prediction object
    prediction = {
        'threat_type': threat_type,
        'severity': severity,
        'probability': probability,
        'confidence_score': 0.82,  # Fixed confidence for historical data
        'predicted_timeframe': random.choice(['1-2 days', '3-5 days', '5-7 days', '1-2 weeks']),
        'description': f'Historical pattern analysis detected {threat_type.lower()} signature similar to {attack_type} attack. Network traffic patterns match known attack vectors.',
        'indicators': {
            'protocol': row['protocol_type'],
            'service': row['service'],
            'src_bytes': int(row['src_bytes']),
            'dst_bytes': int(row['dst_bytes']),
            'failed_logins': int(row['num_failed_logins']) if row['num_failed_logins'] > 0 else None,
            'attack_signature': attack_type
        },
        'source': 'NSL-KDD Historical Dataset',
        # Spread created_at over last 30 days
        'created_at': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
    }
    
    predictions.append(prediction)

print(f"✅ Created {len(predictions)} predictions")

# Step 4: Save to processed folder
print("\nStep 4: Saving processed data...")

import json

with open('data/processed/predictions_from_nsl_kdd.json', 'w') as f:
    json.dump(predictions, f, indent=2)

print("✅ Saved to: data/processed/predictions_from_nsl_kdd.json")

# Show preview
print("\n👀 Sample prediction:")
print(json.dumps(predictions[0], indent=2))

print("\n" + "=" * 50)
print("PROCESSING COMPLETE!")
print("=" * 50)
print("\nNext step: Run 4_upload_to_supabase.py to put this in your database")