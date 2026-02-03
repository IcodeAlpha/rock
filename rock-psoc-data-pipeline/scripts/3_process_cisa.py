"""
Process CISA Known Exploited Vulnerabilities into threat intelligence
"""

import pandas as pd
import json
from datetime import datetime
import random

print("=" * 50)
print("PROCESSING CISA KEV DATASET")
print("=" * 50)

# Read dataset
print("\nReading CISA data...")
df = pd.read_csv('data/raw/cisa_kev.csv')

print(f"✅ Loaded {len(df)} vulnerabilities")

# Create threat intelligence records
threats = []

for idx, row in df.head(200).iterrows():  # Process first 200
    # Calculate relevance score (you'll improve this later with org profiles)
    relevance = 0.6  # Base relevance
    
    # Increase if recently added
    date_added = datetime.strptime(row['dateAdded'], '%Y-%m-%d')
    days_old = (datetime.now() - date_added).days
    
    if days_old < 30:
        relevance += 0.2
    elif days_old < 90:
        relevance += 0.1
    
    # Increase if critical product
    critical_products = ['Windows', 'Apache', 'Cisco', 'Linux', 'Oracle']
    if any(prod in row['product'] for prod in critical_products):
        relevance += 0.15
    
    relevance = min(0.95, relevance)  # Cap at 0.95
    
    threat = {
        'threat_type': 'Known Exploited Vulnerability',
        'title': f"{row['vendorProject']} {row['product']} - {row['vulnerabilityName']}",
        'description': row['shortDescription'],
        'source': 'CISA KEV Catalog',
        'severity': 'high',  # All CISA KEV are high by default
        'relevance_score': round(relevance, 2),
        'indicators': {
            'cve_id': row['cveID'],
            'vendor': row['vendorProject'],
            'product': row['product'],
            'date_added': row['dateAdded'],
            'due_date': row['dueDate'] if 'dueDate' in row else None
        },
        'created_at': row['dateAdded']
    }
    
    threats.append(threat)

print(f"✅ Created {len(threats)} threat intelligence records")

# Save
with open('data/processed/threats_from_cisa.json', 'w') as f:
    json.dump(threats, f, indent=2)

print("✅ Saved to: data/processed/threats_from_cisa.json")

print("\n👀 Sample threat:")
print(json.dumps(threats[0], indent=2))

print("\n" + "=" * 50)
print("PROCESSING COMPLETE!")
print("=" * 50)