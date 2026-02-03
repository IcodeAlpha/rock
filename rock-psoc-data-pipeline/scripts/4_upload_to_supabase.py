"""
Upload processed data to Supabase database
Maps data to actual table schemas
Updated to include phishing threats
Script: 4_upload_to_supabase_UPDATED.py
"""

import json
from datetime import datetime, timezone
from uuid import uuid4
from config import supabase

print("=" * 60)
print("UPLOADING TO SUPABASE (UPDATED)")
print("=" * 60)

org_id = "d74d1969-8f4c-48f7-843a-3910db7e2960"

# Helper function to convert severity to standard levels
def normalize_severity(severity):
    """Normalize severity to standard levels"""
    severity = str(severity).lower().strip()
    if severity in ['critical', 'high']:
        return 'high'
    elif severity in ['medium', 'moderate']:
        return 'medium'
    elif severity in ['low']:
        return 'low'
    else:
        return 'medium'

batch_size = 100

# ============================================================
# UPLOAD PREDICTIONS (NSL-KDD)
# ============================================================
print("\n1. Loading predictions (NSL-KDD)...")
with open('data/processed/predictions_from_nsl_kdd.json', 'r') as f:
    predictions = json.load(f)

print(f"📊 Loaded {len(predictions)} predictions")

# Map predictions to the predictions table schema
print("\n   Mapping prediction data to table schema...")
mapped_predictions = []

for pred in predictions:
    try:
        # Extract indicators (which is already a dict)
        indicators = pred.get('indicators', {})
        
        mapped_pred = {
            'id': str(uuid4()),
            'organization_id': org_id,
            'title': pred.get('threat_type', 'Unknown Threat'),
            'description': pred.get('description', ''),
            'severity': normalize_severity(pred.get('severity', 'medium')),
            'probability': float(pred.get('probability', 0.5)),
            'confidence': float(pred.get('confidence_score', 0.5)),
            'impact': f"Attack Type: {pred.get('threat_type', 'Unknown')}",
            'timeframe': pred.get('predicted_timeframe', 'Unknown'),
            'affected_systems': [indicators.get('service', 'unknown')] if indicators else ['unknown'],
            'status': 'detected',
            'source': pred.get('source', 'NSL-KDD'),
            'created_at': pred.get('created_at', datetime.now(timezone.utc).isoformat()),
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'confidence_score': float(pred.get('confidence_score', 0.5)),
            'indicators': indicators,  # Already a dict, will be stored as JSONB
            'predicted_timeframe': pred.get('predicted_timeframe', '')
        }
        mapped_predictions.append(mapped_pred)
    except Exception as e:
        print(f"   ⚠️  Skipping prediction due to error: {e}")
        continue

print(f"   ✅ Mapped {len(mapped_predictions)} predictions")

# Upload predictions in batches
print("\n2. Uploading predictions...")

for i in range(0, len(mapped_predictions), batch_size):
    batch = mapped_predictions[i:i+batch_size]
    batch_num = i // batch_size + 1
    total_batches = (len(mapped_predictions) + batch_size - 1) // batch_size
    
    try:
        result = supabase.table('predictions').insert(batch).execute()
        print(f"   ✅ Uploaded batch {batch_num}/{total_batches} ({len(batch)} predictions)")
    except Exception as e:
        print(f"   ❌ Error uploading batch {batch_num}: {str(e)}")

# ============================================================
# UPLOAD THREATS (CISA)
# ============================================================
print("\n3. Loading threat intelligence (CISA)...")
with open('data/processed/threats_from_cisa.json', 'r') as f:
    cisa_threats = json.load(f)

print(f"📊 Loaded {len(cisa_threats)} CISA threats")

# Map threats to the predictions table schema
print("\n   Mapping CISA threat data to table schema...")
mapped_cisa_threats = []

for threat in cisa_threats:
    try:
        # Extract indicators (which is already a dict)
        indicators = threat.get('indicators', {})
        
        mapped_threat = {
            'id': str(uuid4()),
            'organization_id': org_id,
            'title': threat.get('title', 'Unknown Threat'),
            'description': threat.get('description', ''),
            'severity': normalize_severity(threat.get('severity', 'medium')),
            'probability': float(threat.get('relevance_score', 0.5)),
            'confidence': float(threat.get('relevance_score', 0.5)),
            'impact': f"Threat Type: {threat.get('threat_type', 'Unknown')}",
            'timeframe': threat.get('due_date', 'Unknown') if threat.get('indicators', {}).get('due_date') else 'Unknown',
            'affected_systems': [threat.get('indicators', {}).get('product', 'unknown')] if threat.get('indicators') else ['unknown'],
            'status': 'active',
            'source': threat.get('source', 'CISA'),
            'created_at': threat.get('created_at', datetime.now(timezone.utc).isoformat()),
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'confidence_score': float(threat.get('relevance_score', 0.5)),
            'indicators': indicators,  # Already a dict, will be stored as JSONB
            'predicted_timeframe': threat.get('indicators', {}).get('due_date', '')
        }
        mapped_cisa_threats.append(mapped_threat)
    except Exception as e:
        print(f"   ⚠️  Skipping CISA threat due to error: {e}")
        continue

print(f"   ✅ Mapped {len(mapped_cisa_threats)} CISA threats")

# Upload CISA threats in batches
print("\n4. Uploading CISA threats...")

for i in range(0, len(mapped_cisa_threats), batch_size):
    batch = mapped_cisa_threats[i:i+batch_size]
    batch_num = i // batch_size + 1
    total_batches = (len(mapped_cisa_threats) + batch_size - 1) // batch_size
    
    try:
        result = supabase.table('predictions').insert(batch).execute()
        print(f"   ✅ Uploaded batch {batch_num}/{total_batches} ({len(batch)} CISA threats)")
    except Exception as e:
        print(f"   ❌ Error uploading batch {batch_num}: {str(e)}")

# ============================================================
# UPLOAD THREATS (PHISHING)
# ============================================================
print("\n5. Loading phishing detections...")
try:
    with open('data/processed/threats_from_phishing_urls.json', 'r') as f:
        phishing_threats = json.load(f)
    print(f"📊 Loaded {len(phishing_threats)} phishing detections")
except FileNotFoundError:
    print("⚠️  Phishing threats file not found. Skipping phishing upload.")
    phishing_threats = []

if phishing_threats:
    # Map threats to the predictions table schema
    print("\n   Mapping phishing threat data to table schema...")
    mapped_phishing_threats = []

    for threat in phishing_threats:
        try:
            # Extract indicators (which is already a dict)
            indicators = threat.get('indicators', {})
            
            mapped_threat = {
                'id': str(uuid4()),
                'organization_id': org_id,
                'title': threat.get('title', 'Unknown Phishing'),
                'description': threat.get('description', ''),
                'severity': normalize_severity(threat.get('severity', 'high')),
                'probability': threat.get('relevance_score', 0.7),
                'confidence': threat.get('relevance_score', 0.7),
                'impact': threat.get('threat_type', 'Phishing Attack'),
                'timeframe': 'Immediate',
                'affected_systems': ['Users', 'Email'],
                'status': 'detected',
                'source': threat.get('source', 'Phishing Dataset'),
                'created_at': threat.get('created_at', datetime.now(timezone.utc).isoformat()),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'confidence_score': threat.get('relevance_score', 0.7),
                'indicators': indicators,  # Already a dict, will be stored as JSONB
                'predicted_timeframe': 'Immediate'
            }
            mapped_phishing_threats.append(mapped_threat)
        except Exception as e:
            print(f"   ⚠️  Skipping phishing threat due to error: {e}")
            continue

    print(f"   ✅ Mapped {len(mapped_phishing_threats)} phishing threats")

    # Upload phishing threats in batches
    print("\n6. Uploading phishing detections...")

    for i in range(0, len(mapped_phishing_threats), batch_size):
        batch = mapped_phishing_threats[i:i+batch_size]
        batch_num = i // batch_size + 1
        total_batches = (len(mapped_phishing_threats) + batch_size - 1) // batch_size
        
        try:
            result = supabase.table('predictions').insert(batch).execute()
            print(f"   ✅ Uploaded batch {batch_num}/{total_batches} ({len(batch)} phishing threats)")
        except Exception as e:
            print(f"   ❌ Error uploading batch {batch_num}: {str(e)}")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 60)
print("UPLOAD COMPLETE!")
print("=" * 60)

total_records = len(mapped_predictions) + len(mapped_cisa_threats) + len(mapped_phishing_threats)

print(f"\n✅ Upload Summary:")
print(f"   NSL-KDD Predictions: {len(mapped_predictions)}")
print(f"   CISA Threats: {len(mapped_cisa_threats)}")
print(f"   Phishing Detections: {len(mapped_phishing_threats)}")
print(f"   ─────────────────────────")
print(f"   Total Records: {total_records}")

print(f"\n🌐 Check your React app - you should see all threat data!")
print(f"✅ Database is now fully populated with threat intelligence!")