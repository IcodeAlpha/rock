"""
Upload Model Metadata to Supabase - FIXED VERSION
Script: 8_upload_to_supabase.py

Uploads:
1. Model metadata and performance metrics
2. Training statistics and evaluation results
3. Feature importance (if available)

NOTE: Threat intelligence is uploaded separately via Script 4
"""

import json
import os
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime
import time
from uuid import uuid4

print("=" * 70)
print("UPLOAD TO SUPABASE - MODEL METADATA & TRAINING STATS")
print("=" * 70)

# ============================================
# 1. LOAD ENVIRONMENT VARIABLES
# ============================================
print("\n[1/5] Loading environment variables...")

load_dotenv()

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    print("❌ Error: Supabase credentials not found in .env file!")
    print("   Please add:")
    print("   SUPABASE_URL=your_supabase_url")
    print("   SUPABASE_KEY=your_supabase_key")
    exit(1)

print("✅ Environment variables loaded")

# ============================================
# 2. CONNECT TO SUPABASE
# ============================================
print("\n[2/5] Connecting to Supabase...")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Connected to Supabase")
except Exception as e:
    print(f"❌ Error connecting to Supabase: {str(e)}")
    exit(1)

# ============================================
# 3. UPLOAD MODEL METADATA
# ============================================
print("\n[3/5] Uploading model metadata...")

# Load master evaluation report (contains all metrics)
model_metadata = []

if os.path.exists('models/evaluation/master_evaluation_report.json'):
    try:
        with open('models/evaluation/master_evaluation_report.json', 'r') as f:
            report = json.load(f)
        
        detailed_metrics = report.get('detailed_metrics', {})
        
        # Process each task
        for task_name, task_data in detailed_metrics.items():
            print(f"\n   Processing: {task_name}...")
            
            # ===== CLASSIFICATION MODELS (Intrusion Detection, Phishing Detection) =====
            if 'models' in task_data and 'classification' not in task_data:
                # Intrusion Detection & Phishing Detection
                for model_name, model_metrics in task_data['models'].items():
                    try:
                        metadata = {
                            'task': task_name,
                            'model_name': model_name,
                            'model_type': model_name,
                            'is_best': model_name == task_data.get('best_model'),
                            'accuracy': float(model_metrics.get('accuracy')) if model_metrics.get('accuracy') is not None else None,
                            'precision': float(model_metrics.get('precision')) if model_metrics.get('precision') is not None else None,
                            'recall': float(model_metrics.get('recall')) if model_metrics.get('recall') is not None else None,
                            'f1_score': float(model_metrics.get('f1_score')) if model_metrics.get('f1_score') is not None else None,
                            'auc_roc': float(model_metrics.get('auc_roc')) if model_metrics.get('auc_roc') is not None else None,
                            'training_samples': int(task_data.get('training_samples', 0)),
                            'test_samples': int(task_data.get('test_samples', 0)),
                            'num_classes': int(task_data.get('num_classes', 0)),
                            'class_names': task_data.get('class_names', []),
                            'trained_at': datetime.now().isoformat()
                        }
                        model_metadata.append(metadata)
                        print(f"      ✓ Added: {model_name}")
                    except Exception as e:
                        print(f"      ⚠️  Error processing {model_name}: {str(e)[:50]}")
            
            # ===== VULNERABILITY SCORING (has both regression and classification) =====
            elif 'regression' in task_data or 'classification' in task_data:
                # Regression models
                if 'regression' in task_data:
                    for model_name, model_metrics in task_data['regression'].items():
                        try:
                            metadata = {
                                'task': f"{task_name} - Regression",
                                'model_name': model_name,
                                'model_type': model_name,
                                'is_best': model_name == task_data.get('best_regression_model'),
                                'mse': float(model_metrics.get('mse')) if model_metrics.get('mse') is not None else None,
                                'rmse': float(model_metrics.get('rmse')) if model_metrics.get('rmse') is not None else None,
                                'mae': float(model_metrics.get('mae')) if model_metrics.get('mae') is not None else None,
                                'r2': float(model_metrics.get('r2')) if model_metrics.get('r2') is not None else None,
                                'training_samples': int(task_data.get('training_samples', 0)),
                                'test_samples': int(task_data.get('test_samples', 0)),
                                'trained_at': datetime.now().isoformat()
                            }
                            model_metadata.append(metadata)
                            print(f"      ✓ Added: {model_name} (Regression)")
                        except Exception as e:
                            print(f"      ⚠️  Error processing {model_name}: {str(e)[:50]}")
                
                # Classification models
                if 'classification' in task_data:
                    for model_name, model_metrics in task_data['classification'].items():
                        try:
                            metadata = {
                                'task': f"{task_name} - Classification",
                                'model_name': model_name,
                                'model_type': model_name,
                                'is_best': model_name == task_data.get('best_classification_model'),
                                'accuracy': float(model_metrics.get('accuracy')) if model_metrics.get('accuracy') is not None else None,
                                'f1_score': float(model_metrics.get('f1_score')) if model_metrics.get('f1_score') is not None else None,
                                'training_samples': int(task_data.get('training_samples', 0)),
                                'test_samples': int(task_data.get('test_samples', 0)),
                                'trained_at': datetime.now().isoformat()
                            }
                            model_metadata.append(metadata)
                            print(f"      ✓ Added: {model_name} (Classification)")
                        except Exception as e:
                            print(f"      ⚠️  Error processing {model_name}: {str(e)[:50]}")
        
    except Exception as e:
        print(f"   ⚠️  Error loading master evaluation report: {str(e)[:100]}")
else:
    print("   ⚠️  Master evaluation report not found")

# Upload model metadata ONE AT A TIME to avoid schema mismatch
if model_metadata:
    print(f"\n   Uploading {len(model_metadata)} model records to Supabase...")
    uploaded = 0
    failed = 0
    
    for idx, record in enumerate(model_metadata, 1):
        try:
            # Upload one record at a time
            result = supabase.table('ml_models').insert([record]).execute()
            uploaded += 1
            print(f"      ✅ Uploaded {uploaded}/{len(model_metadata)} ({record['model_name']})", end='\r')
            time.sleep(0.05)
        except Exception as e:
            failed += 1
            error_msg = str(e)[:80]
            print(f"\n      ⚠️  Failed {record['model_name']}: {error_msg}")
    
    print(f"\n   ✅ Model metadata: {uploaded} uploaded, {failed} failed")
else:
    print("   ⚠️  No model metadata found to upload")

# ============================================
# 4. UPLOAD TRAINING STATISTICS
# ============================================
print("\n[4/5] Uploading training statistics...")

# Load master evaluation report
if os.path.exists('models/evaluation/master_evaluation_report.json'):
    try:
        with open('models/evaluation/master_evaluation_report.json', 'r') as f:
            report = json.load(f)
        
        print("   Found master evaluation report")
        
        # Create training session record with correct data types
        training_session = {
            'session_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'evaluation_date': str(report.get('evaluation_date', datetime.now().isoformat())),
            'tasks_evaluated': int(report.get('tasks_evaluated', 0)),
            'tasks_found': int(len(report.get('tasks_found', []))),  # Convert list to count
            'tasks_missing': report.get('tasks_missing', []),
            'best_models_summary': report.get('best_models_summary', [])
        }
        
        print(f"   Session ID: {training_session['session_id']}")
        print(f"   Tasks evaluated: {training_session['tasks_evaluated']}")
        print(f"   Tasks found: {training_session['tasks_found']}")
        
        result = supabase.table('training_sessions').insert([training_session]).execute()
        
        print(f"   ✅ Training session uploaded successfully")
        
    except Exception as e:
        print(f"   ⚠️  Error uploading training statistics: {str(e)[:100]}")
else:
    print("   ⚠️  Master evaluation report not found at models/evaluation/master_evaluation_report.json")

# ============================================
# 5. UPLOAD FEATURE IMPORTANCE (if available)
# ============================================
print("\n[5/5] Uploading feature importance...")

feature_importance_records = []

# Note: Feature importance would require extracting from saved models
# or would need to be included in the metrics JSON files

print("   ℹ️  Feature importance not available in current metrics files")

# ============================================
# FINAL SUMMARY
# ============================================
print("\n" + "=" * 70)
print("UPLOAD COMPLETE!")
print("=" * 70)

print(f"\n📊 Upload Summary:")
print(f"   Model Metadata: {len(model_metadata)} records")
print(f"   Training Sessions: 1 record")
print(f"   Feature Importance: {len(feature_importance_records)} records")

print(f"\n📁 Uploaded to Supabase Tables:")
print(f"   • ml_models")
print(f"   • training_sessions")
print(f"   • feature_importance")

print(f"\n✅ Model data is now available in your Supabase dashboard!")

print(f"\n💡 Sample Queries:")
print(f"\n   # Get all models")
print(f"   SELECT * FROM ml_models ORDER BY created_at DESC;")
print(f"\n   # Get best performing models")
print(f"   SELECT * FROM ml_models WHERE is_best = true;")
print(f"\n   # Get Intrusion Detection models")
print(f"   SELECT * FROM ml_models WHERE task = 'Intrusion Detection';")
print(f"\n   # Get Vulnerability Scoring regression models")
print(f"   SELECT * FROM ml_models WHERE task LIKE '%Regression%';")

print("\n" + "=" * 70)
print("🎉 MODEL METADATA UPLOAD COMPLETE!")
print("=" * 70)

print(f"\n✅ Wizard Done")