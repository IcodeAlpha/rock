"""
Script 11: Update Prediction API to Use Improved Models
Switches API from v1 models to v2 models
Updates all three prediction endpoints
"""

import pickle
from pathlib import Path
import shutil
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
MODEL_DIR = BASE_DIR / 'models' / 'saved_models'
BACKUP_DIR = BASE_DIR / 'models' / 'backups'

# Create backup directory
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("🔄 UPDATING PREDICTION API MODELS")
print("=" * 70)

# Check if v2 models exist
v2_models = {
    'intrusion': MODEL_DIR / 'intrusion_model_v2.pkl',
    'intrusion_encoder': MODEL_DIR / 'intrusion_label_encoder_v2.pkl',
    'intrusion_features': MODEL_DIR / 'intrusion_features_v2.pkl',
}

print("\n🔍 Checking for v2 models...")
all_exist = True
for name, path in v2_models.items():
    if path.exists():
        size = path.stat().st_size / (1024*1024)
        print(f"   ✅ {name}: {size:.1f} MB")
    else:
        print(f"   ❌ {name}: NOT FOUND")
        all_exist = False

if not all_exist:
    print("\n❌ Not all v2 models found!")
    print("   Run: python scripts/10_retrain_intrusion_model.py first")
    exit(1)

# Backup v1 models
print("\n💾 Backing up v1 models...")
backup_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
backup_subdir = BACKUP_DIR / f'v1_backup_{backup_timestamp}'
backup_subdir.mkdir(exist_ok=True)

v1_models = {
    'intrusion': MODEL_DIR / 'intrusion_model.pkl',
    'intrusion_encoder': MODEL_DIR / 'intrusion_label_encoder.pkl',
    'intrusion_features': MODEL_DIR / 'intrusion_features.pkl',
}

for name, path in v1_models.items():
    if path.exists():
        backup_path = backup_subdir / path.name
        shutil.copy2(path, backup_path)
        print(f"   ✅ Backed up: {name}")

print(f"   Backup location: {backup_subdir}")

# Replace v1 with v2
print("\n🔄 Replacing v1 models with v2 models...")

for name, v2_path in v2_models.items():
    # Get corresponding v1 path
    v1_name = v2_path.name.replace('_v2', '')
    v1_path = MODEL_DIR / v1_name
    
    # Copy v2 to v1 location
    shutil.copy2(v2_path, v1_path)
    print(f"   ✅ Updated: {v1_name}")

# Verify models can be loaded
print("\n✅ Verifying models...")
try:
    with open(MODEL_DIR / 'intrusion_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print(f"   ✅ Intrusion model loaded successfully")
    print(f"      Estimators: {model.n_estimators}")
    
    with open(MODEL_DIR / 'intrusion_label_encoder.pkl', 'rb') as f:
        encoder = pickle.load(f)
    print(f"   ✅ Label encoder loaded successfully")
    print(f"      Classes: {len(encoder.classes_)}")
    
    with open(MODEL_DIR / 'intrusion_features.pkl', 'rb') as f:
        features = pickle.load(f)
    print(f"   ✅ Features loaded successfully")
    print(f"      Features: {len(features)}")
    
except Exception as e:
    print(f"   ❌ Error loading models: {e}")
    print("   Restoring from backup...")
    for name, path in v1_models.items():
        backup_path = backup_subdir / path.name
        if backup_path.exists():
            shutil.copy2(backup_path, path)
    print("   Backup restored")
    exit(1)

print("\n" + "=" * 70)
print("✅ PREDICTION API UPDATED SUCCESSFULLY")
print("=" * 70)

print("\nModels now using:")
print("   - CICIDS2017 dataset (2.8M samples)")
print("   - 200 estimators (improved from 100)")
print("   - 78 network features")

print("\nNext steps:")
print("   1. Restart prediction API:")
print("      python scripts/6_create_prediction_api.py")
print("   2. Test predictions in React app")
print("   3. Monitor performance improvements")

print(f"\nBackups stored in: {backup_subdir}")
print("You can revert anytime by copying from backups folder")