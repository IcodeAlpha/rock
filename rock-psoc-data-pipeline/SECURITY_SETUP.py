"""
Security Setup Script
Automated setup for ML model security system
"""

import subprocess
import sys
from pathlib import Path
import shutil

def run_command(command, description):
    """Run a shell command"""
    print(f"\n{'='*70}")
    print(f"🔧 {description}")
    print(f"{'='*70}")
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        print(e.stderr)
        return False


def setup_security():
    """Setup complete security system"""
    
    print("\n" + "="*70)
    print("🔒 ML MODEL SECURITY SYSTEM SETUP")
    print("="*70)
    
    # Step 1: Install dependencies
    print("\n📦 Installing Python dependencies...")
    packages = [
        "cryptography",
        "pydantic",
        "fastapi",
        "uvicorn",
        "python-multipart"
    ]
    
    for package in packages:
        run_command(
            f"pip install {package} --break-system-packages",
            f"Installing {package}"
        )
    
    # Step 2: Create directory structure
    print("\n📁 Creating directory structure...")
    dirs = [
        "config",
        "logs",
        "models/saved_models",
        "models/evaluation",
        "security"
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"   ✅ Created: {dir_path}")
    
    # Step 3: Copy security files
    print("\n📋 Setting up security modules...")
    security_files = [
        "SECURITY_1_api_auth.py",
        "SECURITY_2_model_encryption.py",
        "SECURITY_3_model_integrity.py",
        "SECURITY_4_input_validator.py",
        "SECURITY_5_audit_logger.py",
        "SECURITY_6_secure_ml_api.py"
    ]
    
    for file in security_files:
        if Path(file).exists():
            shutil.copy(file, f"security/{file}")
            print(f"   ✅ Installed: {file}")
    
    # Step 4: Initialize API keys
    print("\n🔑 Initializing API key system...")
    sys.path.insert(0, "security")
    
    try:
        from SECURITY_1_api_auth import APIKeyManager
        
        key_manager = APIKeyManager()
        print("   ✅ API key system initialized")
        print("   📝 Check console output for your admin API key!")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Step 5: Register models
    print("\n📋 Registering models for integrity verification...")
    
    try:
        from SECURITY_3_model_integrity import ModelIntegrityChecker
        
        checker = ModelIntegrityChecker()
        
        # Find all models
        models_dir = Path("models/saved_models")
        if models_dir.exists():
            model_files = list(models_dir.glob("*.pkl"))
            
            if model_files:
                for model_file in model_files:
                    try:
                        checker.register_model(model_file)
                    except Exception as e:
                        print(f"   ⚠️  Could not register {model_file.name}: {e}")
            else:
                print("   ⚠️  No model files found in models/saved_models")
                print("   You'll need to register models manually after training")
        else:
            print("   ⚠️  models/saved_models directory not found")
            print("   Create it and add your models, then register them")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Step 6: Setup file permissions
    print("\n🔒 Setting file permissions...")
    
    try:
        import os
        
        # Restrict key file
        key_file = Path("config/.model_key")
        if key_file.exists():
            os.chmod(key_file, 0o600)
            print("   ✅ Encryption key protected")
        
        # Restrict API keys
        api_keys = Path("config/api_keys.json")
        if api_keys.exists():
            os.chmod(api_keys, 0o600)
            print("   ✅ API keys protected")
    except Exception as e:
        print(f"   ⚠️  Could not set permissions (Windows?): {e}")
        print("   Manually restrict access to config/ directory")
    
    # Step 7: Create startup script
    print("\n📝 Creating startup scripts...")
    
    # Windows batch file
    with open("START_SECURE_API.bat", "w") as f:
        f.write("""@echo off
echo.
echo ============================================================
echo  Starting Secure ML Prediction API
echo ============================================================
echo.

cd /d "%~dp0"

REM Activate virtual environment if it exists
if exist venv\\Scripts\\activate.bat (
    call venv\\Scripts\\activate.bat
)

REM Start the secure API
python security/SECURITY_6_secure_ml_api.py

pause
""")
    print("   ✅ Created: START_SECURE_API.bat (Windows)")
    
    # Unix shell script
    with open("start_secure_api.sh", "w") as f:
        f.write("""#!/bin/bash

echo ""
echo "============================================================"
echo " Starting Secure ML Prediction API"
echo "============================================================"
echo ""

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -f venv/bin/activate ]; then
    source venv/bin/activate
fi

# Start the secure API
python security/SECURITY_6_secure_ml_api.py
""")
    
    try:
        import os
        os.chmod("start_secure_api.sh", 0o755)
    except:
        pass
    
    print("   ✅ Created: start_secure_api.sh (Linux/Mac)")
    
    # Final summary
    print("\n" + "="*70)
    print("✅ SECURITY SETUP COMPLETE!")
    print("="*70)
    print("\n📋 Next Steps:")
    print("   1. Review the admin API key shown above")
    print("   2. Encrypt your models:")
    print("      python security/SECURITY_2_model_encryption.py encrypt-all")
    print("   3. Register models for integrity checking:")
    print("      python security/SECURITY_3_model_integrity.py register-all")
    print("   4. Start the secure API:")
    print("      Windows: START_SECURE_API.bat")
    print("      Linux/Mac: ./start_secure_api.sh")
    print("\n📖 Documentation:")
    print("   API docs: http://localhost:8000/docs")
    print("   Security guide: ML_MODEL_SECURITY_GUIDE.md")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    setup_security()