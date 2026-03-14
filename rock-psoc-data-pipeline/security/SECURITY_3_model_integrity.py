"""
Model Integrity Verification System
Detect tampering with ML models using cryptographic hashes
"""

import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class ModelIntegrityChecker:
    """Verify model files haven't been tampered with"""
    
    def __init__(self, manifest_file: str = "config/model_manifest.json"):
        self.manifest_file = Path(manifest_file)
        self.manifest_file.parent.mkdir(parents=True, exist_ok=True)
        self.manifest = self._load_manifest()
    
    def _load_manifest(self) -> Dict:
        """Load integrity manifest"""
        if self.manifest_file.exists():
            with open(self.manifest_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_manifest(self):
        """Save integrity manifest"""
        with open(self.manifest_file, 'w') as f:
            json.dump(self.manifest, f, indent=2)
    
    def calculate_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA-256 hash as hex string
        """
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def register_model(
        self, 
        model_path: Path,
        model_name: str = None,
        model_version: str = "1.0"
    ) -> str:
        """
        Register a model in the integrity manifest
        
        Args:
            model_path: Path to model file
            model_name: Friendly name (default: filename)
            model_version: Version string
            
        Returns:
            SHA-256 hash of the model
        """
        model_path = Path(model_path)
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        print(f"📋 Registering model: {model_path.name}")
        
        # Calculate hash
        file_hash = self.calculate_hash(model_path)
        
        # Get file info
        stat = model_path.stat()
        
        # Store in manifest
        path_str = str(model_path)
        self.manifest[path_str] = {
            "name": model_name or model_path.stem,
            "version": model_version,
            "hash": file_hash,
            "size": stat.st_size,
            "registered_at": datetime.now().isoformat(),
            "last_verified": datetime.now().isoformat(),
            "verification_count": 0,
            "integrity_status": "verified"
        }
        
        self._save_manifest()
        
        print(f"   ✅ Hash: {file_hash[:16]}...{file_hash[-16:]}")
        print(f"   Size: {stat.st_size:,} bytes")
        
        return file_hash
    
    def verify_model(self, model_path: Path, raise_on_failure: bool = True) -> bool:
        """
        Verify a model hasn't been tampered with
        
        Args:
            model_path: Path to model file
            raise_on_failure: Whether to raise exception on verification failure
            
        Returns:
            True if verification passed, False otherwise
            
        Raises:
            ModelIntegrityError: If verification fails and raise_on_failure=True
        """
        model_path = Path(model_path)
        path_str = str(model_path)
        
        if path_str not in self.manifest:
            error_msg = f"Model not registered: {model_path}\nRegister it first with register_model()"
            if raise_on_failure:
                raise ModelNotRegisteredError(error_msg)
            else:
                print(f"⚠️  {error_msg}")
                return False
        
        # Get expected hash
        expected_hash = self.manifest[path_str]["hash"]
        expected_size = self.manifest[path_str]["size"]
        
        # Calculate current hash
        try:
            current_hash = self.calculate_hash(model_path)
            current_size = model_path.stat().st_size
        except FileNotFoundError:
            error_msg = f"Model file missing: {model_path}"
            if raise_on_failure:
                raise ModelIntegrityError(error_msg)
            else:
                print(f"❌ {error_msg}")
                return False
        
        # Update verification metadata
        self.manifest[path_str]["last_verified"] = datetime.now().isoformat()
        self.manifest[path_str]["verification_count"] += 1
        
        # Check hash
        if current_hash != expected_hash:
            # INTEGRITY FAILURE!
            self.manifest[path_str]["integrity_status"] = "COMPROMISED"
            self.manifest[path_str]["tamper_detected_at"] = datetime.now().isoformat()
            self._save_manifest()
            
            error_msg = (
                f"🚨 MODEL INTEGRITY FAILURE! 🚨\n"
                f"Model: {model_path}\n"
                f"Expected hash: {expected_hash}\n"
                f"Current hash:  {current_hash}\n"
                f"The model file has been modified!\n"
                f"This could indicate:\n"
                f"  - Unauthorized modification\n"
                f"  - File corruption\n"
                f"  - Malicious tampering\n"
                f"DO NOT USE THIS MODEL!"
            )
            
            if raise_on_failure:
                raise ModelIntegrityError(error_msg)
            else:
                print(f"❌ {error_msg}")
                return False
        
        # Check size (quick sanity check)
        if current_size != expected_size:
            warning_msg = (
                f"⚠️  Size mismatch for {model_path}\n"
                f"Expected: {expected_size:,} bytes\n"
                f"Current: {current_size:,} bytes"
            )
            print(warning_msg)
        
        # Success!
        self.manifest[path_str]["integrity_status"] = "verified"
        self._save_manifest()
        
        return True
    
    def verify_all(self, raise_on_failure: bool = False) -> Dict[str, bool]:
        """
        Verify all registered models
        
        Args:
            raise_on_failure: Whether to stop on first failure
            
        Returns:
            Dict mapping model paths to verification results
        """
        results = {}
        
        print("\n🔍 Verifying all registered models...")
        print("="*70)
        
        for model_path in self.manifest.keys():
            try:
                verified = self.verify_model(Path(model_path), raise_on_failure=False)
                results[model_path] = verified
                
                if verified:
                    print(f"✅ {Path(model_path).name}")
                else:
                    print(f"❌ {Path(model_path).name}")
                    if raise_on_failure:
                        raise ModelIntegrityError(f"Verification failed for {model_path}")
                        
            except Exception as e:
                print(f"❌ {Path(model_path).name}: {e}")
                results[model_path] = False
                if raise_on_failure:
                    raise
        
        print("="*70)
        
        # Summary
        passed = sum(results.values())
        total = len(results)
        print(f"\n📊 Results: {passed}/{total} models verified")
        
        if passed < total:
            print("⚠️  SOME MODELS FAILED VERIFICATION!")
            print("   Review the errors above and investigate immediately.")
        
        return results
    
    def get_status(self) -> List[Dict]:
        """Get status of all registered models"""
        status = []
        
        for path, info in self.manifest.items():
            status.append({
                "path": path,
                "name": info["name"],
                "version": info["version"],
                "size": info["size"],
                "registered": info["registered_at"],
                "last_verified": info["last_verified"],
                "verification_count": info["verification_count"],
                "status": info["integrity_status"]
            })
        
        return status
    
    def register_all_models(self, models_dir: str = "models/saved_models"):
        """
        Register all models in a directory
        
        Args:
            models_dir: Directory containing model files
        """
        models_dir = Path(models_dir)
        
        if not models_dir.exists():
            print(f"❌ Directory not found: {models_dir}")
            return
        
        # Find all model files (.pkl and .encrypted)
        model_files = list(models_dir.glob("*.pkl")) + list(models_dir.glob("*.encrypted"))
        
        if not model_files:
            print(f"No model files found in {models_dir}")
            return
        
        print(f"\n📋 Registering {len(model_files)} models from {models_dir}")
        print("="*70)
        
        for model_file in model_files:
            try:
                self.register_model(model_file)
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        print("="*70)
        print("✅ Registration complete!\n")


class ModelIntegrityError(Exception):
    """Raised when model integrity check fails"""
    pass


class ModelNotRegisteredError(Exception):
    """Raised when trying to verify unregistered model"""
    pass


# CLI tool
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Model Integrity Verification Tool")
        print("="*70)
        print("Usage:")
        print("  python model_integrity.py register <model_path> [name] [version]")
        print("  python model_integrity.py verify <model_path>")
        print("  python model_integrity.py verify-all")
        print("  python model_integrity.py register-all [models_dir]")
        print("  python model_integrity.py status")
        print("\nExamples:")
        print("  python model_integrity.py register models/saved_models/intrusion_model.pkl")
        print("  python model_integrity.py verify models/saved_models/intrusion_model.pkl")
        print("  python model_integrity.py register-all models/saved_models")
        print("  python model_integrity.py verify-all")
        sys.exit(1)
    
    command = sys.argv[1]
    checker = ModelIntegrityChecker()
    
    if command == "register":
        if len(sys.argv) < 3:
            print("Usage: python model_integrity.py register <model_path> [name] [version]")
            sys.exit(1)
        
        model_path = Path(sys.argv[2])
        model_name = sys.argv[3] if len(sys.argv) > 3 else None
        model_version = sys.argv[4] if len(sys.argv) > 4 else "1.0"
        
        checker.register_model(model_path, model_name, model_version)
    
    elif command == "verify":
        if len(sys.argv) < 3:
            print("Usage: python model_integrity.py verify <model_path>")
            sys.exit(1)
        
        model_path = Path(sys.argv[2])
        
        try:
            if checker.verify_model(model_path):
                print(f"\n✅ Model verified: {model_path}\n")
            else:
                print(f"\n❌ Verification failed: {model_path}\n")
                sys.exit(1)
        except ModelIntegrityError as e:
            print(f"\n{e}\n")
            sys.exit(1)
    
    elif command == "verify-all":
        results = checker.verify_all(raise_on_failure=False)
        
        if not all(results.values()):
            sys.exit(1)
    
    elif command == "register-all":
        models_dir = sys.argv[2] if len(sys.argv) > 2 else "models/saved_models"
        checker.register_all_models(models_dir)
    
    elif command == "status":
        status = checker.get_status()
        
        print("\n📊 Model Integrity Status:")
        print("="*70)
        
        for model in status:
            print(f"\n📄 {model['name']} (v{model['version']})")
            print(f"   Path: {model['path']}")
            print(f"   Size: {model['size']:,} bytes")
            print(f"   Registered: {model['registered']}")
            print(f"   Last Verified: {model['last_verified']}")
            print(f"   Verification Count: {model['verification_count']}")
            
            if model['status'] == 'verified':
                print(f"   Status: ✅ {model['status'].upper()}")
            else:
                print(f"   Status: ❌ {model['status'].upper()}")
        
        print("="*70 + "\n")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)