"""
Model Encryption System
Encrypt ML models at rest using AES-256
"""

from cryptography.fernet import Fernet
from pathlib import Path
import pickle
import os
import json
from datetime import datetime

class ModelEncryption:
    """Encrypt and decrypt ML models for secure storage"""
    
    def __init__(self, key_file: str = "config/.model_key"):
        self.key_file = Path(key_file)
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)
        self.manifest_file = self.key_file.parent / "encryption_manifest.json"
        self.manifest = self._load_manifest()
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing encryption key or generate new one"""
        if self.key_file.exists():
            print("🔑 Loading existing encryption key...")
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            print("🔑 Generating new encryption key...")
            key = Fernet.generate_key()
            
            # Save with restricted permissions
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            # Set read/write for owner only (Unix)
            try:
                os.chmod(self.key_file, 0o600)
                print(f"✅ Encryption key saved to: {self.key_file}")
                print("   ⚠️  BACKUP THIS KEY SECURELY - Without it, models cannot be decrypted!")
            except:
                print(f"⚠️  Could not set file permissions. Manually restrict access to {self.key_file}")
            
            return key
    
    def _load_manifest(self) -> dict:
        """Load encryption manifest"""
        if self.manifest_file.exists():
            with open(self.manifest_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_manifest(self):
        """Save encryption manifest"""
        with open(self.manifest_file, 'w') as f:
            json.dump(self.manifest, f, indent=2)
    
    def encrypt_model(
        self, 
        model_path: Path, 
        output_path: Path = None,
        delete_original: bool = False
    ) -> Path:
        """
        Encrypt a model file
        
        Args:
            model_path: Path to unencrypted model
            output_path: Where to save encrypted model (default: same name + .encrypted)
            delete_original: Whether to delete original after encryption
            
        Returns:
            Path to encrypted model
        """
        model_path = Path(model_path)
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        if output_path is None:
            output_path = model_path.with_suffix(model_path.suffix + '.encrypted')
        else:
            output_path = Path(output_path)
        
        print(f"🔒 Encrypting: {model_path.name}")
        
        # Load model data
        with open(model_path, 'rb') as f:
            model_data = f.read()
        
        # Encrypt
        encrypted_data = self.cipher.encrypt(model_data)
        
        # Save encrypted
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Set permissions
        try:
            os.chmod(output_path, 0o600)
        except:
            pass
        
        # Update manifest
        self.manifest[str(output_path)] = {
            "original_file": str(model_path),
            "encrypted_at": datetime.now().isoformat(),
            "original_size": len(model_data),
            "encrypted_size": len(encrypted_data)
        }
        self._save_manifest()
        
        print(f"   ✅ Saved to: {output_path}")
        print(f"   Original size: {len(model_data):,} bytes")
        print(f"   Encrypted size: {len(encrypted_data):,} bytes")
        
        # Optionally delete original
        if delete_original:
            model_path.unlink()
            print(f"   🗑️  Deleted original: {model_path}")
        
        return output_path
    
    def decrypt_model(self, encrypted_path: Path):
        """
        Decrypt and return a model object
        
        Args:
            encrypted_path: Path to encrypted model
            
        Returns:
            Decrypted model object
        """
        encrypted_path = Path(encrypted_path)
        
        if not encrypted_path.exists():
            raise FileNotFoundError(f"Encrypted model not found: {encrypted_path}")
        
        # Load encrypted data
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            # Decrypt
            decrypted_data = self.cipher.decrypt(encrypted_data)
            
            # Load model
            model = pickle.loads(decrypted_data)
            
            return model
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt model. Key may be incorrect. Error: {e}")
    
    def decrypt_to_file(self, encrypted_path: Path, output_path: Path):
        """
        Decrypt model and save to file
        
        Args:
            encrypted_path: Path to encrypted model
            output_path: Where to save decrypted model
        """
        encrypted_path = Path(encrypted_path)
        output_path = Path(output_path)
        
        print(f"🔓 Decrypting: {encrypted_path.name}")
        
        # Load encrypted data
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt
        decrypted_data = self.cipher.decrypt(encrypted_data)
        
        # Save decrypted
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"   ✅ Saved to: {output_path}")
    
    def encrypt_all_models(self, models_dir: str = "models/saved_models"):
        """
        Encrypt all .pkl files in a directory
        
        Args:
            models_dir: Directory containing models
        """
        models_dir = Path(models_dir)
        
        if not models_dir.exists():
            print(f"❌ Directory not found: {models_dir}")
            return
        
        # Find all .pkl files
        pkl_files = list(models_dir.glob("*.pkl"))
        
        if not pkl_files:
            print(f"No .pkl files found in {models_dir}")
            return
        
        print(f"\n🔒 Encrypting {len(pkl_files)} models in {models_dir}")
        print("="*70)
        
        for model_file in pkl_files:
            # Skip if already encrypted
            encrypted_path = model_file.with_suffix('.pkl.encrypted')
            if encrypted_path.exists():
                print(f"⏭️  Skipping (already encrypted): {model_file.name}")
                continue
            
            try:
                self.encrypt_model(model_file, delete_original=False)
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        print("="*70)
        print("✅ Encryption complete!\n")
    
    def get_manifest(self) -> dict:
        """Get encryption manifest"""
        return self.manifest


# Secure model loader for production
class SecureModelLoader:
    """Load encrypted models securely"""
    
    def __init__(self):
        self.encryptor = ModelEncryption()
        self.loaded_models = {}
    
    def load_model(self, model_name: str, models_dir: str = "models/saved_models") -> object:
        """
        Load an encrypted model
        
        Args:
            model_name: Name of the model (without extension)
            models_dir: Directory containing models
            
        Returns:
            Loaded model object
        """
        # Check cache
        if model_name in self.loaded_models:
            return self.loaded_models[model_name]
        
        # Try encrypted version first
        encrypted_path = Path(models_dir) / f"{model_name}.encrypted"
        
        if encrypted_path.exists():
            print(f"🔓 Loading encrypted model: {model_name}")
            model = self.encryptor.decrypt_model(encrypted_path)
        else:
            # Fall back to unencrypted (for development)
            unencrypted_path = Path(models_dir) / f"{model_name}.pkl"
            if unencrypted_path.exists():
                print(f"⚠️  Loading UNENCRYPTED model: {model_name}")
                print("   Consider encrypting models in production!")
                with open(unencrypted_path, 'rb') as f:
                    model = pickle.load(f)
            else:
                raise FileNotFoundError(
                    f"Model not found: {model_name}\n"
                    f"Tried: {encrypted_path} and {unencrypted_path}"
                )
        
        # Cache
        self.loaded_models[model_name] = model
        return model


# CLI tool
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Model Encryption Tool")
        print("="*70)
        print("Usage:")
        print("  python model_encryption.py encrypt <model_path>")
        print("  python model_encryption.py decrypt <encrypted_path> <output_path>")
        print("  python model_encryption.py encrypt-all [models_dir]")
        print("  python model_encryption.py manifest")
        print("\nExamples:")
        print("  python model_encryption.py encrypt models/saved_models/intrusion_model.pkl")
        print("  python model_encryption.py encrypt-all models/saved_models")
        print("  python model_encryption.py decrypt intrusion_model.pkl.encrypted intrusion_model.pkl")
        sys.exit(1)
    
    command = sys.argv[1]
    encryptor = ModelEncryption()
    
    if command == "encrypt":
        if len(sys.argv) < 3:
            print("Usage: python model_encryption.py encrypt <model_path>")
            sys.exit(1)
        
        model_path = Path(sys.argv[2])
        encryptor.encrypt_model(model_path)
    
    elif command == "decrypt":
        if len(sys.argv) < 4:
            print("Usage: python model_encryption.py decrypt <encrypted_path> <output_path>")
            sys.exit(1)
        
        encrypted_path = Path(sys.argv[2])
        output_path = Path(sys.argv[3])
        encryptor.decrypt_to_file(encrypted_path, output_path)
    
    elif command == "encrypt-all":
        models_dir = sys.argv[2] if len(sys.argv) > 2 else "models/saved_models"
        encryptor.encrypt_all_models(models_dir)
    
    elif command == "manifest":
        manifest = encryptor.get_manifest()
        print("\n📋 Encryption Manifest:")
        print("="*70)
        for encrypted_file, info in manifest.items():
            print(f"\n📄 {Path(encrypted_file).name}")
            print(f"   Original: {info['original_file']}")
            print(f"   Encrypted: {info['encrypted_at']}")
            print(f"   Size: {info['original_size']:,} → {info['encrypted_size']:,} bytes")
        print("="*70 + "\n")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)