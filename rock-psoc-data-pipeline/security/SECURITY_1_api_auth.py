"""
API Key Authentication System
Secure authentication for ML prediction API
"""

from fastapi import Security, HTTPException, status, Request
from fastapi.security import APIKeyHeader
from typing import Optional, Dict
import hashlib
from datetime import datetime, timedelta
import json
from pathlib import Path

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

class APIKeyManager:
    """Manage API keys with hashing and permissions"""
    
    def __init__(self, keys_file: str = "config/api_keys.json"):
        self.keys_file = Path(keys_file)
        self.keys_file.parent.mkdir(parents=True, exist_ok=True)
        self.api_keys = self._load_keys()
        self.request_log = {}  # In production: Use Redis
        
    def _load_keys(self) -> Dict:
        """Load API keys from file"""
        if self.keys_file.exists():
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        
        # Create default admin key
        default_keys = self._create_default_keys()
        self._save_keys(default_keys)
        return default_keys
    
    def _create_default_keys(self) -> Dict:
        """Create default API keys for initial setup"""
        # Generate secure admin key
        admin_key = "rockpsoc_admin_" + hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
        
        # Hash for storage
        admin_key_hash = self._hash_key(admin_key)
        
        print("\n" + "="*70)
        print("🔑 DEFAULT API KEY GENERATED")
        print("="*70)
        print(f"   Admin API Key: {admin_key}")
        print("   Save this key securely - it won't be shown again!")
        print("="*70 + "\n")
        
        return {
            admin_key_hash: {
                "name": "admin",
                "user_id": "system_admin",
                "permissions": ["predict", "admin", "read", "write"],
                "rate_limit": 1000,  # requests per hour
                "created_at": datetime.now().isoformat(),
                "last_used": None,
                "active": True
            }
        }
    
    def _save_keys(self, keys: Dict):
        """Save API keys to file"""
        with open(self.keys_file, 'w') as f:
            json.dump(keys, f, indent=2)
    
    def _hash_key(self, api_key: str) -> str:
        """Hash an API key using SHA-256"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def create_api_key(
        self, 
        name: str, 
        user_id: str,
        permissions: list = ["predict"],
        rate_limit: int = 100
    ) -> str:
        """
        Create a new API key
        
        Args:
            name: Friendly name for the key
            user_id: User/service identifier
            permissions: List of permissions
            rate_limit: Max requests per hour
            
        Returns:
            The plain-text API key (save it - won't be shown again!)
        """
        # Generate key
        prefix = f"rockpsoc_{name}_"
        random_part = hashlib.sha256(
            f"{name}{user_id}{datetime.now()}".encode()
        ).hexdigest()[:16]
        
        api_key = prefix + random_part
        key_hash = self._hash_key(api_key)
        
        # Store hashed version
        self.api_keys[key_hash] = {
            "name": name,
            "user_id": user_id,
            "permissions": permissions,
            "rate_limit": rate_limit,
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "active": True
        }
        
        self._save_keys(self.api_keys)
        
        return api_key
    
    def verify_key(
        self, 
        api_key: str,
        required_permission: str = "predict"
    ) -> Dict:
        """
        Verify an API key and check permissions
        
        Args:
            api_key: The API key to verify
            required_permission: Permission required for this operation
            
        Returns:
            Key information dict
            
        Raises:
            HTTPException: If key is invalid or lacks permission
        """
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key required. Include X-API-Key header."
            )
        
        # Hash provided key
        key_hash = self._hash_key(api_key)
        
        if key_hash not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid API key"
            )
        
        key_info = self.api_keys[key_hash]
        
        # Check if key is active
        if not key_info.get("active", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key has been deactivated"
            )
        
        # Check permissions
        if required_permission not in key_info["permissions"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks required permission: {required_permission}"
            )
        
        # Update last used
        key_info["last_used"] = datetime.now().isoformat()
        self._save_keys(self.api_keys)
        
        return key_info
    
    def check_rate_limit(self, key_hash: str, limit: int) -> bool:
        """
        Check if key has exceeded rate limit
        
        Args:
            key_hash: Hashed API key
            limit: Max requests per hour
            
        Returns:
            True if rate limit exceeded, False otherwise
        """
        now = datetime.now()
        hour_key = f"{key_hash}:{now.strftime('%Y-%m-%d-%H')}"
        
        if hour_key not in self.request_log:
            self.request_log[hour_key] = 0
        
        self.request_log[hour_key] += 1
        
        # Cleanup old entries
        cutoff = (now - timedelta(hours=2)).strftime('%Y-%m-%d-%H')
        old_keys = [k for k in self.request_log.keys() if k.split(':')[1] < cutoff]
        for old_key in old_keys:
            del self.request_log[old_key]
        
        return self.request_log[hour_key] > limit
    
    def revoke_key(self, api_key: str):
        """Revoke an API key"""
        key_hash = self._hash_key(api_key)
        if key_hash in self.api_keys:
            self.api_keys[key_hash]["active"] = False
            self._save_keys(self.api_keys)
    
    def list_keys(self) -> list:
        """List all API keys (for admin)"""
        return [
            {
                "name": info["name"],
                "user_id": info["user_id"],
                "permissions": info["permissions"],
                "rate_limit": info["rate_limit"],
                "created_at": info["created_at"],
                "last_used": info["last_used"],
                "active": info["active"]
            }
            for info in self.api_keys.values()
        ]


class APIKeyAuth:
    """FastAPI dependency for API key authentication"""
    
    def __init__(self, key_manager: APIKeyManager):
        self.key_manager = key_manager
    
    async def __call__(
        self,
        request: Request,
        api_key: Optional[str] = Security(API_KEY_HEADER),
        required_permission: str = "predict"
    ) -> Dict:
        """
        Verify API key and enforce rate limits
        
        Usage:
            @app.post("/predict")
            async def predict(auth: dict = Depends(api_auth)):
                # auth contains key info
                ...
        """
        # Verify key
        key_info = self.key_manager.verify_key(api_key, required_permission)
        
        # Check rate limit
        key_hash = self.key_manager._hash_key(api_key)
        rate_limit = key_info["rate_limit"]
        
        if self.key_manager.check_rate_limit(key_hash, rate_limit):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {rate_limit} requests per hour."
            )
        
        # Add request info
        key_info["client_ip"] = request.client.host
        key_info["endpoint"] = request.url.path
        
        return key_info


# Initialize global key manager
key_manager = APIKeyManager()
api_auth = APIKeyAuth(key_manager)


# CLI tool for key management
if __name__ == "__main__":
    import sys
    
    manager = APIKeyManager()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python api_auth.py create <name> <user_id> [rate_limit]")
        print("  python api_auth.py list")
        print("  python api_auth.py revoke <api_key>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "create":
        if len(sys.argv) < 4:
            print("Usage: python api_auth.py create <name> <user_id> [rate_limit]")
            sys.exit(1)
        
        name = sys.argv[2]
        user_id = sys.argv[3]
        rate_limit = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        
        key = manager.create_api_key(name, user_id, rate_limit=rate_limit)
        
        print("\n" + "="*70)
        print("✅ API KEY CREATED")
        print("="*70)
        print(f"   Name: {name}")
        print(f"   User ID: {user_id}")
        print(f"   API Key: {key}")
        print(f"   Rate Limit: {rate_limit} req/hour")
        print("   Save this key - it won't be shown again!")
        print("="*70 + "\n")
    
    elif command == "list":
        keys = manager.list_keys()
        print("\n📋 API KEYS:")
        print("="*70)
        for idx, key in enumerate(keys, 1):
            print(f"\n{idx}. {key['name']} ({key['user_id']})")
            print(f"   Permissions: {', '.join(key['permissions'])}")
            print(f"   Rate Limit: {key['rate_limit']} req/hour")
            print(f"   Status: {'✅ Active' if key['active'] else '❌ Revoked'}")
            print(f"   Last Used: {key['last_used'] or 'Never'}")
        print("="*70 + "\n")
    
    elif command == "revoke":
        if len(sys.argv) < 3:
            print("Usage: python api_auth.py revoke <api_key>")
            sys.exit(1)
        
        api_key = sys.argv[2]
        manager.revoke_key(api_key)
        print(f"\n✅ API key revoked: {api_key[:20]}...\n")