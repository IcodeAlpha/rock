"""
Input Validation & Adversarial Detection
Protect ML models from malicious inputs and adversarial attacks
"""

from pydantic import BaseModel, validator, Field
from typing import Dict, List, Optional
import numpy as np
from datetime import datetime
import json
from pathlib import Path

class InputValidator:
    """Validate and sanitize ML model inputs"""
    
    def __init__(self, config_file: str = "config/input_validation_rules.json"):
        self.config_file = Path(config_file)
        self.rules = self._load_rules()
        self.attack_log = []
    
    def _load_rules(self) -> Dict:
        """Load validation rules"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        
        # Default rules for UNSW-NB15 intrusion detection
        default_rules = {
            "intrusion_detection": {
                "required_features": [
                    "dur", "spkts", "dpkts", "sbytes", "dbytes",
                    "rate", "sttl", "dttl", "sload", "dload",
                    "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit"
                ],
                "feature_ranges": {
                    "dur": {"min": 0, "max": 1e10},
                    "spkts": {"min": 0, "max": 1e8},
                    "dpkts": {"min": 0, "max": 1e8},
                    "sbytes": {"min": 0, "max": 1e12},
                    "dbytes": {"min": 0, "max": 1e12},
                    "rate": {"min": 0, "max": 1e10},
                    "sttl": {"min": 0, "max": 255},
                    "dttl": {"min": 0, "max": 255}
                },
                "allow_negative": ["synack", "ackdat"],
                "max_abs_value": 1e15
            },
            "phishing_detection": {
                "required_features": ["url_length", "num_digits", "num_special_chars"],
                "feature_ranges": {
                    "url_length": {"min": 0, "max": 5000},
                    "num_digits": {"min": 0, "max": 1000},
                    "num_special_chars": {"min": 0, "max": 1000}
                }
            }
        }
        
        # Save default rules
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(default_rules, f, indent=2)
        
        return default_rules
    
    def validate_features(
        self, 
        features: Dict[str, float],
        model_type: str = "intrusion_detection"
    ) -> Dict:
        """
        Validate input features for a model
        
        Args:
            features: Dictionary of feature values
            model_type: Type of model (intrusion_detection, phishing_detection, etc.)
            
        Returns:
            Validated features dict
            
        Raises:
            ValueError: If validation fails
        """
        if model_type not in self.rules:
            raise ValueError(f"Unknown model type: {model_type}")
        
        rules = self.rules[model_type]
        
        # Check required features
        required = rules.get("required_features", [])
        missing = [f for f in required if f not in features]
        if missing:
            raise ValueError(f"Missing required features: {missing}")
        
        # Validate each feature
        allow_negative = rules.get("allow_negative", [])
        max_abs = rules.get("max_abs_value", 1e15)
        ranges = rules.get("feature_ranges", {})
        
        for key, value in features.items():
            # Check for NaN, Inf
            if not np.isfinite(value):
                raise ValueError(f"Invalid value for '{key}': {value} (must be finite)")
            
            # Check sign
            if value < 0 and key not in allow_negative:
                raise ValueError(f"Negative value not allowed for '{key}': {value}")
            
            # Check absolute value
            if abs(value) > max_abs:
                raise ValueError(f"Value too large for '{key}': {value} (max: {max_abs})")
            
            # Check range
            if key in ranges:
                min_val = ranges[key].get("min", -np.inf)
                max_val = ranges[key].get("max", np.inf)
                
                if value < min_val or value > max_val:
                    raise ValueError(
                        f"Value out of range for '{key}': {value} "
                        f"(expected: {min_val} to {max_val})"
                    )
        
        return features
    
    def detect_adversarial_patterns(
        self,
        features: Dict[str, float],
        client_id: str = "unknown"
    ) -> Optional[str]:
        """
        Detect common adversarial attack patterns
        
        Args:
            features: Feature dictionary
            client_id: Client identifier
            
        Returns:
            Attack type if detected, None otherwise
        """
        values = list(features.values())
        
        # Pattern 1: All zeros (common in fuzzing attacks)
        if all(v == 0 for v in values):
            self._log_attack(client_id, "all_zeros", features)
            return "all_zeros"
        
        # Pattern 2: All identical values
        if len(set(values)) == 1:
            self._log_attack(client_id, "uniform_values", features)
            return "uniform_values"
        
        # Pattern 3: Suspiciously small variations (gradient-based attacks)
        if len(values) > 5:
            value_changes = np.diff(sorted(values))
            if len(value_changes) > 0 and np.std(value_changes) < 1e-10:
                self._log_attack(client_id, "micro_perturbations", features)
                return "micro_perturbations"
        
        # Pattern 4: Extreme outliers (attempting to find decision boundaries)
        mean_val = np.mean(np.abs(values))
        for key, val in features.items():
            if mean_val > 0 and abs(val) > mean_val * 1000:
                self._log_attack(client_id, "extreme_outlier", features)
                return "extreme_outlier"
        
        # Pattern 5: Unusual feature combinations
        # (This would be model-specific, e.g., high packet count but zero bytes)
        if "spkts" in features and "sbytes" in features:
            if features["spkts"] > 1000 and features["sbytes"] == 0:
                self._log_attack(client_id, "impossible_combination", features)
                return "impossible_combination"
        
        return None
    
    def _log_attack(self, client_id: str, attack_type: str, features: Dict):
        """Log detected attack"""
        self.attack_log.append({
            "timestamp": datetime.now().isoformat(),
            "client_id": client_id,
            "attack_type": attack_type,
            "feature_count": len(features),
            "feature_sample": {k: features[k] for k in list(features.keys())[:5]}
        })
        
        # Keep only recent attacks
        if len(self.attack_log) > 1000:
            self.attack_log = self.attack_log[-1000:]
    
    def get_attack_stats(self) -> Dict:
        """Get statistics on detected attacks"""
        if not self.attack_log:
            return {"total_attacks": 0}
        
        attack_types = {}
        clients = set()
        
        for attack in self.attack_log:
            attack_type = attack["attack_type"]
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            clients.add(attack["client_id"])
        
        return {
            "total_attacks": len(self.attack_log),
            "attack_types": attack_types,
            "unique_clients": len(clients),
            "recent_attacks": self.attack_log[-10:]
        }


# Pydantic models for API validation
class SecureIntrusionRequest(BaseModel):
    """Secure request model for intrusion detection"""
    
    features: Dict[str, float] = Field(..., description="Network traffic features")
    
    @validator('features')
    def validate_features(cls, features):
        validator = InputValidator()
        
        # Validate features
        try:
            validated = validator.validate_features(features, "intrusion_detection")
        except ValueError as e:
            raise ValueError(f"Feature validation failed: {e}")
        
        # Check for adversarial patterns
        attack_type = validator.detect_adversarial_patterns(features)
        if attack_type:
            raise ValueError(
                f"Adversarial attack pattern detected: {attack_type}. "
                f"This input appears to be crafted to attack the model."
            )
        
        return validated


class SecurePhishingRequest(BaseModel):
    """Secure request model for phishing detection"""
    
    url: str = Field(..., max_length=5000, description="URL to check")
    features: Optional[Dict[str, float]] = Field(None, description="Pre-extracted features")
    
    @validator('url')
    def validate_url(cls, url):
        if not url or len(url) < 5:
            raise ValueError("URL too short")
        
        # Basic URL format check
        if not any(url.startswith(prefix) for prefix in ['http://', 'https://', 'ftp://']):
            # Add https:// if missing
            url = 'https://' + url
        
        return url
    
    @validator('features')
    def validate_features(cls, features):
        if features:
            validator = InputValidator()
            try:
                validated = validator.validate_features(features, "phishing_detection")
            except ValueError as e:
                raise ValueError(f"Feature validation failed: {e}")
            
            return validated
        return features


class InputSanitizer:
    """Sanitize inputs to prevent injection attacks"""
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize string input
        
        Args:
            input_str: Input string
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            raise ValueError(f"Expected string, got {type(input_str)}")
        
        # Truncate
        sanitized = input_str[:max_length]
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Remove control characters (except newline, tab)
        sanitized = ''.join(
            c for c in sanitized 
            if c.isprintable() or c in ['\n', '\t']
        )
        
        return sanitized
    
    @staticmethod
    def sanitize_numeric(value: float, min_val: float = -1e15, max_val: float = 1e15) -> float:
        """
        Sanitize numeric input
        
        Args:
            value: Input value
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            
        Returns:
            Sanitized value
        """
        if not np.isfinite(value):
            raise ValueError(f"Non-finite value: {value}")
        
        # Clip to range
        return max(min_val, min(max_val, value))


# CLI tool
if __name__ == "__main__":
    import sys
    
    validator = InputValidator()
    
    if len(sys.argv) < 2:
        print("Input Validation Tool")
        print("="*70)
        print("Usage:")
        print("  python input_validator.py test-intrusion")
        print("  python input_validator.py test-attacks")
        print("  python input_validator.py stats")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "test-intrusion":
        # Test valid input
        print("\n✅ Testing valid input...")
        valid_features = {
            "dur": 1.5,
            "spkts": 10,
            "dpkts": 8,
            "sbytes": 1024,
            "dbytes": 512,
            "rate": 5.0,
            "sttl": 64,
            "dttl": 64,
            "sload": 100.0,
            "dload": 50.0,
            "sloss": 0,
            "dloss": 0,
            "sinpkt": 0.1,
            "dinpkt": 0.1,
            "sjit": 0.01,
            "djit": 0.01
        }
        
        try:
            validator.validate_features(valid_features, "intrusion_detection")
            print("   ✅ Validation passed")
        except ValueError as e:
            print(f"   ❌ Validation failed: {e}")
        
        # Test invalid input
        print("\n❌ Testing invalid input (negative value)...")
        invalid_features = valid_features.copy()
        invalid_features["spkts"] = -100
        
        try:
            validator.validate_features(invalid_features, "intrusion_detection")
            print("   ⚠️  Validation should have failed!")
        except ValueError as e:
            print(f"   ✅ Correctly rejected: {e}")
    
    elif command == "test-attacks":
        print("\n🚨 Testing adversarial attack detection...")
        
        # Attack 1: All zeros
        print("\n1. All zeros attack:")
        attack1 = {f"feature_{i}": 0.0 for i in range(10)}
        result = validator.detect_adversarial_patterns(attack1, "test_client")
        print(f"   {'✅ Detected' if result else '❌ Missed'}: {result}")
        
        # Attack 2: All same values
        print("\n2. Uniform values attack:")
        attack2 = {f"feature_{i}": 42.0 for i in range(10)}
        result = validator.detect_adversarial_patterns(attack2, "test_client")
        print(f"   {'✅ Detected' if result else '❌ Missed'}: {result}")
        
        # Attack 3: Micro perturbations
        print("\n3. Micro perturbations attack:")
        attack3 = {f"feature_{i}": 1.0 + i * 1e-15 for i in range(10)}
        result = validator.detect_adversarial_patterns(attack3, "test_client")
        print(f"   {'✅ Detected' if result else '❌ Missed'}: {result}")
        
        # Normal input (should not be flagged)
        print("\n4. Normal input:")
        normal = {f"feature_{i}": float(i * 10) for i in range(10)}
        result = validator.detect_adversarial_patterns(normal, "test_client")
        print(f"   {'✅ Passed' if not result else '❌ False positive'}: {result}")
    
    elif command == "stats":
        stats = validator.get_attack_stats()
        
        print("\n📊 Attack Detection Statistics:")
        print("="*70)
        print(f"Total attacks detected: {stats['total_attacks']}")
        
        if stats['total_attacks'] > 0:
            print(f"\nAttack types:")
            for attack_type, count in stats.get('attack_types', {}).items():
                print(f"  - {attack_type}: {count}")
            
            print(f"\nUnique clients: {stats['unique_clients']}")
            
            print(f"\nRecent attacks:")
            for attack in stats.get('recent_attacks', []):
                print(f"  - {attack['timestamp']}: {attack['attack_type']} from {attack['client_id']}")
        
        print("="*70 + "\n")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)