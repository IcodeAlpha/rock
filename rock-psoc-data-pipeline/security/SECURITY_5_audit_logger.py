"""
Security Audit Logger
Comprehensive logging of security events and API usage
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
import json
from typing import Dict, List, Optional
from collections import defaultdict
import hashlib

class SecurityAuditLogger:
    """Log security events and maintain audit trail"""
    
    def __init__(
        self, 
        log_file: str = "logs/security_audit.log",
        json_log: str = "logs/security_audit.json"
    ):
        self.log_file = Path(log_file)
        self.json_log = Path(json_log)
        
        # Create log directory
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup text logger
        self.logger = logging.getLogger("security_audit")
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            # File handler
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            self.logger.addHandler(file_handler)
            
            # Console handler for critical events
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.WARNING)
            console_handler.setFormatter(logging.Formatter(
                '🚨 %(levelname)s: %(message)s'
            ))
            self.logger.addHandler(console_handler)
        
        # JSON event store
        self.events = []
        self._load_json_log()
    
    def _load_json_log(self):
        """Load existing JSON log"""
        if self.json_log.exists():
            try:
                with open(self.json_log, 'r') as f:
                    self.events = json.load(f)
            except:
                self.events = []
    
    def _save_json_log(self):
        """Save JSON log"""
        # Keep only recent events (last 10000)
        if len(self.events) > 10000:
            self.events = self.events[-10000:]
        
        with open(self.json_log, 'w') as f:
            json.dump(self.events, f, indent=2)
    
    def _create_event(self, event_type: str, details: Dict) -> Dict:
        """Create standardized event"""
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
    
    def log_prediction_request(
        self,
        client_ip: str,
        model: str,
        features: Dict,
        api_key_hash: str,
        endpoint: str = "/predict"
    ):
        """Log ML prediction request"""
        event = self._create_event("prediction_request", {
            "client_ip": client_ip,
            "model": model,
            "endpoint": endpoint,
            "feature_count": len(features),
            "api_key_hash": api_key_hash[:8],  # First 8 chars only
        })
        
        self.events.append(event)
        self.logger.info(f"Prediction | {model} | {client_ip} | {len(features)} features")
        
        if len(self.events) % 100 == 0:
            self._save_json_log()
    
    def log_authentication_failure(
        self,
        client_ip: str,
        reason: str,
        api_key_provided: Optional[str] = None
    ):
        """Log failed authentication attempt"""
        event = self._create_event("auth_failure", {
            "client_ip": client_ip,
            "reason": reason,
            "api_key_hash": hashlib.sha256(api_key_provided.encode()).hexdigest()[:8] if api_key_provided else None
        })
        
        self.events.append(event)
        self.logger.warning(f"Auth Failed | {client_ip} | {reason}")
        self._save_json_log()
    
    def log_rate_limit_exceeded(
        self,
        client_ip: str,
        api_key_hash: str,
        limit: int,
        current_count: int
    ):
        """Log rate limit violation"""
        event = self._create_event("rate_limit_exceeded", {
            "client_ip": client_ip,
            "api_key_hash": api_key_hash[:8],
            "limit": limit,
            "current_count": current_count
        })
        
        self.events.append(event)
        self.logger.warning(
            f"Rate Limit | {client_ip} | {current_count}/{limit} requests"
        )
        self._save_json_log()
    
    def log_model_access(
        self,
        model_name: str,
        action: str,
        user: str,
        success: bool = True
    ):
        """Log model file access"""
        event = self._create_event("model_access", {
            "model": model_name,
            "action": action,
            "user": user,
            "success": success
        })
        
        self.events.append(event)
        
        if success:
            self.logger.info(f"Model Access | {model_name} | {action} | {user}")
        else:
            self.logger.warning(f"Model Access Failed | {model_name} | {action} | {user}")
        
        self._save_json_log()
    
    def log_integrity_check(
        self,
        model_name: str,
        passed: bool,
        expected_hash: str = None,
        actual_hash: str = None
    ):
        """Log model integrity verification"""
        event = self._create_event("integrity_check", {
            "model": model_name,
            "passed": passed,
            "expected_hash": expected_hash[:16] if expected_hash else None,
            "actual_hash": actual_hash[:16] if actual_hash else None
        })
        
        self.events.append(event)
        
        if passed:
            self.logger.info(f"Integrity OK | {model_name}")
        else:
            self.logger.critical(
                f"INTEGRITY FAILURE | {model_name} | "
                f"Expected: {expected_hash[:16]}... | "
                f"Actual: {actual_hash[:16]}..."
            )
        
        self._save_json_log()
    
    def log_adversarial_attack(
        self,
        client_ip: str,
        attack_type: str,
        model: str,
        features_sample: Dict
    ):
        """Log detected adversarial attack"""
        event = self._create_event("adversarial_attack", {
            "client_ip": client_ip,
            "attack_type": attack_type,
            "model": model,
            "features_sample": features_sample
        })
        
        self.events.append(event)
        self.logger.critical(
            f"ADVERSARIAL ATTACK | {attack_type} | {model} | {client_ip}"
        )
        self._save_json_log()
    
    def log_security_incident(
        self,
        incident_type: str,
        severity: str,
        details: Dict
    ):
        """Log general security incident"""
        event = self._create_event("security_incident", {
            "incident_type": incident_type,
            "severity": severity,
            "details": details
        })
        
        self.events.append(event)
        
        if severity == "critical":
            self.logger.critical(f"SECURITY INCIDENT | {incident_type} | {details}")
        elif severity == "high":
            self.logger.error(f"Security Incident | {incident_type} | {details}")
        else:
            self.logger.warning(f"Security Incident | {incident_type} | {details}")
        
        self._save_json_log()
    
    def get_recent_events(
        self,
        event_type: Optional[str] = None,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get recent security events
        
        Args:
            event_type: Filter by event type (None = all)
            hours: How many hours back to look
            limit: Maximum events to return
            
        Returns:
            List of events
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()
        
        filtered = [
            event for event in self.events
            if event["timestamp"] >= cutoff_str
            and (event_type is None or event["event_type"] == event_type)
        ]
        
        return filtered[-limit:]
    
    def get_statistics(self, hours: int = 24) -> Dict:
        """
        Get security statistics
        
        Args:
            hours: Time window in hours
            
        Returns:
            Statistics dictionary
        """
        recent = self.get_recent_events(hours=hours, limit=10000)
        
        if not recent:
            return {
                "time_window_hours": hours,
                "total_events": 0
            }
        
        # Count by type
        event_counts = defaultdict(int)
        for event in recent:
            event_counts[event["event_type"]] += 1
        
        # Unique clients
        clients = set()
        for event in recent:
            if "client_ip" in event["details"]:
                clients.add(event["details"]["client_ip"])
        
        # Failed auth attempts
        auth_failures = [e for e in recent if e["event_type"] == "auth_failure"]
        
        # Rate limit violations
        rate_limit_violations = [e for e in recent if e["event_type"] == "rate_limit_exceeded"]
        
        # Adversarial attacks
        attacks = [e for e in recent if e["event_type"] == "adversarial_attack"]
        
        # Integrity failures
        integrity_failures = [
            e for e in recent 
            if e["event_type"] == "integrity_check" and not e["details"]["passed"]
        ]
        
        return {
            "time_window_hours": hours,
            "total_events": len(recent),
            "event_counts": dict(event_counts),
            "unique_clients": len(clients),
            "auth_failures": len(auth_failures),
            "rate_limit_violations": len(rate_limit_violations),
            "adversarial_attacks": len(attacks),
            "integrity_failures": len(integrity_failures),
            "top_clients": self._get_top_clients(recent, limit=5),
            "recent_critical_events": [
                e for e in recent[-20:]
                if e["event_type"] in ["adversarial_attack", "security_incident", "integrity_check"]
            ]
        }
    
    def _get_top_clients(self, events: List[Dict], limit: int = 5) -> List[Dict]:
        """Get top clients by request count"""
        client_counts = defaultdict(int)
        
        for event in events:
            if "client_ip" in event["details"]:
                client_counts[event["details"]["client_ip"]] += 1
        
        sorted_clients = sorted(
            client_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [
            {"client_ip": ip, "event_count": count}
            for ip, count in sorted_clients[:limit]
        ]
    
    def generate_report(self, hours: int = 24) -> str:
        """
        Generate security report
        
        Args:
            hours: Time window in hours
            
        Returns:
            Formatted report string
        """
        stats = self.get_statistics(hours)
        
        report = []
        report.append("="*70)
        report.append(f"SECURITY AUDIT REPORT - Last {hours} hours")
        report.append("="*70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        report.append("OVERVIEW:")
        report.append(f"  Total Events: {stats['total_events']}")
        report.append(f"  Unique Clients: {stats['unique_clients']}")
        report.append("")
        
        report.append("SECURITY ALERTS:")
        report.append(f"  ❌ Failed Authentications: {stats['auth_failures']}")
        report.append(f"  ⚠️  Rate Limit Violations: {stats['rate_limit_violations']}")
        report.append(f"  🚨 Adversarial Attacks: {stats['adversarial_attacks']}")
        report.append(f"  🔒 Integrity Failures: {stats['integrity_failures']}")
        report.append("")
        
        if stats['event_counts']:
            report.append("EVENT BREAKDOWN:")
            for event_type, count in sorted(stats['event_counts'].items(), key=lambda x: x[1], reverse=True):
                report.append(f"  - {event_type}: {count}")
            report.append("")
        
        if stats['top_clients']:
            report.append("TOP CLIENTS:")
            for client in stats['top_clients']:
                report.append(f"  - {client['client_ip']}: {client['event_count']} events")
            report.append("")
        
        if stats['recent_critical_events']:
            report.append("RECENT CRITICAL EVENTS:")
            for event in stats['recent_critical_events'][-10:]:
                report.append(
                    f"  [{event['timestamp']}] {event['event_type']}: "
                    f"{event['details']}"
                )
        
        report.append("="*70)
        
        return "\n".join(report)


# Global logger instance
audit_logger = SecurityAuditLogger()


# CLI tool
if __name__ == "__main__":
    import sys
    
    logger = SecurityAuditLogger()
    
    if len(sys.argv) < 2:
        print("Security Audit Logger")
        print("="*70)
        print("Usage:")
        print("  python security_logger.py stats [hours]")
        print("  python security_logger.py report [hours]")
        print("  python security_logger.py test")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "stats":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        stats = logger.get_statistics(hours)
        
        print(f"\n📊 Security Statistics (Last {hours} hours):")
        print("="*70)
        print(f"Total Events: {stats['total_events']}")
        print(f"Unique Clients: {stats['unique_clients']}")
        print(f"\nSecurity Alerts:")
        print(f"  Failed Authentications: {stats['auth_failures']}")
        print(f"  Rate Limit Violations: {stats['rate_limit_violations']}")
        print(f"  Adversarial Attacks: {stats['adversarial_attacks']}")
        print(f"  Integrity Failures: {stats['integrity_failures']}")
        print("="*70 + "\n")
    
    elif command == "report":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        report = logger.generate_report(hours)
        print(f"\n{report}\n")
    
    elif command == "test":
        print("\n🧪 Testing security logger...")
        
        logger.log_prediction_request(
            client_ip="192.168.1.100",
            model="intrusion_detection",
            features={"test": 1.0},
            api_key_hash="testhash123"
        )
        print("   ✅ Logged prediction request")
        
        logger.log_authentication_failure(
            client_ip="192.168.1.200",
            reason="Invalid API key"
        )
        print("   ✅ Logged auth failure")
        
        logger.log_adversarial_attack(
            client_ip="192.168.1.300",
            attack_type="all_zeros",
            model="intrusion_detection",
            features_sample={"f1": 0, "f2": 0}
        )
        print("   ✅ Logged adversarial attack")
        
        print("\nTest complete! Check logs/security_audit.log\n")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)