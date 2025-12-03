import threading
import time
import os
from datetime import datetime

# Optional Import: Handle missing elasticsearch module gracefully
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    Elasticsearch = None
    bulk = None

class TelemetryService:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(TelemetryService, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        self.es_host = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        self.client = None
        self._connect()
        self._initialized = True

    def _connect(self):
        """Establish connection to Elasticsearch safely."""
        if not ELASTICSEARCH_AVAILABLE:
            print("⚠️ [Telemetry] Elasticsearch module not found. Telemetry disabled.")
            return

        try:
            self.client = Elasticsearch([self.es_host])
            if not self.client.ping():
                print(f"⚠️ [Telemetry] Could not ping Elasticsearch at {self.es_host}")
                self.client = None
            else:
                print(f"✅ [Telemetry] Connected to Elasticsearch at {self.es_host}")
        except Exception as e:
            print(f"❌ [Telemetry] Connection failed: {e}")
            self.client = None

    def log_attack(self, data):
        """Single log method (Legacy support)."""
        self.log_bulk_threats(data.get("scan_id", "unknown"), [data])

    def log_bulk_threats(self, scan_id, threats_list):
        """
        Log multiple threats at once using Bulk API.
        Runs in a background thread.
        """
        if not ELASTICSEARCH_AVAILABLE:
            return

        if not self.client:
            self._connect()
            if not self.client:
                return

        # Run in background thread
        thread = threading.Thread(
            target=self._send_bulk_to_es, 
            args=(scan_id, threats_list)
        )
        thread.daemon = True
        thread.start()

    def _enrich_threat_data(self, threat):
        """
        Enrich threat data with Severity and Action fields for professional dashboards.
        """
        attack_type = threat.get("attack_type", "Unknown")
        
        # Default mappings
        severity = "Low"
        action = "Allowed"
        
        # Severity Logic
        if attack_type in ["SQL Injection", "Command Injection", "Remote File Inclusion (RFI)", "Shell Upload Attempt", "XXE"]:
            severity = "Critical"
        elif attack_type in ["Cross-Site Scripting (XSS)", "SSRF", "Directory Traversal / LFI"]:
            severity = "High"
        elif attack_type in ["Bruteforce Attack", "URL Spoofing / Typosquatting"]:
            severity = "Medium"
        elif attack_type == "Benign":
            severity = "Info"
            
        # Action Logic (Simulated based on severity/type)
        if severity in ["Critical", "High"]:
            action = "Blocked"
        else:
            action = "Monitored"

        # Override if status code implies success/failure
        status_code = threat.get("status_code", 0)
        if 200 <= status_code < 300 and severity != "Info":
            action = "Breach Confirmed" # Critical: Attack succeeded
        elif status_code >= 400:
            action = "Blocked"

        return severity, action

    def _send_bulk_to_es(self, scan_id, threats_list):
        """Worker method to send bulk data."""
        if not ELASTICSEARCH_AVAILABLE or not self.client:
            return

        try:
            actions = []
            timestamp = datetime.utcnow().isoformat()

            for threat in threats_list:
                # Enrich data
                severity, action_taken = self._enrich_threat_data(threat)

                doc = {
                    "@timestamp": threat.get("@timestamp", timestamp),
                    "scan_id": scan_id,
                    "source_ip": threat.get("source_ip", "0.0.0.0"),
                    "target_host": threat.get("target_host", ""),
                    "url": threat.get("url", ""),
                    "attack_type": threat.get("attack_type", "Unknown"),
                    "severity": severity,
                    "action": action_taken, # New Field
                    "confidence_score": threat.get("confidence", 1.0), # New Field
                    "status_code": threat.get("status_code", 0),
                    "detection_method": threat.get("detection_method", "Unknown"),
                    "evidence": threat.get("evidence", ""),
                }
                
                action = {
                    "_index": "aura-attacks",
                    "_source": doc
                }
                actions.append(action)

            if actions:
                success, _ = bulk(self.client, actions)
                print(f"📡 [Telemetry] Logged {success} enriched events for Scan ID: {scan_id}")

        except Exception as e:
            print(f"⚠️ [Telemetry] Failed to log bulk data: {e}")

# Global Singleton Instance
telemetry = TelemetryService()
