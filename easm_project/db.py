"""
ARES - Database Module (db.py)
MongoDB Connection and Data Access Layer

This module handles all database operations for the ARES EASM tool.
It manages the hierarchical data structure: Target -> Subdomains -> Ports -> Vulnerabilities
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from datetime import datetime
from bson.objectid import ObjectId
import sys


class Database:
    """
    Database class for ARES MongoDB operations.
    Implements singleton pattern for connection reuse.
    """
    
    _instance = None
    _client = None
    _db = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialize_connection()
        return cls._instance
    
    def _initialize_connection(self):
        """Initialize MongoDB connection with error handling."""
        try:
            # MongoDB connection settings
            MONGO_URI = "mongodb://localhost:27017/"
            DATABASE_NAME = "ares_easm"
            
            # Create client with timeout settings
            self._client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000
            )
            
            # Test connection
            self._client.admin.command('ping')
            
            # Get database reference
            self._db = self._client[DATABASE_NAME]
            
            # Ensure indexes for performance
            self._create_indexes()
            
            print("[✓] MongoDB connection established successfully.")
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"[✗] Failed to connect to MongoDB: {e}")
            print("[!] Please ensure MongoDB is running on localhost:27017")
            sys.exit(1)
    
    def _create_indexes(self):
        """Create database indexes for optimized queries."""
        # Index on scans collection
        self._db.scans.create_index("target_domain")
        self._db.scans.create_index("created_at")
        self._db.scans.create_index("status")
        
        # Compound index for faster lookups
        self._db.scans.create_index([
            ("target_domain", 1),
            ("created_at", -1)
        ])
    
    @property
    def db(self):
        """Return database reference."""
        return self._db
    
    # ==================== SCAN OPERATIONS ====================
    
    def create_scan(self, target_domain):
        """
        Create a new scan record for a target domain.
        
        Args:
            target_domain (str): The target domain to scan
            
        Returns:
            str: The scan ID as string
        """
        scan_document = {
            "target_domain": target_domain.lower().strip(),
            "status": "pending",  # pending, running, completed, failed
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "completed_at": None,
            
            # Scan results containers
            "subdomains": [],
            "ports": [],
            "live_hosts": [],
            "vulnerabilities": [],
            
            # Statistics
            "stats": {
                "total_subdomains": 0,
                "total_ports": 0,
                "total_live_hosts": 0,
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0
            },
            
            # Scan progress tracking
            "progress": {
                "subfinder": "pending",
                "naabu": "pending",
                "httpx": "pending",
                "nuclei": "pending"
            },
            
            # Error logging
            "errors": []
        }
        
        result = self._db.scans.insert_one(scan_document)
        return str(result.inserted_id)
    
    def get_scan(self, scan_id):
        """
        Retrieve a scan by its ID.
        
        Args:
            scan_id (str): The scan ID
            
        Returns:
            dict: The scan document or None
        """
        try:
            return self._db.scans.find_one({"_id": ObjectId(scan_id)})
        except Exception:
            return None
    
    def get_scan_by_domain(self, target_domain):
        """
        Get the most recent scan for a domain.
        
        Args:
            target_domain (str): The target domain
            
        Returns:
            dict: The most recent scan document or None
        """
        return self._db.scans.find_one(
            {"target_domain": target_domain.lower().strip()},
            sort=[("created_at", -1)]
        )
    
    def get_all_scans(self, limit=50):
        """
        Get all scans, ordered by creation date (newest first).
        
        Args:
            limit (int): Maximum number of scans to return
            
        Returns:
            list: List of scan documents
        """
        cursor = self._db.scans.find().sort("created_at", -1).limit(limit)
        return list(cursor)
    
    def update_scan_status(self, scan_id, status):
        """
        Update the status of a scan.
        
        Args:
            scan_id (str): The scan ID
            status (str): New status (pending, running, completed, failed)
        """
        update_data = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if status == "completed":
            update_data["completed_at"] = datetime.utcnow()
        
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": update_data}
        )
    
    def update_tool_progress(self, scan_id, tool_name, status):
        """
        Update the progress of a specific tool in the scan.
        
        Args:
            scan_id (str): The scan ID
            tool_name (str): Tool name (subfinder, naabu, httpx, nuclei)
            status (str): Status (pending, running, completed, failed)
        """
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    f"progress.{tool_name}": status,
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    # ==================== DATA STORAGE OPERATIONS ====================
    
    def store_subdomains(self, scan_id, subdomains):
        """
        Store discovered subdomains.
        
        Args:
            scan_id (str): The scan ID
            subdomains (list): List of subdomain strings
        """
        unique_subdomains = list(set(subdomains))
        
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "subdomains": unique_subdomains,
                    "stats.total_subdomains": len(unique_subdomains),
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    def store_ports(self, scan_id, ports_data):
        """
        Store discovered ports.
        
        Args:
            scan_id (str): The scan ID
            ports_data (list): List of port data dicts [{host, port, protocol}, ...]
        """
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "ports": ports_data,
                    "stats.total_ports": len(ports_data),
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    def store_live_hosts(self, scan_id, live_hosts):
        """
        Store live HTTP/HTTPS hosts.
        
        Args:
            scan_id (str): The scan ID
            live_hosts (list): List of live host URLs
        """
        unique_hosts = list(set(live_hosts))
        
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "live_hosts": unique_hosts,
                    "stats.total_live_hosts": len(unique_hosts),
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    def store_vulnerabilities(self, scan_id, vulnerabilities):
        """
        Store discovered vulnerabilities and update severity counts.
        
        Args:
            scan_id (str): The scan ID
            vulnerabilities (list): List of vulnerability dicts from Nuclei
        """
        # Count severities
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("info", {}).get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "vulnerabilities": vulnerabilities,
                    "stats.total_vulnerabilities": len(vulnerabilities),
                    "stats.critical_count": severity_counts["critical"],
                    "stats.high_count": severity_counts["high"],
                    "stats.medium_count": severity_counts["medium"],
                    "stats.low_count": severity_counts["low"],
                    "stats.info_count": severity_counts["info"],
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    def add_error(self, scan_id, error_message):
        """
        Add an error message to the scan's error log.
        
        Args:
            scan_id (str): The scan ID
            error_message (str): The error message to log
        """
        error_entry = {
            "message": error_message,
            "timestamp": datetime.utcnow()
        }
        
        self._db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$push": {"errors": error_entry},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
    
    # ==================== CLEANUP OPERATIONS ====================
    
    def delete_scan(self, scan_id):
        """
        Delete a scan by its ID.
        
        Args:
            scan_id (str): The scan ID
            
        Returns:
            bool: True if deleted, False otherwise
        """
        result = self._db.scans.delete_one({"_id": ObjectId(scan_id)})
        return result.deleted_count > 0
    
    def delete_all_scans(self):
        """
        Delete all scans (use with caution).
        
        Returns:
            int: Number of deleted documents
        """
        result = self._db.scans.delete_many({})
        return result.deleted_count
    
    def close_connection(self):
        """Close the MongoDB connection."""
        if self._client:
            self._client.close()
            print("[✓] MongoDB connection closed.")


# Create a global database instance for import
db = Database()


# ==================== CONVENIENCE FUNCTIONS ====================

def get_db():
    """Get the database instance."""
    return db


def create_new_scan(target_domain):
    """Convenience function to create a new scan."""
    return db.create_scan(target_domain)


def get_scan_results(scan_id):
    """Convenience function to get scan results."""
    return db.get_scan(scan_id)
