"""
ARES - Database Module
Handles all MongoDB connections and data operations.
Implements hierarchical storage: Target -> Subdomains -> Ports -> Vulnerabilities
"""

import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from bson import ObjectId


class AresDB:
    """
    MongoDB handler for ARES scan data persistence.
    Provides CRUD operations for scans, assets, and vulnerabilities.
    """

    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize MongoDB connection.
        
        Args:
            connection_string: MongoDB URI. Defaults to localhost if not provided.
        """
        self.connection_string = connection_string or os.getenv(
            "MONGO_URI", 
            "mongodb://localhost:27017/"
        )
        
        try:
            self.client: MongoClient = MongoClient(
                self.connection_string,
                serverSelectionTimeoutMS=5000
            )
            # Test connection
            self.client.admin.command('ping')
            print("[+] Successfully connected to MongoDB")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"[!] MongoDB connection failed: {e}")
            raise
            
        self.db: Database = self.client["ares_db"]
        
        # Collections
        self.scans: Collection = self.db["scans"]
        self.assets: Collection = self.db["assets"]
        self.vulnerabilities: Collection = self.db["vulnerabilities"]
        
        # Ensure indexes for performance
        self._create_indexes()

    def _create_indexes(self) -> None:
        """Create database indexes for optimized queries."""
        try:
            # Scans collection indexes
            self.scans.create_index("target_domain")
            self.scans.create_index("created_at")
            self.scans.create_index("status")
            
            # Assets collection indexes
            self.assets.create_index("scan_id")
            self.assets.create_index("subdomain")
            self.assets.create_index([("scan_id", 1), ("subdomain", 1)], unique=True)
            
            # Vulnerabilities collection indexes
            self.vulnerabilities.create_index("scan_id")
            self.vulnerabilities.create_index("asset_id")
            self.vulnerabilities.create_index("severity")
            self.vulnerabilities.create_index("template_id")
            self.vulnerabilities.create_index([("scan_id", 1), ("severity", 1)])
            
            print("[+] Database indexes created successfully")
        except Exception as e:
            print(f"[!] Warning: Could not create indexes: {e}")

    def close(self) -> None:
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            print("[+] MongoDB connection closed")

    # ==================== SCAN OPERATIONS ====================

    def create_scan(self, target_domain: str) -> str:
        """
        Create a new scan record.
        
        Args:
            target_domain: The target domain to scan.
            
        Returns:
            The ID of the created scan as a string.
        """
        # Clean the domain
        clean_domain = target_domain.lower().strip()
        clean_domain = clean_domain.replace("http://", "").replace("https://", "")
        clean_domain = clean_domain.rstrip("/")
        
        scan_doc = {
            "target_domain": clean_domain,
            "status": "initializing",
            "current_phase": "starting",
            "progress_percent": 0,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "completed_at": None,
            "statistics": {
                "total_assets": 0,
                "total_ports": 0,
                "total_live_urls": 0,
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0
            },
            "phases_completed": {
                "subfinder": False,
                "naabu": False,
                "httpx": False,
                "nuclei": False
            },
            "error_log": []
        }
        
        result = self.scans.insert_one(scan_doc)
        return str(result.inserted_id)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan by its ID.
        
        Args:
            scan_id: The scan ID string.
            
        Returns:
            The scan document or None if not found.
        """
        try:
            scan = self.scans.find_one({"_id": ObjectId(scan_id)})
            if scan:
                scan["_id"] = str(scan["_id"])
            return scan
        except Exception as e:
            print(f"[!] Error retrieving scan: {e}")
            return None

    def get_scan_by_domain(self, target_domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve the most recent scan for a domain.
        
        Args:
            target_domain: The target domain.
            
        Returns:
            The most recent scan document or None.
        """
        clean_domain = target_domain.lower().strip()
        clean_domain = clean_domain.replace("http://", "").replace("https://", "")
        clean_domain = clean_domain.rstrip("/")
        
        scan = self.scans.find_one(
            {"target_domain": clean_domain},
            sort=[("created_at", DESCENDING)]
        )
        if scan:
            scan["_id"] = str(scan["_id"])
        return scan

    def update_scan_status(
        self, 
        scan_id: str, 
        status: str, 
        phase: Optional[str] = None,
        progress: Optional[int] = None
    ) -> bool:
        """
        Update scan status and optionally the current phase.
        
        Args:
            scan_id: The scan ID.
            status: New status (initializing, running, completed, failed).
            phase: Current scanning phase.
            progress: Progress percentage (0-100).
            
        Returns:
            True if update was successful.
        """
        update_doc = {
            "status": status,
            "updated_at": datetime.utcnow()
        }
        
        if phase:
            update_doc["current_phase"] = phase
            
        if progress is not None:
            update_doc["progress_percent"] = min(100, max(0, progress))
            
        if status == "completed":
            update_doc["completed_at"] = datetime.utcnow()
            update_doc["progress_percent"] = 100
            
        result = self.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": update_doc}
        )
        
        return result.modified_count > 0

    def mark_phase_completed(self, scan_id: str, phase: str) -> bool:
        """
        Mark a specific scanning phase as completed.
        
        Args:
            scan_id: The scan ID.
            phase: Phase name (subfinder, naabu, httpx, nuclei).
            
        Returns:
            True if update was successful.
        """
        result = self.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    f"phases_completed.{phase}": True,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0

    def add_scan_error(self, scan_id: str, error_message: str) -> bool:
        """
        Add an error message to the scan's error log.
        
        Args:
            scan_id: The scan ID.
            error_message: The error message to log.
            
        Returns:
            True if update was successful.
        """
        error_entry = {
            "timestamp": datetime.utcnow(),
            "message": str(error_message)
        }
        
        result = self.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$push": {"error_log": error_entry},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        
        return result.modified_count > 0

    def update_scan_statistics(self, scan_id: str) -> bool:
        """
        Recalculate and update scan statistics from assets and vulnerabilities.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            True if update was successful.
        """
        try:
            # Count assets
            total_assets = self.assets.count_documents({"scan_id": scan_id})
            
            # Count total ports across all assets
            port_pipeline = [
                {"$match": {"scan_id": scan_id}},
                {"$project": {"port_count": {"$size": {"$ifNull": ["$ports", []]}}}},
                {"$group": {"_id": None, "total": {"$sum": "$port_count"}}}
            ]
            port_result = list(self.assets.aggregate(port_pipeline))
            total_ports = port_result[0]["total"] if port_result else 0
            
            # Count total live URLs
            url_pipeline = [
                {"$match": {"scan_id": scan_id}},
                {"$project": {"url_count": {"$size": {"$ifNull": ["$live_urls", []]}}}},
                {"$group": {"_id": None, "total": {"$sum": "$url_count"}}}
            ]
            url_result = list(self.assets.aggregate(url_pipeline))
            total_live_urls = url_result[0]["total"] if url_result else 0
            
            # Count vulnerabilities by severity
            total_vulns = self.vulnerabilities.count_documents({"scan_id": scan_id})
            critical_count = self.vulnerabilities.count_documents(
                {"scan_id": scan_id, "severity": "critical"}
            )
            high_count = self.vulnerabilities.count_documents(
                {"scan_id": scan_id, "severity": "high"}
            )
            medium_count = self.vulnerabilities.count_documents(
                {"scan_id": scan_id, "severity": "medium"}
            )
            low_count = self.vulnerabilities.count_documents(
                {"scan_id": scan_id, "severity": "low"}
            )
            info_count = self.vulnerabilities.count_documents(
                {"scan_id": scan_id, "severity": "info"}
            )
            
            statistics = {
                "total_assets": total_assets,
                "total_ports": total_ports,
                "total_live_urls": total_live_urls,
                "total_vulnerabilities": total_vulns,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "info_count": info_count
            }
            
            result = self.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {
                    "$set": {
                        "statistics": statistics,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            return result.modified_count > 0
            
        except Exception as e:
            print(f"[!] Error updating statistics: {e}")
            return False

    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve all scans, ordered by creation date descending.
        
        Args:
            limit: Maximum number of scans to return.
            
        Returns:
            List of scan documents.
        """
        scans = list(
            self.scans.find()
            .sort("created_at", DESCENDING)
            .limit(limit)
        )
        
        for scan in scans:
            scan["_id"] = str(scan["_id"])
            
        return scans

    # ==================== ASSET OPERATIONS ====================

    def add_asset(
        self, 
        scan_id: str, 
        subdomain: str, 
        source: str = "subfinder"
    ) -> Optional[str]:
        """
        Add a discovered asset (subdomain) to a scan.
        
        Args:
            scan_id: The parent scan ID.
            subdomain: The discovered subdomain.
            source: Discovery source tool.
            
        Returns:
            The ID of the created asset or None if duplicate.
        """
        clean_subdomain = subdomain.lower().strip()
        
        if not clean_subdomain:
            return None
            
        asset_doc = {
            "scan_id": scan_id,
            "subdomain": clean_subdomain,
            "source": source,
            "discovered_at": datetime.utcnow(),
            "ports": [],
            "live_urls": [],
            "technologies": []
        }
        
        try:
            result = self.assets.insert_one(asset_doc)
            return str(result.inserted_id)
        except Exception:
            # Duplicate subdomain for this scan - ignore
            return None

    def add_assets_bulk(
        self, 
        scan_id: str, 
        subdomains: List[str], 
        source: str = "subfinder"
    ) -> int:
        """
        Bulk insert multiple assets, ignoring duplicates.
        
        Args:
            scan_id: The parent scan ID.
            subdomains: List of discovered subdomains.
            source: Discovery source tool.
            
        Returns:
            Number of assets inserted.
        """
        if not subdomains:
            return 0
        
        inserted_count = 0
        
        for subdomain in subdomains:
            clean_subdomain = subdomain.lower().strip()
            
            if not clean_subdomain:
                continue
                
            asset_doc = {
                "scan_id": scan_id,
                "subdomain": clean_subdomain,
                "source": source,
                "discovered_at": datetime.utcnow(),
                "ports": [],
                "live_urls": [],
                "technologies": []
            }
            
            try:
                # Use update with upsert to handle duplicates gracefully
                result = self.assets.update_one(
                    {"scan_id": scan_id, "subdomain": clean_subdomain},
                    {"$setOnInsert": asset_doc},
                    upsert=True
                )
                if result.upserted_id:
                    inserted_count += 1
            except Exception:
                continue
                
        return inserted_count

    def get_assets_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get all assets for a scan.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            List of asset documents.
        """
        assets = list(self.assets.find({"scan_id": scan_id}))
        
        for asset in assets:
            asset["_id"] = str(asset["_id"])
            
        return assets

    def get_asset_by_subdomain(
        self, 
        scan_id: str, 
        subdomain: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific asset by subdomain.
        
        Args:
            scan_id: The scan ID.
            subdomain: The subdomain to find.
            
        Returns:
            The asset document or None.
        """
        asset = self.assets.find_one({
            "scan_id": scan_id,
            "subdomain": subdomain.lower().strip()
        })
        
        if asset:
            asset["_id"] = str(asset["_id"])
            
        return asset

    def add_port_to_asset(
        self, 
        scan_id: str, 
        subdomain: str, 
        port: int, 
        protocol: str = "tcp"
    ) -> bool:
        """
        Add a discovered port to an asset.
        
        Args:
            scan_id: The scan ID.
            subdomain: The subdomain.
            port: The port number.
            protocol: Port protocol (tcp/udp).
            
        Returns:
            True if update was successful.
        """
        port_doc = {
            "port": int(port),
            "protocol": protocol,
            "discovered_at": datetime.utcnow()
        }
        
        # First check if port already exists
        existing = self.assets.find_one({
            "scan_id": scan_id,
            "subdomain": subdomain.lower().strip(),
            "ports.port": int(port)
        })
        
        if existing:
            return True  # Port already recorded
        
        result = self.assets.update_one(
            {"scan_id": scan_id, "subdomain": subdomain.lower().strip()},
            {"$push": {"ports": port_doc}}
        )
        
        return result.modified_count > 0

    def add_ports_bulk(
        self, 
        scan_id: str, 
        host_port_list: List[Dict[str, Any]]
    ) -> int:
        """
        Add multiple ports to multiple assets efficiently.
        
        Args:
            scan_id: The scan ID.
            host_port_list: List of dicts with 'host' and 'port' keys.
            
        Returns:
            Number of ports added.
        """
        added_count = 0
        
        for item in host_port_list:
            host = item.get("host", "").lower().strip()
            port = item.get("port")
            
            if not host or port is None:
                continue
                
            try:
                port = int(port)
            except (ValueError, TypeError):
                continue
                
            if self.add_port_to_asset(scan_id, host, port):
                added_count += 1
                
        return added_count

    def add_live_url_to_asset(
        self, 
        scan_id: str, 
        subdomain: str, 
        url: str, 
        status_code: Optional[int] = None,
        title: Optional[str] = None,
        technologies: Optional[List[str]] = None,
        content_length: Optional[int] = None
    ) -> bool:
        """
        Add a live URL discovered by HTTPX to an asset.
        
        Args:
            scan_id: The scan ID.
            subdomain: The subdomain.
            url: The live URL.
            status_code: HTTP status code.
            title: Page title.
            technologies: Detected technologies.
            content_length: Response content length.
            
        Returns:
            True if update was successful.
        """
        # Check if URL already exists
        existing = self.assets.find_one({
            "scan_id": scan_id,
            "subdomain": subdomain.lower().strip(),
            "live_urls.url": url
        })
        
        if existing:
            return True  # URL already recorded
            
        url_doc = {
            "url": url,
            "status_code": status_code,
            "title": title,
            "content_length": content_length,
            "discovered_at": datetime.utcnow()
        }
        
        update_ops = {"$push": {"live_urls": url_doc}}
        
        if technologies:
            update_ops["$addToSet"] = {"technologies": {"$each": technologies}}
        
        result = self.assets.update_one(
            {"scan_id": scan_id, "subdomain": subdomain.lower().strip()},
            update_ops
        )
        
        return result.modified_count > 0

    def add_live_urls_bulk(
        self, 
        scan_id: str, 
        url_data_list: List[Dict[str, Any]]
    ) -> int:
        """
        Add multiple live URLs to assets efficiently.
        
        Args:
            scan_id: The scan ID.
            url_data_list: List of URL data dicts from HTTPX.
            
        Returns:
            Number of URLs added.
        """
        added_count = 0
        
        for item in url_data_list:
            url = item.get("url", "")
            host = item.get("host", "").lower().strip()
            
            if not url or not host:
                continue
            
            # Extract subdomain from host (remove port if present)
            subdomain = host.split(":")[0] if ":" in host else host
            
            success = self.add_live_url_to_asset(
                scan_id=scan_id,
                subdomain=subdomain,
                url=url,
                status_code=item.get("status_code") or item.get("status-code"),
                title=item.get("title"),
                technologies=item.get("technologies") or item.get("tech"),
                content_length=item.get("content_length") or item.get("content-length")
            )
            
            if success:
                added_count += 1
                
        return added_count

    def get_all_subdomains(self, scan_id: str) -> List[str]:
        """
        Get list of all subdomains for a scan.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            List of subdomain strings.
        """
        assets = self.assets.find(
            {"scan_id": scan_id},
            {"subdomain": 1}
        )
        
        return [asset["subdomain"] for asset in assets]

    def get_all_host_port_pairs(self, scan_id: str) -> List[str]:
        """
        Get all host:port pairs for HTTPX input.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            List of "subdomain:port" strings.
        """
        pairs = []
        assets = self.assets.find(
            {"scan_id": scan_id, "ports": {"$ne": []}}
        )
        
        for asset in assets:
            for port_info in asset.get("ports", []):
                pair = f"{asset['subdomain']}:{port_info['port']}"
                if pair not in pairs:
                    pairs.append(pair)
                
        return pairs

    def get_all_live_urls(self, scan_id: str) -> List[str]:
        """
        Get all live URLs for Nuclei input.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            List of live URL strings.
        """
        urls = []
        assets = self.assets.find(
            {"scan_id": scan_id, "live_urls": {"$ne": []}}
        )
        
        for asset in assets:
            for url_info in asset.get("live_urls", []):
                url = url_info.get("url")
                if url and url not in urls:
                    urls.append(url)
                
        return urls

    # ==================== VULNERABILITY OPERATIONS ====================

    def add_vulnerability(
        self, 
        scan_id: str,
        template_id: str,
        name: str,
        severity: str,
        host: str,
        matched_at: str,
        asset_id: Optional[str] = None,
        description: Optional[str] = None,
        extracted_results: Optional[List[str]] = None,
        curl_command: Optional[str] = None,
        tags: Optional[List[str]] = None,
        reference: Optional[List[str]] = None,
        raw_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a discovered vulnerability.
        
        Args:
            scan_id: The parent scan ID.
            template_id: Nuclei template ID.
            name: Vulnerability name.
            severity: Severity level.
            host: Affected host.
            matched_at: URL/location where vuln was found.
            asset_id: The related asset ID (optional).
            description: Vulnerability description.
            extracted_results: Extracted data from the vuln.
            curl_command: cURL command to reproduce.
            tags: Nuclei template tags.
            reference: Reference URLs.
            raw_data: Raw Nuclei output.
            
        Returns:
            The ID of the created vulnerability.
        """
        vuln_doc = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "template_id": template_id,
            "name": name,
            "severity": severity.lower().strip(),
            "host": host,
            "matched_at": matched_at,
            "description": description,
            "extracted_results": extracted_results or [],
            "curl_command": curl_command,
            "tags": tags or [],
            "reference": reference or [],
            "raw_data": raw_data,
            "discovered_at": datetime.utcnow(),
            "status": "open",
            "notes": []
        }
        
        result = self.vulnerabilities.insert_one(vuln_doc)
        return str(result.inserted_id)

    def add_vulnerabilities_bulk(
        self, 
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> int:
        """
        Bulk insert multiple vulnerabilities.
        
        Args:
            scan_id: The parent scan ID.
            vulnerabilities: List of vulnerability data dicts from Nuclei.
            
        Returns:
            Number of vulnerabilities inserted.
        """
        if not vulnerabilities:
            return 0
        
        vuln_docs = []
        
        for vuln in vulnerabilities:
            # Extract info block if present
            info = vuln.get("info", {})
            
            vuln_doc = {
                "scan_id": scan_id,
                "asset_id": None,
                "template_id": vuln.get("template-id") or vuln.get("template_id", "unknown"),
                "name": info.get("name") or vuln.get("name", "Unknown Vulnerability"),
                "severity": (info.get("severity") or vuln.get("severity", "info")).lower().strip(),
                "host": vuln.get("host", ""),
                "matched_at": vuln.get("matched-at") or vuln.get("matched_at", ""),
                "description": info.get("description") or vuln.get("description"),
                "extracted_results": vuln.get("extracted-results") or vuln.get("extracted_results", []),
                "curl_command": vuln.get("curl-command") or vuln.get("curl_command"),
                "tags": info.get("tags") or vuln.get("tags", []),
                "reference": info.get("reference") or vuln.get("reference", []),
                "raw_data": vuln,
                "discovered_at": datetime.utcnow(),
                "status": "open",
                "notes": []
            }
            
            vuln_docs.append(vuln_doc)
        
        if not vuln_docs:
            return 0
            
        result = self.vulnerabilities.insert_many(vuln_docs)
        return len(result.inserted_ids)

    def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a vulnerability by ID.
        
        Args:
            vuln_id: The vulnerability ID.
            
        Returns:
            The vulnerability document or None.
        """
        try:
            vuln = self.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
            if vuln:
                vuln["_id"] = str(vuln["_id"])
            return vuln
        except Exception:
            return None

    def get_vulnerabilities_by_scan(
        self, 
        scan_id: str, 
        severity_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for a scan, sorted by severity.
        
        Args:
            scan_id: The scan ID.
            severity_filter: Optional severity to filter by.
            
        Returns:
            List of vulnerability documents sorted by severity.
        """
        query = {"scan_id": scan_id}
        
        if severity_filter:
            query["severity"] = severity_filter.lower()
            
        # Severity priority for sorting
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        vulns = list(self.vulnerabilities.find(query))
        
        for vuln in vulns:
            vuln["_id"] = str(vuln["_id"])
            
        # Sort by severity priority
        vulns.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))
        
        return vulns

    def get_vulnerabilities_by_template(
        self, 
        scan_id: str, 
        template_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities matching a specific template ID.
        
        Args:
            scan_id: The scan ID.
            template_id: The Nuclei template ID.
            
        Returns:
            List of vulnerability documents.
        """
        vulns = list(self.vulnerabilities.find({
            "scan_id": scan_id,
            "template_id": template_id
        }))
        
        for vuln in vulns:
            vuln["_id"] = str(vuln["_id"])
            
        return vulns

    def update_vulnerability_status(
        self, 
        vuln_id: str, 
        status: str, 
        note: Optional[str] = None
    ) -> bool:
        """
        Update vulnerability status.
        
        Args:
            vuln_id: The vulnerability ID.
            status: New status (open, in_progress, resolved, false_positive).
            note: Optional note to add.
            
        Returns:
            True if update was successful.
        """
        update_ops = {"$set": {"status": status}}
        
        if note:
            note_entry = {
                "timestamp": datetime.utcnow(),
                "content": note
            }
            update_ops["$push"] = {"notes": note_entry}
            
        try:
            result = self.vulnerabilities.update_one(
                {"_id": ObjectId(vuln_id)},
                update_ops
            )
            return result.modified_count > 0
        except Exception:
            return False

    # ==================== UTILITY METHODS ====================

    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and all related data.
        
        Args:
            scan_id: The scan ID to delete.
            
        Returns:
            True if deletion was successful.
        """
        try:
            # Delete vulnerabilities first
            self.vulnerabilities.delete_many({"scan_id": scan_id})
            
            # Delete assets
            self.assets.delete_many({"scan_id": scan_id})
            
            # Delete scan
            result = self.scans.delete_one({"_id": ObjectId(scan_id)})
            
            return result.deleted_count > 0
        except Exception as e:
            print(f"[!] Error deleting scan: {e}")
            return False

    def get_scan_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a comprehensive summary of a scan for dashboard display.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            Summary dictionary with all relevant data.
        """
        scan = self.get_scan(scan_id)
        
        if not scan:
            return None
        
        # Refresh statistics before returning
        self.update_scan_statistics(scan_id)
        scan = self.get_scan(scan_id)
            
        assets = self.get_assets_by_scan(scan_id)
        vulnerabilities = self.get_vulnerabilities_by_scan(scan_id)
        
        # Calculate critical risks (critical + high)
        stats = scan.get("statistics", {})
        critical_risks = stats.get("critical_count", 0) + stats.get("high_count", 0)
        
        return {
            "scan": scan,
            "assets": assets,
            "vulnerabilities": vulnerabilities,
            "statistics": stats,
            "critical_risks": critical_risks
        }

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get minimal scan status for polling.
        
        Args:
            scan_id: The scan ID.
            
        Returns:
            Status dictionary with current phase and progress.
        """
        scan = self.get_scan(scan_id)
        
        if not scan:
            return None
            
        return {
            "status": scan.get("status"),
            "current_phase": scan.get("current_phase"),
            "progress_percent": scan.get("progress_percent", 0),
            "phases_completed": scan.get("phases_completed", {}),
            "statistics": scan.get("statistics", {})
        }


# ==================== SINGLETON INSTANCE ====================

_db_instance: Optional[AresDB] = None


def get_db() -> AresDB:
    """
    Get the singleton database instance.
    Creates a new instance if one doesn't exist.
    
    Returns:
        AresDB instance.
    """
    global _db_instance
    
    if _db_instance is None:
        _db_instance = AresDB()
        
    return _db_instance


def init_db(connection_string: Optional[str] = None) -> AresDB:
    """
    Initialize the database with an optional custom connection string.
    
    Args:
        connection_string: MongoDB URI.
        
    Returns:
        AresDB instance.
    """
    global _db_instance
    
    _db_instance = AresDB(connection_string)
    return _db_instance


def close_db() -> None:
    """
    Close the database connection and reset the singleton.
    """
    global _db_instance
    
    if _db_instance is not None:
        _db_instance.close()
        _db_instance = None