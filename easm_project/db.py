from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["easm_project"]
collection = db["scans"]

def save_scan_result(domain, subdomains, ports, live_urls, vulns):
    """Saves scan data to MongoDB"""
    # Create the document structure
    scan_doc = {
        "target": domain,
        "timestamp": datetime.now(),
        "stats": {
            "subdomains": len(subdomains) if subdomains else 0,
            "ports": len(ports) if ports else 0,
            "live_urls": len(live_urls) if live_urls else 0,
            "vulns": len(vulns) if vulns else 0
        },
        "data": {
            "subdomains": subdomains,
            "ports": ports,
            "live_urls": live_urls,
            "vulnerabilities": vulns
        }
    }
    
    # Insert into DB
    result = collection.insert_one(scan_doc)
    return str(result.inserted_id)

def get_all_scans():
    """Get scan history sorted by newest first"""
    return list(collection.find().sort("timestamp", -1))

def get_scan_by_id(scan_id):
    """Get a single scan result"""
    try:
        return collection.find_one({"_id": ObjectId(scan_id)})
    except:
        return None