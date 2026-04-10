"""
API Key Manager
===============
Manages API keys with:
  - Secure storage (encrypted in MongoDB)
  - Runtime configuration updates (no restart needed)
  - Key validation/testing
  - Fallback to environment variables
"""

import os
from typing import Dict, Optional, Any
from datetime import datetime


# In-memory cache of decrypted keys (refreshed on updates)
_key_cache = {}




class APIKeyManager:
    """Manages API keys with secure storage and runtime updates."""
    
    # Supported API key types and their metadata
    KEY_TYPES = {
        "HUNTER_API_KEY": {
            "name": "Hunter.io API",
            "description": "Email discovery and verification",
            "test_url": "https://api.hunter.io/v2/account",
            "features": ["Email harvesting", "Email pattern detection"],
            "docs": "https://hunter.io/api-documentation"
        },
        "INTELX_API_KEY": {
            "name": "IntelX API",
            "description": "Email search via Phonebook.cz",
            "test_url": None,  # Custom test
            "features": ["Email discovery", "Breach checking", "Paste monitoring"],
            "docs": "https://intelx.io/account?tab=developer"
        },
        "LEAKCHECK_API_KEY": {
            "name": "LeakCheck API",
            "description": "Email breach checking",
            "test_url": "https://leakcheck.io/api/public",
            "features": ["Breach verification", "Password leak detection"],
            "docs": "https://leakcheck.io/api"
        },
        "SHODAN_API_KEY": {
            "name": "Shodan API",
            "description": "Internet-connected device search",
            "test_url": "https://api.shodan.io/account/profile",
            "features": ["Port discovery", "Service fingerprinting", "CVE detection"],
            "docs": "https://developer.shodan.io/api"
        },
        "CENSYS_PAT": {
            "name": "Censys Personal Access Token",
            "description": "Internet asset search and discovery",
            "test_url": "https://search.censys.io/api/v2/account",
            "features": ["Certificate monitoring", "Host discovery", "Service detection"],
            "docs": "https://search.censys.io/account/api"
        }
    }
    
    @staticmethod
    def get_key(key_name: str) -> Optional[str]:
        """
        Get API key value (decrypted).
        
        Priority:
          1. In-memory cache (if recently loaded)
          2. Database (encrypted)
          3. Environment variable (fallback)
        
        Args:
            key_name: Key identifier (e.g., "HUNTER_API_KEY")
        
        Returns:
            Decrypted API key or None
        """
        # Check cache first
        if key_name in _key_cache:
            return _key_cache[key_name]
        
        try:
            # Load from database (lazy import)
            from database.connection import get_db
            from utils.encryption import decrypt_value
            
            db = get_db()
            key_doc = db.api_keys.find_one({"key_name": key_name})
            
            if key_doc and key_doc.get("encrypted_value"):
                decrypted = decrypt_value(key_doc["encrypted_value"])
                _key_cache[key_name] = decrypted
                return decrypted
        except Exception:
            pass  # Fall through to env var
        
        # Fallback to environment variable
        env_value = os.getenv(key_name, "")
        if env_value:
            return env_value
        
        return None
    
    @staticmethod
    def set_key(key_name: str, key_value: str, user: str = "admin") -> bool:
        """
        Save API key (encrypted) to database.
        
        Args:
            key_name: Key identifier
            key_value: Plaintext API key
            user: Username who set the key
        
        Returns:
            True if saved successfully
        """
        if key_name not in APIKeyManager.KEY_TYPES:
            return False
        
        try:
            from database.connection import get_db
            from utils.encryption import encrypt_value
            from utils.logger import logger
            
            db = get_db()
            encrypted = encrypt_value(key_value)
            
            db.api_keys.update_one(
                {"key_name": key_name},
                {
                    "$set": {
                        "key_name": key_name,
                        "encrypted_value": encrypted,
                        "updated_by": user,
                        "updated_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            # Update cache
            _key_cache[key_name] = key_value
            
            logger.info(f"[API_KEYS] {key_name} updated by {user}")
            return True
        
        except Exception as e:
            try:
                from utils.logger import logger
                logger.error(f"[API_KEYS] Error saving {key_name}: {e}")
            except Exception:
                pass
            return False
    
    @staticmethod
    def delete_key(key_name: str) -> bool:
        """Remove API key from database."""
        try:
            from database.connection import get_db
            from utils.logger import logger
            
            db = get_db()
            db.api_keys.delete_one({"key_name": key_name})
            
            # Remove from cache
            if key_name in _key_cache:
                del _key_cache[key_name]
            
            logger.info(f"[API_KEYS] {key_name} deleted")
            return True
        
        except Exception as e:
            try:
                from utils.logger import logger
                logger.error(f"[API_KEYS] Error deleting {key_name}: {e}")
            except Exception:
                pass
            return False
    
    @staticmethod
    def get_all_keys_status() -> Dict[str, Any]:
        """
        Get status of all supported API keys.
        
        Returns:
            Dict with key status, masked values, features
        """
        from utils.encryption import mask_api_key
        
        status = {}
        
        for key_name, metadata in APIKeyManager.KEY_TYPES.items():
            key_value = APIKeyManager.get_key(key_name)
            
            status[key_name] = {
                "name": metadata["name"],
                "description": metadata["description"],
                "configured": bool(key_value),
                "masked_value": mask_api_key(key_value) if key_value else None,
                "source": "database" if key_name in _key_cache else "environment" if key_value else "none",
                "features": metadata["features"],
                "docs": metadata["docs"]
            }
        
        return status
    
    @staticmethod
    def test_key(key_name: str, key_value: str = None) -> Dict[str, Any]:
        """
        Test if an API key is valid.
        
        Args:
            key_name: Key identifier
            key_value: Optional key to test (defaults to stored key)
        
        Returns:
            Dict with success status and details
        """
        import requests
        
        if not key_value:
            key_value = APIKeyManager.get_key(key_name)
        
        if not key_value:
            return {
                "success": False,
                "error": "No API key configured"
            }
        
        metadata = APIKeyManager.KEY_TYPES.get(key_name)
        if not metadata:
            return {
                "success": False,
                "error": "Unknown key type"
            }
        
        # Custom test logic per API
        try:
            if key_name == "HUNTER_API_KEY":
                resp = requests.get(
                    "https://api.hunter.io/v2/account",
                    params={"api_key": key_value},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {
                        "success": True,
                        "message": "API key valid",
                        "details": {
                            "requests_used": data.get("requests", {}).get("used", 0),
                            "requests_available": data.get("requests", {}).get("available", 0)
                        }
                    }
                elif resp.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                else:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
            
            elif key_name == "INTELX_API_KEY":
                # Test with a simple search
                resp = requests.post(
                    "https://free.intelx.io/phonebook/search",
                    json={
                        "term": "test@example.com",
                        "maxresults": 1,
                        "media": 0,
                        "target": 2,
                        "timeout": 5
                    },
                    headers={"x-key": key_value},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    return {"success": True, "message": "API key valid"}
                elif resp.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                elif resp.status_code == 402:
                    return {"success": True, "message": "API key valid (quota exceeded but key works)"}
                else:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
            
            elif key_name == "LEAKCHECK_API_KEY":
                resp = requests.get(
                    "https://leakcheck.io/api/public",
                    params={"check": "test@example.com"},
                    headers={"X-API-Key": key_value},
                    timeout=10
                )
                
                if resp.status_code == 200 or resp.status_code == 404:
                    return {"success": True, "message": "API key valid"}
                elif resp.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                else:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
            
            elif key_name == "SHODAN_API_KEY":
                resp = requests.get(
                    f"https://api.shodan.io/account/profile?key={key_value}",
                    timeout=10
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "success": True,
                        "message": "API key valid",
                        "details": {
                            "credits": data.get("credits", 0)
                        }
                    }
                elif resp.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                else:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
            
            elif key_name == "CENSYS_PAT":
                # Censys uses Basic Auth with PAT as password
                resp = requests.get(
                    "https://search.censys.io/api/v2/account",
                    auth=(key_value.split(":")[0], key_value.split(":")[1] if ":" in key_value else ""),
                    timeout=10
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "success": True,
                        "message": "API key valid",
                        "details": {
                            "email": data.get("email", "")
                        }
                    }
                elif resp.status_code == 401:
                    return {"success": False, "error": "Invalid API key"}
                else:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
            
            else:
                # Generic test for unknown types
                return {
                    "success": True,
                    "message": "Key saved (validation not implemented for this API)"
                }
        
        except requests.Timeout:
            return {"success": False, "error": "API timeout"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}


