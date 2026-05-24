"""
MITRE ATT&CK Mapper — Campaign Context Intelligence
===================================================

Maps vulnerability findings to MITRE ATT&CK Tactics and Techniques
using the local knowledge base.
"""

from typing import Dict, Any, List, Optional
from core.threat_researcher import ThreatResearcher

class MitreMapper:
    """
    Utility to map vulnerabilities to MITRE ATT&CK context.
    """

    def map_to_mitre(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map a vulnerability to its corresponding MITRE ATT&CK context.

        Args:
            vuln: Vulnerability dictionary from scan/database

        Returns:
            MITRE context object with tactic, technique, and description.
        """
        # Attempt to get intelligence from the Threat Researcher
        research = ThreatResearcher.research(vuln)

        mitre_data = {
            "tactic": "Unknown",
            "tactic_id": "TA0043", # Recce fallback
            "tactic_name": "Reconnaissance",
            "technique": "N/A",
            "techniques": [],
            "description": "General vulnerability that may be leveraged in multiple attack phases.",
            "icon": "🛡️",
            "color": "#6c757d",
            "confidence": 0.3
        }

        if research and research.get("mitre_attack"):
            attack = research["mitre_attack"]
            mitre_data["tactic"] = attack.get("tactic", "Unknown")
            mitre_data["tactic_name"] = attack.get("tactic", "Unknown")

            # Map common tactics to IDs and icons
            tactic_map = {
                "Initial Access": {"id": "TA0001", "icon": "🔓", "color": "#dc3545"},
                "Execution": {"id": "TA0002", "icon": "⚙️", "color": "#fd7e14"},
                "Persistence": {"id": "TA0003", "icon": "📌", "color": "#ffc107"},
                "Privilege Escalation": {"id": "TA0004", "icon": "📈", "color": "#0d6efd"},
                "Defense Evasion": {"id": "TA0005", "icon": "👻", "color": "#6610f2"},
                "Credential Access": {"id": "TA0006", "icon": "🔑", "color": "#20c997"},
                "Discovery": {"id": "TA0007", "icon": "🔍", "color": "#198754"},
                "Lateral Movement": {"id": "TA0008", "icon": "🚶", "color": "#6f42c1"},
                "Collection": {"id": "TA0009", "icon": "📥", "color": "#d63384"},
                "Command and Control": {"id": "TA0011", "icon": "📡", "color": "#0dcaf0"},
                "Exfiltration": {"id": "TA0010", "icon": "📤", "color": "#000000"},
                "Impact": {"id": "TA0040", "icon": "💥", "color": "#b02a37"},
                "Resource Development": {"id": "TA0042", "icon": "🏗️", "color": "#6c757d"}
            }

            t_info = tactic_map.get(mitre_data["tactic"], {})
            mitre_data["tactic_id"] = t_info.get("id", "TA0000")
            mitre_data["icon"] = t_info.get("icon", "🛡️")
            mitre_data["color"] = t_info.get("color", "#6c757d")

            mitre_data["technique"] = attack.get("technique", "N/A")
            mitre_data["techniques"] = [attack.get("technique")] if attack.get("technique") else []
            mitre_data["description"] = attack.get("description", mitre_data["description"])
            mitre_data["confidence"] = 0.9 if attack.get("technique") else 0.5

        return mitre_data

# Singleton instance for import
mitre_mapper = MitreMapper()
