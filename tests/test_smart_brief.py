"""
Tests for Smart Brief Intelligence Engine
"""

import pytest
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cve_enricher import smart_brief_engine

def test_get_simple_description_curated():
    """Test curated description retrieval"""
    vuln = {
        "template_id": "aws-object-listing",
        "name": "AWS S3 Bucket Listing",
        "severity": "high"
    }

    result = smart_brief_engine.get_simple_description(vuln)

    assert result["confidence"] == 1.0
    assert result["source"] == "curated"
    assert "S3 bucket" in result["brief"]
    assert "business_risk" in result


def test_get_simple_description_pattern():
    """Test pattern-based fallback"""
    vuln = {
        "template_id": "custom-xss-check",
        "name": "XSS Vulnerability",
        "severity": "medium"
    }

    result = smart_brief_engine.get_simple_description(vuln)

    assert result["confidence"] == 0.7
    assert result["source"] == "pattern"
    assert "browser" in result["brief"].lower() or "script" in result["brief"].lower()


def test_get_community_reference():
    """Test community reference retrieval"""
    vuln = {"template_id": "sql-injection"}

    ref = smart_brief_engine.get_community_reference(vuln)

    assert ref is not None
    assert "url" in ref
    assert "title" in ref
    assert ref["trustworthiness"] in ["official", "authoritative", "high", "medium"]


def test_generate_smart_brief():
    """Test complete Smart Brief generation"""
    vuln = {
        "template_id": "default-login",
        "name": "Default Credentials",
        "severity": "critical",
        "host": "admin.example.com"
    }

    brief = smart_brief_engine.generate_smart_brief(vuln)

    assert "description" in brief
    assert "reference" in brief
    assert "campaign_context" in brief

    # Check description
    assert brief["description"]["brief"]
    assert brief["description"]["business_risk"]
    assert brief["description"]["action"]

    # Check reference
    assert brief["reference"]["url"]

    # Check MITRE context
    assert brief["campaign_context"]["tactic"]
