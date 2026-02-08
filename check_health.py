#!/usr/bin/env python3
"""
AEGIS System Health Check (check_health.py)
============================================
A standalone diagnostic script to verify the AEGIS environment is correctly
configured. Run this when scans are failing to identify the root cause.

Usage:
    python check_health.py

Author: AEGIS Team
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


# =============================================================================
# CONFIGURATION (Must match scanner.py exactly)
# =============================================================================
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR: str = os.path.join(BASE_DIR, "tools")

# Handle Windows .exe extension
IS_WINDOWS: bool = platform.system() == "Windows"
EXT: str = ".exe" if IS_WINDOWS else ""

# Tool binaries (same paths as scanner.py)
TOOLS: dict = {
    "subfinder": os.path.join(TOOLS_DIR, f"subfinder{EXT}"),
    "naabu": os.path.join(TOOLS_DIR, f"naabu{EXT}"),
    "httpx": os.path.join(TOOLS_DIR, f"httpx{EXT}"),
    "nuclei": os.path.join(TOOLS_DIR, f"nuclei{EXT}"),
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def print_header(title: str) -> None:
    """Print a section header."""
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print('=' * 50)


def check_ok(message: str) -> None:
    """Print a success message."""
    print(f"[+] OK: {message}")


def check_fail(message: str) -> None:
    """Print a failure message."""
    print(f"[-] FAIL: {message}")


def check_warn(message: str) -> None:
    """Print a warning message."""
    print(f"[!] WARN: {message}")


# =============================================================================
# CHECK FUNCTIONS
# =============================================================================

def check_python_dependencies() -> int:
    """
    Check if required Python packages are importable.
    Returns number of failures.
    """
    print_header("Python Dependencies")
    
    required_packages = ["flask", "pymongo", "requests", "dotenv"]
    failures = 0
    
    for package in required_packages:
        try:
            if package == "dotenv":
                __import__("dotenv")
            else:
                __import__(package)
            check_ok(f"{package} is installed")
        except ImportError:
            check_fail(f"{package} is MISSING - run: pip install {package}")
            failures += 1
    
    return failures


def check_mongodb() -> int:
    """
    Check if MongoDB is running and accessible.
    Returns 1 if failed, 0 if success.
    """
    print_header("MongoDB Connection")
    
    try:
        from pymongo import MongoClient
        from pymongo.errors import ServerSelectionTimeoutError
        
        # Attempt connection with short timeout
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
        # Force a connection attempt
        client.admin.command('ping')
        
        check_ok("MongoDB is running and accessible at localhost:27017")
        client.close()
        return 0
        
    except ImportError:
        check_fail("pymongo not installed - cannot check MongoDB")
        return 1
    except Exception as e:
        check_fail(f"MongoDB connection refused - {e}")
        check_warn("Make sure MongoDB is running: mongod --dbpath <path>")
        return 1


def check_binary_tools() -> int:
    """
    Check if scanner binaries exist and are executable.
    Returns number of failures.
    """
    print_header("Scanner Binaries (CRITICAL)")
    
    print(f"[*] Tools directory: {TOOLS_DIR}")
    print(f"[*] Platform: {platform.system()} (extension: '{EXT}')")
    print()
    
    failures = 0
    
    for tool_name, tool_path in TOOLS.items():
        # Step 1: Check if file exists
        if not os.path.exists(tool_path):
            check_fail(f"{tool_name}: File not found at {tool_path}")
            failures += 1
            continue
        
        check_ok(f"{tool_name}: Binary exists at {tool_path}")
        
        # Step 2: Check if executable (try running with -version)
        try:
            result = subprocess.run(
                [tool_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract first line of version output
                version_line = result.stdout.strip().split('\n')[0] if result.stdout else "OK"
                check_ok(f"{tool_name}: Executable - {version_line}")
            else:
                check_warn(f"{tool_name}: Ran but returned exit code {result.returncode}")
                
        except PermissionError:
            check_fail(f"{tool_name}: Permission denied - cannot execute")
            failures += 1
        except subprocess.TimeoutExpired:
            check_warn(f"{tool_name}: Execution timed out (10s)")
        except Exception as e:
            check_fail(f"{tool_name}: Execution error - {e}")
            failures += 1
    
    return failures


def check_nuclei_templates() -> int:
    """
    Check if Nuclei templates are installed.
    Returns 1 if warning, 0 if found.
    """
    print_header("Nuclei Templates")
    
    # Common template locations
    home = Path.home()
    possible_paths = [
        home / "nuclei-templates",
        home / ".nuclei-templates",
        Path(os.environ.get("NUCLEI_TEMPLATES", "")) if os.environ.get("NUCLEI_TEMPLATES") else None,
    ]
    
    for path in possible_paths:
        if path and path.exists() and path.is_dir():
            # Count templates
            template_count = len(list(path.rglob("*.yaml")))
            check_ok(f"Nuclei templates found at: {path}")
            check_ok(f"Template count: ~{template_count} YAML files")
            return 0
    
    check_warn("Nuclei templates directory not found in common locations")
    check_warn("Run: nuclei -update-templates")
    return 1


def check_wkhtmltopdf() -> int:
    """
    Check if wkhtmltopdf is available for PDF generation.
    Returns 1 if failed, 0 if success.
    """
    print_header("PDF Engine (wkhtmltopdf)")
    
    try:
        result = subprocess.run(
            ["wkhtmltopdf", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            version_line = result.stdout.strip().split('\n')[0] if result.stdout else "OK"
            check_ok(f"wkhtmltopdf is available - {version_line}")
            return 0
        else:
            check_fail("wkhtmltopdf returned non-zero exit code")
            return 1
            
    except FileNotFoundError:
        check_fail("wkhtmltopdf not found in PATH")
        check_warn("Download from: https://wkhtmltopdf.org/downloads.html")
        return 1
    except Exception as e:
        check_fail(f"Error checking wkhtmltopdf: {e}")
        return 1


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main() -> None:
    """Run all health checks and print summary."""
    print("\n" + "=" * 50)
    print("       AEGIS SYSTEM HEALTH CHECK")
    print("=" * 50)
    print(f"[*] Base Directory: {BASE_DIR}")
    print(f"[*] Python Version: {sys.version.split()[0]}")
    
    total_failures = 0
    total_warnings = 0
    
    # Run all checks
    total_failures += check_python_dependencies()
    total_failures += check_mongodb()
    total_failures += check_binary_tools()
    total_warnings += check_nuclei_templates()
    total_failures += check_wkhtmltopdf()
    
    # Print summary
    print_header("SUMMARY")
    
    if total_failures == 0:
        print("[+] All critical checks PASSED!")
        if total_warnings > 0:
            print(f"[!] {total_warnings} warning(s) detected - review above")
        print("\n[*] AEGIS is ready to run scans.")
    else:
        print(f"[-] {total_failures} critical check(s) FAILED")
        print("[!] Fix the issues above before running scans.")
        sys.exit(1)


if __name__ == "__main__":
    main()
