import os
import shutil
import sys

print("--- FINAL SYSTEM CHECK ---\n")

# 1. Check Python Libraries
try:
    import flask
    import pymongo
    import pdfkit
    print("[OK] Python Libraries are installed.")
except ImportError as e:
    print(f"[X] MISSING LIBRARY: {e}")

# 2. Check Tools Folder
tools = ["subfinder.exe", "naabu.exe", "httpx.exe", "nuclei.exe"]
tools_dir = os.path.join(os.getcwd(), "tools")
missing_tools = []

if os.path.exists(tools_dir):
    for t in tools:
        if not os.path.exists(os.path.join(tools_dir, t)):
            missing_tools.append(t)
    
    if not missing_tools:
        print("[OK] Scanner Tools (Subfinder/Nuclei/etc) are found.")
    else:
        print(f"[X] MISSING TOOLS: {missing_tools}")
else:
    print("[X] 'tools' folder is missing!")

# 3. Check MongoDB
try:
    client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
    client.server_info() # Trigger connection
    print("[OK] MongoDB is running and accessible.")
except:
    print("[X] MongoDB is NOT running. Please install it or start the service.")

# 4. Check PDF Engine
if shutil.which("wkhtmltopdf"):
    print("[OK] wkhtmltopdf (PDF Engine) is in System PATH.")
else:
    print("[!] wkhtmltopdf is installed but not in PATH. (We will handle this in code).")

print("\n------------------------------")