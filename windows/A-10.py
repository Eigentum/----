import json
import os
import platform
import requests

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

allowed_domains =config.get("allowed_domains", [])
metadata_blocked = config.get("metadata_bloacked", True)
allowed_method = config.get("allowed_methods", ["GET", "POST"])
            
