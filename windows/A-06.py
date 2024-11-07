import json
import os
import requests

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

dependency_file = config.get("dependency_file", "").strip()
cve_api_url = config.get("cve_api_url", "").strip()
components = config.get("components", [])

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def check_latest_versions(result_filename):
    if not components:
        append_results_to_file(result_filename, "[INFO] No components specified in config.json. Skipping version check.")
        return
    
    append_results_to_file(result_filename, "[INFO] Checking if components are up-to date...")
    for component in components:
        name = component.get("name")
        version = component.get("version")

        if not name or not version:
            append_results_to_file(result_filename, f"[INFO] Skipping {name or 'unnamed component'} - name or version missing.")
            continue

        # Check Vulnerability through CVE API
        try: 
            response = requests.get(f"{cve_api_url}?name={name}&version={version}")
            if response.status_code == 200:
                cve_data = response.json()
                if cve_data.get("vunerable"):
                    append_results_to_file(result_filename, f"[CAUTION] {name} {version} is vulnerable: {cve_data.get('details')}")
                else:
                    append_results_to_file(result_filename, f"[SAFE] {name} {version} is up-to-date and secure.")
            else:
                append_results_to_file(result_filename, f"[ERROR] Could not check {name} - API request failed with status {response.status_code}.")
        except requests.RequestException as e:
            append_results_to_file(result_filename, f"[ERROR] Failed to check {name} for vulnerabilities: {e}")

def check_eol_components(result_filename):
    if not components:
        append_results_to_file(result_filename, "[INFO] No components specified in config.json. Skipping EOL check.")
        return
    
    append_results_to_file(result_filename, "[INFO] Checking if components are past end-of-life (EOL)...")
    for component in components:
        name = component.get("name")
        support_end_date = component.get("support_end_date")

        if not name or not support_end_date:
            append_results_to_file(result_filename, f"[INFO] Skipping {name or 'unnamed'}")