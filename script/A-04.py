import requests
import json
import os

# config.json 파일 로드
config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

base_url = config.get("base_url", "").strip()
api_paths = config.get("api_paths", ["/api/debug"])
requirements_path = config.get("requirements_path", "").strip()

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def validate_configurations(result_filename):
    if not base_url:
        append_results_to_file(result_filename, "[WARNING] base_url is not provided in config.json.")
    if not api_paths:
        append_results_to_file(result_filename, "[WARNING] api_paths is empty or not provided in config.json.")


def check_debug_mode(result_filename):
    try:
        response = requests.get(base_url)
        if "DEBUG" in response.text or "debug" in response.headers.get("X-Debug", "").lower():
            append_results_to_file(result_filename, "[CAUTION] Debug mode appears to be enabled.")
        else:
            append_results_to_file(result_filename, "[SAFE] Debug mode is not enabled.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Could not check debug mode: {e}")

def check_public_api_access(result_filename):
    if not api_paths or not isinstance(api_paths, list):
        append_results_to_file(result_filename, "[INFO] Skipping public API access check (no valid API paths provided).")
        return
    
    for api_path in api_paths:
        url = f"{base_url}{api_path}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                append_results_to_file(result_filename, f"[CAUTION] Public API endpoint accessible without authentication: {url}")
            else:
                append_results_to_file(result_filename, f"[SAFE] API endpoint is not accessible publicly: {url}")
        except requests.RequestException as e:
            append_results_to_file(result_filename, f"[ERROR] Error accessing API path {url}: {e}")

def check_security_requirements(result_filename):
    append_results_to_file(result_filename, "[INFO] Checking security requirements documentation...")

    if not requirements_path:
        append_results_to_file(result_filename, "[INFO] Skipping security requirements check (requirements path not provided).\n")
        return

    if os.path.exists(requirements_path):
        append_results_to_file(result_filename, "[SAFE] Security requirements documentation found.")
    else:
        append_results_to_file(result_filename, "[CAUTION] No security requirements documentation found.")

def check_default_settings(result_filename):
    append_results_to_file(result_filename, "[INFO] Checking default settings for unsafe configurations.")
    
    default_admin_account = config.get("default_admin_account", "")
    default_admin_password = config.get("default_admin_password", "")
    if default_admin_account or default_admin_password:
        append_results_to_file(result_filename, "[CAUTION] Default admin account or password detected.")
    else:
        append_results_to_file(result_filename, "[SAFE] No default admin account or password detected.")


def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=== A-04 Insecure Design Diagnostics ===\n")

    check_debug_mode(result_filename)
    check_public_api_access(result_filename)
    check_security_requirements(result_filename)
    check_default_settings(result_filename)