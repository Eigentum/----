import requests
import json
import os
import platform

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

base_url = config.get("base_rul", "").strip()
default_admin_account = config.get("default_admin_account", "")
default_admin_password = config.get("default_admin_password", "")

os_name = platform.system().lower()
if os_name not in ["linux", "windows"]:
    raise ValueError(f"Unsupported OS: {os_name}")

important_dirs = config.get(f"important_dirs_{os_name}", [])
sensitive_dirs = config.get(f"sensitive_dirs_{os_name}", [])


def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def check_unnecessary_features(result_filename):
    append_results_to_file(result_filename, "\n===== Check for activation of unnecessary HTTP methods. =====")
    try:
        response = requests.get(base_url)
        if "TRACE" in response.headers.get("Allow", ""):
            append_results_to_file(result_filename, "[CAUTION] TRACE method is enabled.")
        else:
            append_results_to_file(result_filename, "[SAFE] TRACE method is disabled.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Could not check unnecessary features: {e}")

def check_default_account(result_filename):
    append_results_to_file(result_filename, "\n===== Check default account usage =====")
    
    if os_name == "Linux":
        command = "cat /etc/passwd"
    elif os_name == "Windows":
        command = "net user"
    else:
        append_results_to_file(result_filename, f"[INFO] OS {os_name} is not supported for default account checks.\n")
        return

    try:
        result = os.popen(command).read()
        if default_admin_account in result or default_admin_password in result:
            append_results_to_file(
                result_filename,
                f"[CAUTION] Default admin account or password detected on {os_name} system.\n"
            )
        else:
            append_results_to_file(result_filename, f"[SAFE] No default admin account or password detected on {os_name} system.\n")
    except Exception as e:
        append_results_to_file(result_filename, f"[ERROR] Could not check default accounts: {e}")

def check_security_headers(result_filename):
    append_results_to_file(result_filename, "\n===== Check if 'Security Header' is set in HTTP Response Header. =====")
    try:
        response = requests.get(base_url)
        headers = response.headers

        if "X-Content-Type-Options" in headers:
            append_results_to_file(result_filename, "[SAFE] X-Content-Type-Options header is set.")
        else:
            append_results_to_file(result_filename, "[CAUTION] X-Content-Type-Options header is missing.")

        if "X-Frame-Options" in headers:
            append_results_to_file(result_filename, "[SAFE] X-Frame-Options header is set.")
        else:
            append_results_to_file(result_filename, "[CAUTION] X-Frame-Options header is missing.")

        if "Strict-Transport-Security" in headers:
            append_results_to_file(result_filename, "[SAFE] Strict-Transport-Security header is set.")
        else:
            append_results_to_file(result_filename, "[CAUTION] Strict-Trasport-Security header is missing.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Could not check security headers: {e}")

def check_latest_patch(result_filename):
    append_results_to_file(result_filename, "[Advice] Please ensure that all software and dependencies are up-to-date.")

def check_directory_permissions(result_filename):
    append_results_to_file(result_filename, "\n===== Check 'write' permissions on critical directories. =====")
    for dir_path in important_dirs:
        try:
            if os.access(dir_path, os.W_OK):
                append_results_to_file(result_filename, f"[CAUTION] Write permission is enabled for {dir_path}.")
            else:
                append_results_to_file(result_filename, f"[SAFE] Write permission is disabled for {dir_path}.")
        except Exception as e:
            append_results_to_file(result_filename, f"[ERROR] Could not check permissions for {dir_path}: {e}")

def check_directory_indexing(result_filename):
    append_results_to_file(result_filename, "\n===== Check if sensitive directories are publicly indexed. =====")
    for dir_path in sensitive_dirs:
        url = f"{base_url}{dir_path.replace(os.sep, '/')}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                if "Index of" in response.text or "Directory listing" in response.text:
                    append_results_to_file(result_filename, f"[CAUTION] Directory {dir_path} is accessible publicly: {url}")
                else:
                    append_results_to_file(result_filename, f"[SAFE] Directory {dir_path} is accessible, but no indexing detected.")
            elif response.status_code == 403:
                append_results_to_file(result_filename, f"[SAFE] Access to directory {dir_path} is forbidden")
            else:
                append_results_to_file(result_filename, f"[INFO] Directory {dir_path}is not found")
        except requests.RequestException as e:
            append_results_to_file(result_filename, f"[ERROR] Could not check directory {dir_path}: {e}")

def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n==================================================")
    append_results_to_file(result_filename, "=== A-05 Security Misconfiguration Diagnostics ===")
    append_results_to_file(result_filename, "==================================================")
    check_unnecessary_features(result_filename)
    check_default_account(result_filename)
    check_security_headers(result_filename)
    check_latest_patch(result_filename)
    check_directory_permissions(result_filename)
    check_directory_indexing(result_filename)

    append_results_to_file(result_filename, "\n=== End of A-05 Diagnostics ===\n")