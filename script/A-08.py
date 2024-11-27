import json
import os
import requests
import subprocess
import platform

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

update_server_url = config.get("update_server_url", "").strip()
cicd_server = config.get("cicd_server", "").strip()
tls_required = config.get("tls_required", True)
external_libraries = config.get("external_libraries", [])
env_files = config.get("env_files", [])

def append_results_to_file(result_filename, content):
    if result_filename:
        with open(result_filename, "a") as result_file:
            result_file.write(content + "\n")
    else:
        print("[ERROR] Result filename is not defined.")

def is_windows():
    return platform.system() == "Windows"

def check_update_server_tls(result_filename):
    append_results_to_file(result_filename, "\n===== Check if the update server provides a secure connection. =====")
    if not update_server_url:
        append_results_to_file(result_filename, "[INFO] Update server URL not specified. Skipping update server check.")
        return

    try:
        response = requests.get(update_server_url, timeout=10)
        if response.url.startswith("https://") and response.status_code == 200:
            append_results_to_file(result_filename, f"[SAFE] Update server {update_server_url} uses HTTPS and is reachable.")
        else:
            append_results_to_file(result_filename, f"[CAUTION] Update server {update_server_url} does not use HTTPS or failed to respond.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Could not verify update server: {e}")

def check_external_libraries(result_filename):
    append_results_to_file(result_filename, "\n===== Compare that the external library matches the expected version and integrity hash. =====")
    if not external_libraries:
        append_results_to_file(result_filename, "[INFO] No external libraries specified. Skipping library integrity check.")
        return

    for lib in external_libraries:
        name = lib.get("name")
        version = lib.get("version")
        integrity_hash = lib.get("integrity_hash")

        if not (name and version and integrity_hash):
            append_results_to_file(result_filename, f"[INFO] Missing data for {name or 'unknown library'}. Skipping integrity check.")
            continue

        try:
            output = subprocess.check_output(['pip', 'show', name], text=True)
            installed_version = ""
            for line in output.splitlines():
                if line.startswith("Version:"):
                    installed_version = line.split("Version: ")[1].strip()
                    break

            if installed_version == version:
                append_results_to_file(result_filename, f"[SAFE] Library {name} version {version} is installed as expected.")
            else:
                append_results_to_file(result_filename, f"[CAUTION] Library {name} version mismatch. Expected {version}, found {installed_version}")
        except subprocess.CalledProcessError:
            append_results_to_file(result_filename, f"[ERROR] Library {name} not installed.")
            continue

"""   Hash Check...  
        try:
            hash_result = subprocess.check_output(['pip', 'hash', name], text=True).splitlines()[-1]
            if integrity_hash in hash_result:
                append_results_to_file(result_filename, f"[SAFE] Integrity check passed for library {name}.")
            else:
                append_results_to_file(result_filename, f"[CAUTION] Integrity check failed for library {name}. Expected hash: {integrity_hash}")
        except subprocess.CalledProcessError:
            append_results_to_file(result_filename, f"[ERROR] Could not verify integrity of library {name}.")
 """

def check_cicd_security(result_filename):
    append_results_to_file(result_filename, "\n===== Check if the CI/CD server provides a secure connection using HTTPS ====== ")
    if not cicd_server:
        append_results_to_file(result_filename, "[INFO] No CI/CD server specified. Skipping CI/CD security check.")
        return

    try:
        response = requests.get(cicd_server, timeout=10)
        if response.status_code == 200 and (response.url.startswith("https://") or not tls_required):
            append_results_to_file(result_filename, f"[SAFE] CI/CD server {cicd_server} is secure.")
        else:
            append_results_to_file(result_filename, f"[CAUTION] CI/CD server {cicd_server} might be insecure. Check HTTPS or server settings.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Could not verify CI/CD server security: {e}")

def check_env_files(result_filename):
    append_results_to_file(result_filename, "\n===== Check the specified .env files =====")
    if not env_files:
        append_results_to_file(result_filename, "[INFO] No environment files specified. Skipping environment file check.")
        return

    for file_path in env_files:
        if os.path.exists(file_path):
            append_results_to_file(result_filename, f"[SAFE] Environment file {file_path} exists.")
            with open(file_path, 'r') as f:
                content = f.read()
                if "SECRET_KEY" in content or "PASSWORD" in content:
                    append_results_to_file(result_filename, f"[CAUTION] Sensitive information found in {file_path}. Consider encryption.")
                else:
                    append_results_to_file(result_filename, f"[SAFE] No sensitive information found in {file_path}")
        else:
            append_results_to_file(result_filename, f"[ERROR] Environment file {file_path} not found.")

def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=============================================================")
    append_results_to_file(result_filename, "=== A-08 Software and Data Integrity Failures Diagnostics ===")
    append_results_to_file(result_filename, "=============================================================")

    check_update_server_tls(result_filename)
    check_external_libraries(result_filename)
    check_cicd_security(result_filename)
    check_env_files(result_filename)

    append_results_to_file(result_filename, "\n=== End of A-08 Diagnostics ===\n")