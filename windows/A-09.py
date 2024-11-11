import json
import os
import platform
import subprocess
import requests
import time

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

log_paths = config.get("log_paths", [])
monitoring_tool_url = config.get("monitoring_tool_url", "").strip()
backup_policy_days = config.get("backup_policy_days", 180)

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def is_windows():
    return platform.system() == "Windows"

def check_log_files_exist(result_filename):
    if not log_paths:
        append_results_to_file(result_filename, "[INFO] No log paths specified. Skipping log file existence check.")
        return

    for log_path in log_paths:
        if os.path.exists(log_path):
            append_results_to_file(result_filename, f"[SAFE] Log file {log_path} exists.")
        else:
            append_results_to_file(result_filename, f"[ERROR] Log file {log_path} not found.")

def check_log_file_permissions(result_filename):
    if not log_paths:
        append_results_to_file(result_filename, "[INFO] No log paths specified. Skipping log file permission check.")
        return
    
    for log_path in log_paths:
        if os.path.exists(log_path):
            if is_windows():
                output = subprocess.check_output(['icacls', log_path], text=True)
                append_results_to_file(result_filename, f"[INFO] Permissions for {log_path}:\n{output}")
            else:
                output = subprocess.check_output(['ls', '-l', log_path], text=True)
                append_results_to_file(result_filename, f"[INFO] Permissions for {log_path}:\n{output}")
        else:
            append_results_to_file(result_filename, f"[ERROR] Log file {log_path} not found. Skipping permission check.")

def check_monitoring_tool_status(result_filename):
    if not monitoring_tool_url:
        append_results_to_file(result_filename, "[INFO] No monitoring tool URL specified. Skipping monitoring tool status check.")
        return
    
    try:
        response = requests.get(monitoring_tool_url, timeout=10)
        if response.status_code == 200:
            append_results_to_file(result_filename, f"[SAFE] Monitoring tool at {monitoring_tool_url} is reachable.")
        else:
            append_results_to_file(result_filename, f"[CAUTION] Monitoring tool at {monitoring_tool_url} returned status code {response.status_code}.")
    except requests. RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Could not reach monitoring tool at {monitoring_tool_url}: {e}")

def check_log_backup_policy(result_filename):
    if not backup_policy_days:
        append_results_to_file(result_filename, "[INFO] No backup policy specified. Skipping backup policy check.")
        return
    
    for log_path in log_paths:
        if os.path.exists(log_path):
            if is_windows():
                output = subprocess.check_output(['powershell', f'(Get-Item {log_path}).LastWriteTime'], text=True).strip()
                last_modified_time = int(time.mktime(time.strptime(output, "%m/%d/%Y %H:%M:%S")))
            else:
                last_modified_time = int(subprocess.check_output(['stat', '-c', '%Y', log_path], text=True).strip())

            current_time = int(time.time())
            age_in_days = (current_time - last_modified_time) // (60 * 60 * 24)

            if age_in_days <= backup_policy_days:
                append_results_to_file(result_filename, f"[SAFE] Log file {log_path} is backed up within the last {backup_policy_days} days.")
            else:
                append_results_to_file(result_filename, f"[CAUTION] Log file {log_path} backup is older than the allowed backup policy period {backup_policy_days} days.")
        else:
            append_results_to_file(result_filename, f"[ERROR] Log file {log_path} not found. Skipping backup check.")

def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=== A-09 Security Logging and Monitoring Failures Diagnostics ===\n")

    check_log_files_exist(result_filename)
    check_log_file_permissions(result_filename)
    check_monitoring_tool_status(result_filename)
    check_log_backup_policy(result_filename)
