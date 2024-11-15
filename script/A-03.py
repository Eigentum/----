import requests
import json
import os
from urllib.parse import urlencode

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

base_url = config.get("base_url", "").strip()
login_path = config.get("login_path", "").strip()
db_path = config.get("db_path", "").strip()
admin_id = config.get("admin_id", "").strip()
cmd_injection_payload = config.get("command_injection_payloads",[])

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")
        
def check_sql_injection(result_filename):
    vulnerable_params = ["'", " OR 1=1--", " OR 1=1 #", " OR '1'='1' #" "' OR '1'='1"]

    for param in vulnerable_params:
        url = f"{base_url}{login_path}?username=admin&password={param}"
        try:
            response = requests.get(url)
            if "Welcome" in response.text or response.status_code == 200:
                append_results_to_file(result_filename, f"[CAUTION] Potential SQL Injection detected with payload: {param}")
            else:
                append_results_to_file(result_filename, f"[SAFE] No SQL Injection detected for payload: {param}")
        except requests.RequestException as e:
            append_results_to_file(result_filename, f"[ERROR] Error occurred while testing SQL Injection: {e}")

def check_nosql_injection(result_filename):
    nosql_payload = {"$ne": None}
    payload_str = urlencode(nosql_payload)
    url = f"{base_url}{login_path}?username={admin_id}&password={payload_str}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            append_results_to_file(result_filename, "[CAUTION] Potential NoSQL Injection detected")
        else:
            append_results_to_file(result_filename, "[SAFE] No NoSQL Injection detected.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Error occurred while testing NoSQL Injection: {e}")

def check_command_injection(result_filename):
    if not cmd_injection_payload:
        append_results_to_file(result_filename, "[INFO] Skipping Command Injection check (no payloads provided).\n")
        return
    
    for payload in cmd_injection_payload:
        url = f"{base_url}{login_path}?username={admin_id}&password=admin{payload}"
        try:
            response = requests.get(url)
            if "bin" in response.text or "root" in response.text:
                append_results_to_file(result_filename, f"[CAUTION] Potential Command Injection detected with payload: {payload}")
            else:
                append_results_to_file(result_filename, f"[SAFE] No Command Injection detected for payload: {payload}")
        except requests.RequestException as e:
            append_results_to_file(result_filename, f"[ERROR] Error occurred while testing Command Injection: {e}")

def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=== A-03 Injection Diagnostics ===\n")
    
    check_sql_injection(result_filename)
    check_nosql_injection(result_filename)
    check_command_injection(result_filename)

