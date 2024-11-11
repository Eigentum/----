import json
import os
import platform
import requests

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

metadata_url = config.get("metadata_url", "")
allowed_domains = config.get("allowed_domains", [])
local_urls = config.get("local_urls", [])
client_offer_url = config.get("client_offer_url","").strip()
metadata_blocked = config.get("metadata_blocked", True)
allowed_methods = config.get("allowed_methods", ["GET", "POST"])

            
def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def is_windows():
    return platform.system() == "Windows"

def check_server_side_request(result_filename):
    if not client_offer_url:
        append_results_to_file(result_filename, "[INFO] Client offer URL not specified. Skipping server-side request check.")
        return

    try:
        response = requests.get(client_offer_url, timeout=5)
        if response.status_code == 200:
            append_results_to_file(result_filename, f"[CAUTION] Server-side request to {client_offer_url} succeeded. Limitation recommended.")
        else:
            append_results_to_file(result_filename, f"[SAFE] Request to {client_offer_url} was blocked.")
    except requests.RequestException:
        append_results_to_file(result_filename, "[SAFE] Server-side requests denied.")

def check_whitelist(result_filename):
    if not allowed_domains:
        append_results_to_file(result_filename, "[INFO] Allowed domains not set. Skipping whitelist check.")
        return

    if any(client_offer_url.endswith(domain) for domain in allowed_domains):
        append_results_to_file(result_filename, f"[SAFE] {client_offer_url} is within allowed domains.")
    else:
        append_results_to_file(result_filename, f"[CAUTION] {client_offer_url} is not within allowed domains.")

def check_metadata_block(result_filename):
    if not metadata_url:
        append_results_to_file(result_filename, "[INFO] Metadata URL not specified. Skipping metadata block check.")
        return

    if metadata_blocked:
        try:
            response = requests.get(metadata_url, timeout=5)
            append_results_to_file(result_filename, f"[CAUTION] Metadata server Accesible: {metadata_url}")
        except requests.RequestException:
            append_results_to_file(result_filename, "[SAFE] Access Denied to Metadata server")
    else:
        append_results_to_file(result_filename, "[INFO] No metadata server blocking settings, skip check.")

def check_url_filtering(result_filename):
    for url in local_urls:
        try:
            response = requests.get(url, timeout=5)
            append_results_to_file(result_filename, f"[CAUTION] Access allowed to internal IP {url}.")
        except requests.RequestException:
            append_results_to_file(result_filename, f"[SAFE] Access Denied to internal IP {url}.")

def check_allowed_methods(result_filename):
    
    if not allowed_methods:
        append_results_to_file(result_filename, "[INFO] Client offer URL not specified. Skipping HTTP method check.")
        return
    
    for method in ["GET", "POST", "PUT", "DELETE"]:
        if method in allowed_methods:
            append_results_to_file(result_filename, f"[INFO] {method} method allowed.")
        else:
            try:
                response = requests.request(method, client_offer_url, timeout=5)
                append_results_to_file(result_filename, f"[CAUTION] {method} method allowed.")
            except requests.RequestException:
                append_results_to_file(result_filename, f"[SAFE] {method} method denied")

def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=== A-10 Server-Side Request Forgery (SSRF) Diagnostics ===\n")

    check_server_side_request(result_filename)
    check_whitelist(result_filename)
    check_metadata_block(result_filename)
    check_url_filtering(result_filename)
    check_allowed_methods(result_filename)


