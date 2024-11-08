import json
import requests
import os
import subprocess

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

base_url = config.get("base_url", "").strip()
session_timeout = config.get("session_timeout", "").strip()
min_password_length = config.get("min_password_length", "").strip()
login_attempt_limit = config.get("login_attempt_limit", "").strip()

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_filename.write(content + "\n")

def check_password_policy(result_filename):
    if not min_password_length:
        append_results_to_file(result_filename)


def check_session_timeout(result_filename):
    if not session_timeout:
        append_results_to_file(result_filename, "[INFO] Session timeout data not provided ")