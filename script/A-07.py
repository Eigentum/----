import json
import requests
import os
import subprocess

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

base_url = config.get("base_url", "").strip()
session_timeout_config = config.get("session_timeout", "").strip()
login_attempt_limit_config = config.get("login_attempt_limit", "").strip()
password_hash_method_config = config.get("password_hash_method", "").strip()

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def get_distro():
    try:
        result = subprocess.check_output(['lsb_release', '-i'], text=True).strip()
        if 'Ubuntu' in result or 'Debian' in result:
            return 'debian'
        elif 'CentOS' in result or 'Red Hat' in result:
            return 'redhat'
        elif 'Arch' in result:
            return 'arch'
    except subprocess.CalledProcessError:
        return None

def get_password_policy():
    distro = get_distro()

    try:
        if distro == 'debian':
            result = subprocess.check_output(['grep', '^PASS_MIN_LEN', '/etc/login.defs'], text=True)
            return int(result.split()[1])
        
        elif distro == 'redhat':
            result = subprocess.check_output(['grep', '^minlen', '/etc/security/pwquality.conf'], text=True)
            return int(result.split('=')[1].strip())
        
        elif distro == 'arch':
            result = subprocess.check_output(['grep', '^minlen', '/etc/security/pwquality.conf'], text=True)
            return int(result.split('=')[1].strip())
        
        else:
            print("[INFO] Distribution not recognized. Please check the password policy manually.")
            return None
        
    except subprocess.CalledProcessError:
        print("[INFO] Password policy not found in the expected files..")

def check_password_policy(result_filename):
    password_policy = get_password_policy()
    if password_policy:
        append_results_to_file(result_filename, f"[SAFE] Password minimum length policy: {password_policy}")
    else:
        append_results_to_file(result_filename, "[INFO] Password policy configuration not found.")


def get_session_timeout():
    try:
        if os.name == 'posix':
            timeout = os.environ.get('TMOUT', None)
            if timeout:
                return int(timeout) // 60
        elif os.name == 'nt':
            result = subprocess.check_output(['reg', 'query', 'HKCU\\Control Panel\\Desktop', '/v', 'ScreenSaveTimeOut'], text=True)
            for line in result.splitlines():
                if 'ScreenSaveTimeOut' in line:
                    return int(line.split()[-1]) // 60
    except Exception as e:
        print(f"[INFO] Unable to load session timeout data: {e}")
    return int(session_timeout_config) if session_timeout_config else None

def get_login_attempt_limit():
    try:
        if os.name == 'posix':
            result = subprocess.check_output(['grep', '^deny', '/etc/security/faillock.conf', '/etc/pam.d/common-auth'], text=True)
            for line in result.splitlines():
                if 'deny' in line:
                    return int(line.split('=')[1].strip())
    except subprocess.CalledProcessError:
        print("[INFO] Login attempt limit configuration not found in system files.")
    return int(login_attempt_limit_config) if login_attempt_limit_config else None

def get_password_hash_method():
    try:
        if os.name == 'posix' and os.path.exists('/etc/shadow'):
            result = subprocess.check_output(['grep', '-E', '^[^:]+:[$]', '/etc/shadow'], text=True)
            if "$6$" in result:
                return "SHA-512"
            elif "$5$" in result:
                return "SHA-256"
            elif "$2y$" in result:
                return "bcrypt"
            elif "$1$" in result:
                return "MD5"
    except subprocess.CalledProcessError:
        print("[INFO] Password hashing method configuration not found. Refer to config.json.")
    return password_hash_method_config if password_hash_method_config else None

def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=== A-07 Identification and Authentication Failures Diagnostics ===\n")

    session_timeout = get_session_timeout()
    if session_timeout:
        append_results_to_file(result_filename, f"[SAFE] Session timeout is set to {session_timeout} minutes.")
    else:
        append_results_to_file(result_filename, "[INFO] Session timeout configuration missing.")

    login_attempt_limit = get_login_attempt_limit()
    if login_attempt_limit:
        append_results_to_file(result_filename, f"[SAFE] Login attempt limit is set to {login_attempt_limit} attempts.")
    else:
        append_results_to_file(result_filename, "[INFO] Login attempt limit configuration missing.")

    password_hash_method = get_password_hash_method()
    if password_hash_method:
        append_results_to_file(result_filename, f"[SAFE] Password hash method is {password_hash_method}.")
    else:
        append_results_to_file(result_filename, "[INFO] Password hash method configuration missing.")