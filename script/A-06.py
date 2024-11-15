import json
import os
import requests
import subprocess
import platform
from datetime import datetime

config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

cve_api_url = config.get("cve_api_url", "").strip()
dependency_file = config.get("dependency_file", "").strip()
components = config.get("components", [])

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def is_windows():
    return platform.system() == "Windows"

# Language and Package Manager Identification
def get_python_dependencies(result_filename):
    try:
        result = subprocess.check_output(['pip', 'list', '--format=json'], text=True)
        dependencies = json.loads(result)
        return [{"name": dep["name"], "version": dep["version"]} for dep in dependencies]
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[ERROR] Failed to retrieve Python dependencies.")
        return []
    
def get_nodejs_dependencies(result_filename):
    try:
        result = subprocess.check_output(['npm', 'list', '--json'], text=True)
        dependencies = json.loads(result).get("dependencies", {})
        return [{"name": name, "version": details.get("version")} for name, details in dependencies.items() if details.get("version")]
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[ERROR] Failed to retrieve Node.js dependencies.")
        return []

def get_java_dependencies(result_filename):
    dependencies = []
    try:
        result = subprocess.check_output(['mvn', 'dependency:list'], text=True)
        for line in result.splitlines():
            if line.startswith("[INFO]"):
                parts = line.split(":")
                if len(parts) >= 4:
                    dependencies.append({"name": f"{parts[0]}:{parts[1]}", "version": parts[3]})
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[ERROR] Failed to retrieve Java dependencies.")
    return dependencies

def get_system_packages(result_filename):
    packages = []
    if not is_windows():
        try:
            if subprocess.call(['which', 'dpkg'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                result = subprocess.check_output(['dpkg', '-l'], text=True)
                for line in result.splitlines()[5:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append({"name": parts[1], "version": parts[2]})
            elif subprocess.call(['which', 'rpm'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
                result = subprocess.check_output(['rpm', '-qa', '--qf', '%{NAME} %{VERSION}\n'], text=True)
                for line in result.splitlines():
                    name, version = line.split()
                    packages.append({"name": name, "version": version})
        except subprocess.CalledProcessError:
            append_results_to_file(result_filename, "[ERROR] Failed to retrieve system packages.")
    else:
        try:
            result = subprocess.check_output(['powershell', 'Get-Package'], text=True)
            for line in result.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 2:
                    packages.append({"name": parts[0], "version": parts[1]})
        except subprocess.CalledProcessError:
            append_results_to_file(result_filename, "[ERROR] Failed to retrieve Windows packages.")
    return packages

# CVE Vulnerability and EOL Check
def check_vulnerability(name, version, result_filename):
    headers = {"apiKey": config.get("nvd_api_key", "")} # API키가 없다면 초당 요청량 제한
    url = f"{cve_api_url}?cpeName=cpe:2.3:a:{name}:{version}"
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            cve_data = response.json()
            
            if "vulnerable" in cve_data:
                severity = cve_data.get("severity", "Unknown")  
                details = cve_data.get("details", "No details provided") 
                append_results_to_file(result_filename, f"[CAUTION] {name} {version} is vulnerable ({severity}): {details}")
            else:
                append_results_to_file(result_filename, f"[SAFE] {name} {version} is up-to-date and secure.")
        else:
            append_results_to_file(result_filename, f"[ERROR] Could not check {name} - API request failed with status {response.status_code}.")
    except requests.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] Failed to check {name} for vulnerabilities: {e}")

def check_eol(name, support_end_date, result_filename):
    try:
        end_date = datetime.strptime(support_end_date, "%Y-%m-%d")
        if end_date < datetime.now():
            append_results_to_file(result_filename, f"[CAUTION] {name} is past its end-of-life date: {support_end_date}.")
        else:
            append_results_to_file(result_filename, f"[SAFE] {name} is within its support period.")
    except ValueError:
        append_results_to_file(result_filename, f"[INFO] Invalid EOL date format for {name}: {support_end_date}")

# Dependency File Check
def check_dependency_file(result_filename):
    if not dependency_file:
        append_results_to_file(result_filename, "[INFO] Skipping dependency file check (no dependency file path provided).\n")
        return
    
    append_results_to_file(result_filename, "[INFO] Checking dependencies in specified file...")
    if not os.path.exists(dependency_file):
        append_results_to_file(result_filename, f"[ERROR] Dependency file {dependency_file} not found.")
        return
    
    with open(dependency_file, "r") as dep_file:
        dependencies = dep_file.readlines()
        for dep in dependencies:
            dep = dep.strip()
            if dep:
                check_vulnerability(dep, "latest", result_filename)

# Nested Dependency Check
def check_python_nested_dependencies(result_filename):
    try:
        result = subprocess.check_output(['pipdeptree', '--json'], text=True)
        dependencies = json.loads(result)
        for dep in dependencies:
            name = dep["package"]["key"]
            version = dep["package"]["installed_version"]
            check_vulnerability(name, version, result_filename)
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[INFO] Python nested dependency check skipped (pipdeptree not available).")

def check_maven_nested_dependencies(result_filename):
    try:
        subprocess.check_output(['mvn', 'org.owasp:dependency-check-maven:check'], text=True)
        append_results_to_file(result_filename, "[INFO] Maven nested dependency vulnerabilities checked via OWASP Dependency-Check.")
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[INFO] Maven nested dependency check skipped (OWASP Dependency-Check plugin not available).")

def check_nodejs_nested_dependencies(result_filename):    
    try:
        result = subprocess.check_output(['npm', 'audit', '--json'], text=True)
        audit_data = json.loads(result)
        if "advisories" in audit_data:
            for advisory_id, advisory in audit_data["advisories"].items():
                name = advisory["module_name"]
                severity = advisory["severity"]
                append_results_to_file(result_filename, f"[CAUTION] {name} has a nested dependency vulnerability ({severity}).")
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[INFO] Nested dependency vulnerability check skipped (npm audit not available).")

def check_ruby_nested_dependencies(result_filename):
    try:
        result = subprocess.check_output(['bundle', 'audit', 'check', '--update'], text=True)
        append_results_to_file(result_filename, result)
    except subprocess.CalledProcessError:
        append_results_to_file(result_filename, "[INFO] Ruby nested dependency check skipped (bundler-audit not available).")

# Run Diagnosis
def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=== A-06 Vulnerable and Outdated Components Diagnostics ===\n")

    python_deps = get_python_dependencies(result_filename)
    nodejs_deps = get_nodejs_dependencies(result_filename)
    java_deps = get_java_dependencies(result_filename)
    system_deps = get_system_packages(result_filename)

    all_dependencies = python_deps + nodejs_deps + java_deps + system_deps
    for dep in all_dependencies:
        name = dep["name"]
        version = dep["version"]
        check_vulnerability(name, version, result_filename)

    if not component:
        append_results_to_file(result_filename, "[INFO] Skipping components check (no components provided in config).\n")

    for component in components:
        name = component.get("name")
        version = component.get("version", "latest")
        support_end_date = component.get("support_end_date")
        if name and support_end_date:
            check_eol(name, support_end_date, result_filename)
        else:
            append_results_to_file(result_filename, f"[INFO] EOL check skipped for {name or 'unnamed component'} - missing name or support end date.")

    check_dependency_file(result_filename)
    check_python_nested_dependencies(result_filename)
    check_maven_nested_dependencies(result_filename)
    check_nodejs_nested_dependencies(result_filename)
    check_ruby_nested_dependencies(result_filename)
