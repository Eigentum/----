import json
import os
import subprocess
import platform
from datetime import datetime

# Load configuration file
config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../settings/config.json"))
if not os.path.exists(config_path):
    raise FileNotFoundError(f"Config file not found at: {config_path}")


with open(config_path, "r") as f:
    config = json.load(f)

# Config values
dependency_file = config.get("dependency_file", "").strip()
components = config.get("components", [])

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

def is_windows():
    return platform.system() == "Windows"

# Dependency identification functions
def get_python_dependencies(result_filename):
    """Retrieve Python dependencies using pip."""
    try:
        result = subprocess.check_output(['pip', 'list', '--format=json'], text=True)
        dependencies = json.loads(result)
        append_results_to_file(result_filename, f"[INFO] Python dependencies: {len(dependencies)} found.")
        return [{"name": dep["name"], "version": dep["version"]} for dep in dependencies]
    except subprocess.CalledProcessError as e:
        append_results_to_file(result_filename, f"[ERROR] Failed to retrieve Python dependencies: {e}")
        return []

def get_system_packages(result_filename):
    """Retrieve system packages for Linux-based systems."""
    if is_windows():
        append_results_to_file(result_filename, "[INFO] Skipping system package check on Windows.")
        return []

    packages = []
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
        else:
            append_results_to_file(result_filename, "[INFO] No supported package manager found (dpkg or rpm).")
        append_results_to_file(result_filename, f"[INFO] System packages: {len(packages)} found.")
    except subprocess.CalledProcessError as e:
        append_results_to_file(result_filename, f"[ERROR] Failed to retrieve system packages: {e}")
    return packages

# EOL check function
def check_eol(component, result_filename):
    """Check if a component is past its end-of-life."""
    name = component.get("name")
    support_end_date = component.get("support_end_date")
    if not name or not support_end_date:
        append_results_to_file(result_filename, f"[INFO] Skipping EOL check for component: {name or 'Unnamed'} (missing data).")
        return

    try:
        end_date = datetime.strptime(support_end_date, "%Y-%m-%d")
        if end_date < datetime.now():
            append_results_to_file(result_filename, f"[CAUTION] {name} is past its end-of-life date: {support_end_date}.")
        else:
            append_results_to_file(result_filename, f"[SAFE] {name} is within its support period.")
    except ValueError:
        append_results_to_file(result_filename, f"[INFO] Invalid EOL date format for {name}: {support_end_date}.")

# Run diagnostics
def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n===========================================================")
    append_results_to_file(result_filename, "=== A-06 Vulnerable and Outdated Components Diagnostics ===")
    append_results_to_file(result_filename, "===========================================================")

    # Retrieve dependencies
    python_deps = []
    system_deps = []

    try:
        python_deps = get_python_dependencies(result_filename)
    except Exception as e:
        append_results_to_file(result_filename, f"[ERROR] Python dependency check failed: {e}")

    try:
        system_deps = get_system_packages(result_filename)
    except Exception as e:
        append_results_to_file(result_filename, f"[ERROR] System package check failed: {e}")

    # Check EOL for components
    if not components:
        append_results_to_file(result_filename, "[INFO] No components provided for EOL check.")
    else:
        for component in components:
            try:
                check_eol(component, result_filename)
            except Exception as e:
                append_results_to_file(result_filename, f"[ERROR] EOL check failed for {component.get('name', 'Unnamed')}: {e}")

    append_results_to_file(result_filename, "\n=== End of A-06 Diagnostics ===\n")
