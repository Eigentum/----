import importlib
import os
import datetime

# 초기 상태 변수
system_info = "empty"
library_status = "empty"
owasp_status = {f"A-{str(i).zfill(2)}": False for i in range(1, 11)}

# 시스템 환경 및 라이브러리 상태 진단 함수
def check_libraries():
    try:
        from settings import check_lib
        return check_lib.check_installed_libraries()
    except ImportError:
        return "Error: settings/check_lib.py not found."

def check_system_environment():
    try:
        from settings import check_os
        return check_os.check_system()
    except ImportError:
        return "Error: settings/check_OS.py not found."

def display_status():
    print("Current System Environment:", system_info)
    print("Current Library Status:", library_status)
    print("=========================================")
    print("Available OWASP Top 10 2021 Categories (A-01 to A-10):")
    for key, value in owasp_status.items():
        status = "Enabled" if value else "Disabled"
        print(f"{key}: {status}")
    print("=========================================")

# OWASP 항목 선택 함수
def toggle_owasp_categories():
    print("Select OWASP categories to enable (e.g., 1,3,5 for A-01, A-03, A-05).")
    choices = input("Enter numbers separated by commas: ").split(",")
    for choice in choices:
        try:
            index = int(choice.strip())
            if 1 <= index <= 10:
                owasp_status[f"A-{str(index).zfill(2)}"] = True
        except ValueError:
            print(f"Invalid choice: {choice}")

# 진단 실행 함수
def run_diagnostics():
    if system_info == "empty" or library_status == "empty":
        print("Error: System environment or library status not checked. Run checks before proceeding.")
        return

    selected_categories = [key for key, enabled in owasp_status.items() if enabled]
    if not selected_categories:
        print("Error: No OWASP categories selected for diagnostics.")
        return
    
    result_folder = os.path.join(os.path.dirname(__file__), "result")
    os.makedirs(result_folder, exist_ok=True)  # 폴더가 없으면 생성
    
    result_filename = os.path.join(result_folder, datetime.datetime.now().strftime("diagnosis_%Y%m%d_%H%M%S.txt"))
    with open(result_filename, "w") as result_file:
        result_file.write("OWASP Top 10 2021 Diagnostics Results\n")
        result_file.write(f"System: {system_info}\n")
        result_file.write(f"Libraries: {library_status}\n\n")
        
        script_directory = os.path.join(os.path.dirname(__file__), "script")
        print("Files in script directory:", os.listdir(script_directory))
        for category in selected_categories:
            module_path = os.path.join(script_directory, f"{category}.py")  # Linux or Windows directory
            try:
                print(f"Running diagnostics for {category}...")
                spec = importlib.util.spec_from_file_location(category, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module.run_diagnosis(result_filename)  # Assume each module has run_diagnosis function
                print(f"{category} diagnostics completed.")
            except FileNotFoundError:
                print(f"Module file {module_path} not found.")
                with open(result_filename, "a") as result_file:
                    result_file.write(f"Results for {category}:\nModule not found.\n\n")
            except AttributeError:
                print(f"Error: 'run_diagnosis' function not found in {module_path}.")
                with open(result_filename, "a") as result_file:
                    result_file.write(f"Results for {category}:\n'run_diagnosis' function not found.\n\n")

    print(f"Diagnostics completed. Results saved to {result_filename}.")

# Main Program
if __name__ == "__main__":
    print("Welcome to the OWASP Top 10 2021 Diagnostics Tool.")

    while True:
        print("\nOptions:")
        print("1. Check System Environment")
        print("2. Check Library Status")
        print("3. Toggle OWASP Categories")
        print("4. Run Diagnostics")
        print("5. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            system_info = check_system_environment()
        elif choice == "2":
            library_status = check_libraries()
        elif choice == "3":
            toggle_owasp_categories()
        elif choice == "4":
            run_diagnostics()
        elif choice == "5":
            print("Exiting the tool.")
            break
        else:
            print("Invalid option. Please select again.")

        display_status()
