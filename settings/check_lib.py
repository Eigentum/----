import importlib

def check_installed_libraries():
    required_libraries = [
        "requests",
        "bs4",
        "jwt"
    ]

    missing_libraries = []
    for library in required_libraries:
        try:
            importlib.import_module(library)
        except ImportError:
            missing_libraries.append(library)

    if missing_libraries:
        missing_list = ", ".join(missing_libraries)
        return f"Missing libraries: {missing_list}"
    else:
        return "All required libraries are installed."
