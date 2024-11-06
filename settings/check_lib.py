import importlib

def check_installed_libraries():
    required_libraries = [
        "requests",
        "bs4",
        "jwt",
        "os",
        "sqlite3"
    ]

    missing_libraries = []
    for library in required_libraries:
        if importlib.util.find_spec(library) is None:
            missing_libraries.append(library)

    if missing_libraries:
        missing_list = ", ".join(missing_libraries)
        return f"Missing libraries: {missing_list}"
    else:
        return "All required libraries are installed."
