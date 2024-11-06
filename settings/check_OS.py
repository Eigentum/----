import platform

def check_system():
    os_name = platform.system()
    os_ver = platform.release()

    if os_name == "Windows":
        return f"Windows {os_ver}"
    elif os_name == "Linux":
        return f"Linux {os_ver}"
    else:
        return f"Unknown OS: {os_name} {os_ver}"
