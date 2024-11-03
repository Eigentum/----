import platform
import os
import subprocess

def get_os_info():
    return{
        'os_name' : platform.system(),
        'os_ver' :  platform.release(),
        'is_windows' : os.name == 'nt',
        'is_linux' : os.name == 'posix'
    }


'''
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..\\settings'))

from check_OS import get_os_info

env_info = get_os_info()
print(f"OS Name: {env_info['os_name']}, OS version: {env_info['os_ver']}")
'''
