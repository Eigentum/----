import requests

sensitive_paths = [ '/admin', '/config', '/backup', '/user/settings']

def check_access_sensi_url(base_url):
    
    for path in sensitive_paths:
        url = base_url + path
        try:
            response = requests.get(url, allow_redirects=False)

            if response.status_code == 200:
                print(f"[CAUTION] allowed Access : {url}" )
            elif response.status_code == 403:
                print(f"[SAFE] Access Deny : {url}")
            elif response.status_code == 404:
                print(f"[SAFE] not exist path : {url}")
            else : 
                print(f"[Need Check] Another Response code: {response.status_code}")
        except requests.exceptions.RequestException as e :
            print(f"[ERROR] Can not Access \"{url}\" Error: {e}")

base_url = ("http://")+input("insert URL : ")
check_access_sensi_url(base_url)


