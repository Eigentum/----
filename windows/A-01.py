import requests

base_url = ("http://")+input("insert URL : ")

def check_access_sensitive_url(base_url):
    sensitive_paths = [ '/admin', '/config', '/backup', '/user/settings']
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
                print(f"[Need to Check] Another Response code: {response.status_code}")
        except requests.exceptions.RequestException as e :
            print(f"[ERROR] Can not Access \"{url}\" Error: {e}")

def check_api_access_control(base_url):
    api_path = input("insert api PATH : ")
    api_endpoints = {api_path: ['GET', 'POST', 'DELETE']}
    for endpoint, methods in api_endpoints.items():
        for method in methods:
            url = base_url + endpoint
            response = requests.request(method, url, allow_redirects=False)
            if response.status_code == 200 and method in ['POST', 'PUT', 'DELETE']:
                print(f"[CAUTION] {method} Allow Request (Requires Authentication): {url}")
            elif response.status_code == 403 :
                print(f"[SAFE] Forbidden Access : {url}")
            else : 
                print(f"[Need to Check] Status Code : {response.status_code} (Method : {method}): {url}")

def check_session_expiration(base_url):
    with requests.Session() as session:
        login_url = base_url + input(f"Insert Login page's URL : {base_url}")
        login_data = {'username': input("Insert ID : "), 
                      'password': input("Insert PW : ")}
        session.post(login_url, data=login_data)

        session.cookies.clear()
        print("now, access the page where you need to login without logging in.")
        target_url = base_url + input(f'target page requiring login : {base_url}')
        response = session.get(target_url, allow_redirects=False)
        if response.status_code == 200:
            print(f"[CAUTION] Allow Access after Session Expires : {target_url}")
        elif response.status_code == 403:
            print(f"[SAFE] Denied Access after Session Expires : {target_url}")

def metadata_manipulation_check(base_url):
    def check_jwt_usage():
        response = requests.get(base_url)
        auth_header = response.headers.get("Authorization")
        if auth_header and "Bearer" in auth_header:     # 'Bearer' : 토큰 기반 인증에서 JWT 사용 시, 일반적으로 붙이는 접두어
            print("JWT Token usage confirmed.")
            return True
        else:
            print("JWT Token not used confirm.")
            return False
        
    def jwt_manipulation_check(original_token):
        import jwt
        import os
        secret_key = os.getenv("JWT_SECRET_KEY")
        manipulated_token = jwt.encode({"role": "admin"}, secret_key, algorithm="HS256") # 터미널에서 환경변수를 통해 비밀키를 받아야함. cmd:"export JWT_SECRET_KEY = [your secret key]" 또는 .env파일을 통한 관리
        headers = {"Authorization": f"Bearer {manipulated_token}"}
        response = requests.get(base_url + input(f"Insert Admin page's PATH : {base_url}"), headers=headers, allow_redirects=False)
        if response.status_code == 200:
            print("[CAUTION] Allowed the Access by Manipulated JWT token")
        elif response.status_code == 403:
            print("[SAFE] Denied Access to Manipulated JWT Tokens")

    def cookie_manipulation_check():
        with requests.Session() as session:
            session.get(base_url + input(f"Insert Login page's PATH : {base_url}"))
            session.cookies.set("user_role", "admin")  # Attempt to manipulate roles
            response = session.get(base_url + input(f"Insert Admin page's PATH : {base_url}"), allow_redirects=False)
            if response.status_code == 200:
                print("[CAUTION] Allowed the Access by Manipulated Cookie")
            elif response.status_code == 403:
                print("[SAFE] Denied Access to Manipulated Cookie")

    if check_jwt_usage():
        original_token = ""
        jwt_manipulation_check(original_token)
    else:
        cookie_manipulation_check()

def check_cors_configuration(base_url):
    headers = {"Origin": "http://"}

check_access_sensitive_url(base_url)
check_api_access_control(base_url)
check_session_expiration(base_url)
metadata_manipulation_check(base_url)



