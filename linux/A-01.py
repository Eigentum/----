import requests
import jwt
import os
from bs4 import BeautifulSoup

class AccessControlDiagnosticTool:
    def __init__(self):
        # 사용자 입력을 한 번에 받아 초기화
        self.base_url = "http://" + input("Enter the Base URL: ").strip()
        self.admin_path = input(f"Enter Admin page path ({self.base_url}): ").strip()
        self.login_path = input(f"Enter Login page path ({self.base_url}): ").strip()
        self.api_path = input(f"Enter API path ({self.base_url}): ").strip()
        self.original_token = input("Enter the JWT original token: ").strip()
        self.secret_key = self.get_secret_key()
        self.cors_origin = input("Enter CORS test Origin URL: ").strip()

    def get_secret_key(self):
        # 비밀키를 환경 변수에서 불러오거나 직접 입력
        print("\n1. Load Secret key from environment variable (JWT_SECRET_KEY)")
        print("2. Enter the Secret key directly")
        choice = input("Choose an option (1 or 2): ").strip()
        if choice == "1":
            secret_key = os.getenv("JWT_SECRET_KEY")
            if secret_key:
                print(f"Secret key loaded successfully: {secret_key}")
                return secret_key
            else:
                print("[ERROR] Secret key not found in environment. Enter manually.")
                return input("Enter the Secret key: ").strip()
        elif choice == "2":
            return input("Enter the Secret key: ").strip()
        else:
            print("No Secret Key provided.")
            return None

    def check_access_sensitive_url(self):
        if not self.base_url:
            print("Skipping sensitive URL access check (Base URL not provided).")
            return

        sensitive_paths = ['/admin', '/config', '/backup', '/user/settings']
        for path in sensitive_paths:
            url = self.base_url + path
            try:
                response = requests.get(url, allow_redirects=False)
                if response.status_code == 200:
                    print(f"[CAUTION] Allowed access to: {url}")
                elif response.status_code == 403:
                    print(f"[SAFE] Access denied to: {url}")
                elif response.status_code == 404:
                    print(f"[SAFE] Path not found: {url}")
                else:
                    print(f"[Need to Check] Unexpected response code {response.status_code} for {url}")
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Unable to access {url}. Error: {e}")

    def check_api_access_control(self):
        if not self.api_path:
            print("Skipping API access control check (API path not provided).")
            return

        api_endpoints = {self.api_path: ['GET', 'POST', 'DELETE']}
        for endpoint, methods in api_endpoints.items():
            if not endpoint or endpoint.strip() == "":
                continue
            for method in methods:
                url = self.base_url + endpoint
                response = requests.request(method, url, allow_redirects=False)
                if response.status_code == 200 and method in ['POST', 'PUT', 'DELETE']:
                    print(f"[CAUTION] {method} allowed without authentication: {url}")
                elif response.status_code == 403:
                    print(f"[SAFE] Access forbidden: {url}")
                else:
                    print(f"[Need to Check] Status code {response.status_code} for {method} request to {url}")

    def check_session_expiration(self):
        if not (self.login_path and self.base_url):
            print("Skipping session expiration check (Login path or Base URL not provided).")
            return

        with requests.Session() as session:
            login_url = self.base_url + self.login_path
            login_data = {'username': input("Enter username: ").strip(),
                          'password': input("Enter password: ").strip()}
            session.post(login_url, data=login_data)
            session.cookies.clear()  # 세션 만료 시뮬레이션
            response = session.get(self.base_url + self.admin_path, allow_redirects=False)
            if response.status_code == 200:
                print(f"[CAUTION] Access allowed after session expiration: {self.admin_path}")
            elif response.status_code == 403:
                print(f"[SAFE] Access denied after session expiration: {self.admin_path}")

    def metadata_manipulation_check(self):
        if not (self.original_token and self.secret_key):
            print("Skipping metadata manipulation check (Token or Secret Key not provided).")
            return

        if self.check_jwt_usage():
            self.jwt_manipulation_check(self.original_token)
        else:
            self.cookie_manipulation_check()

    def check_jwt_usage(self):
        response = requests.get(self.base_url)
        auth_header = response.headers.get("Authorization")
        if auth_header and "Bearer" in auth_header:
            print("JWT token usage confirmed.")
            return True
        else:
            print("JWT token not detected.")
            return False

    def jwt_manipulation_check(self, original_token):
        manipulated_token = jwt.encode({"role": "admin"}, self.secret_key, algorithm="HS256")
        headers = {"Authorization": f"Bearer {manipulated_token}"}
        response = requests.get(self.base_url + self.admin_path, headers=headers, allow_redirects=False)
        if response.status_code == 200:
            print("[CAUTION] Manipulated JWT token allowed access.")
        elif response.status_code == 403:
            print("[SAFE] Manipulated JWT token denied access.")

    def cookie_manipulation_check(self):
        if not (self.admin_path and self.login_path):
            print("Skipping cookie manipulation check (Admin or Login path not provided).")
            return

        with requests.Session() as session:
            session.get(self.base_url + self.login_path)
            session.cookies.set("user_role", "admin")
            response = session.get(self.base_url + self.admin_path, allow_redirects=False)
            if response.status_code == 200:
                print("[CAUTION] Access allowed with manipulated cookie.")
            elif response.status_code == 403:
                print("[SAFE] Access denied with manipulated cookie.")

    def check_cors_configuration(self):
        if not (self.api_path and self.cors_origin):
            print("Skipping CORS configuration check (API path or CORS origin not provided).")
            return

        headers = {"Origin": self.cors_origin}
        response = requests.options(self.base_url + self.api_path, headers=headers)
        if "Access-Control-Allow-Origin" in response.headers:
            allowed_origin = response.headers["Access-Control-Allow-Origin"]
            if allowed_origin == "*":
                print("[CAUTION] CORS allows all origins ('*').")
            else:
                print(f"[SAFE] CORS restricted to specific origin: {allowed_origin}")
        else:
            print("[SAFE] CORS configuration not set.")

    def check_hidden_fields(self):
        paths = input("Enter pages to search for hidden fields (comma-separated, e.g., /admin, /profile): ").strip()
        if not paths:
            print("Skipping hidden fields check (No pages provided).")
            return

        for path in paths.split(","):
            path = path.strip()
            response = requests.get(self.base_url + path)
            soup = BeautifulSoup(response.text, "html.parser")
            hidden_fields = soup.find_all("input", type="hidden")
            if hidden_fields:
                print(f"[CAUTION] Hidden fields found in {path}:")
                for field in hidden_fields:
                    print(f"Field - name: {field.get('name')}, value: {field.get('value')}")
            else:
                print(f"[SAFE] No hidden fields found in {path}")

    def check_error_messages(self):
        paths = input("Enter pages to check error messages (comma-separated, e.g., /admin, /profile): ").strip()
        if not paths:
            print("Skipping error message check (No pages provided).")
            return

        for path in paths.split(","):
            path = path.strip()
            response = requests.get(self.base_url + path, allow_redirects=False)
            if response.status_code == 403:
                if "Access Denied" in response.text or "Unauthorized" in response.text:
                    print(f"[SAFE] Standard error message for {path}")
                else:
                    print(f"[CAUTION] Potential sensitive information in error message for {path}")
            else:
                print(f"[Need Check] Response code {response.status_code} for {path}")

# 진단 실행
tool = AccessControlDiagnosticTool()
tool.check_access_sensitive_url()
tool.check_api_access_control()
tool.check_session_expiration()
tool.metadata_manipulation_check()
tool.check_cors_configuration()
tool.check_hidden_fields()
tool.check_error_messages()
