import requests
import jwt
import os
import json
from bs4 import BeautifulSoup

class AccessControlDiagnosticTool:
    def __init__(self):
        config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")

        with open(config_path, 'r') as f:
            config = json.load(f)

        # 사용자 입력을 한 번에 받아 초기화
        self.base_url = config.get("base_url")
        self.admin_path = config.get("admin_path")
        self.login_path = config.get("login_path")
        self.sensitive_paths = config.get("sensitive_paths")
        self.api_path = config.get("api_paths", ["/api"])[0] if isinstance(config.get("api_paths"), list) else config.get("api_paths")
        self.original_token = config.get("original_token")
        self.secret_key = config.get("secret_key")
        self.cors_origin = config.get("cors_origin")
        self.username = config.get("username")
        self.password = config.get("password")
        self.hidden_field_paths = config.get("hidden_field_paths")
        self.error_message_paths = config.get("error_message_paths")

    
    def perform_diagnostics(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("========================================")
            result_file.write("\n=== A-01 OWASP Broken Access Control ===\n")
            result_file.write("========================================")

        # 진단 함수들에 result_filename 전달
        self.check_access_sensitive_url(result_filename)
        self.check_api_access_control(result_filename)
        self.check_session_expiration(result_filename)
        self.metadata_manipulation_check(result_filename)
        self.check_cors_configuration(result_filename)
        self.check_hidden_fields(result_filename)
        self.check_error_messages(result_filename)

    def fetch_robots_disallowed_paths(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check Robots.txt. =====\n")
            robots_url = self.base_url + "/robots.txt"
            disallowed_paths = []
            try:
                response = requests.get(robots_url)
                if response.status_code == 200:
                    lines = response.text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if line.startswith("Disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                disallowed_paths.append(path)
                    result_file.write(f"[INFO] Found {len(disallowed_paths)} disallowed paths in robots.txt")
                else:
                    result_file.write(f"[INFO] robots.txt not found or inaccessible (status code {response.status_code}).\n")
            except requests.RequestException as e:
                result_file.write(f"[ERROR] Failed to retrieve robots.txt {e}")

            return disallowed_paths

    def check_access_sensitive_url(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check for sensitive path accessibility.=====\n")
            result_file.write("[INFO] Checking sensitive URL access.\n")

            if not self.base_url:
                result_file.write("[INFO] Skipping sensitive URL access check (Base URL not provided).\n")
                return

            combined_sensitive_paths = list(set((self.sensitive_paths or []) + self.fetch_robots_disallowed_paths(result_filename)))
            if not combined_sensitive_paths:
                result_file.write("[INFO] No sensitive paths to check.\n")
                return  # 여기서도 종료 필요

            result_file.write(f"[INFO] Total sensitive paths to check: {len(combined_sensitive_paths)}\n")

            for path in combined_sensitive_paths:
                url = self.base_url + path
                try:
                    response = requests.get(url, allow_redirects=False)
                    result_file.write(f"[DEBUG] Checking URL: {url} - Status Code: {response.status_code}\n")
                    
                    if response.status_code == 200:
                        result_file.write(f"[CAUTION] Allowed access to: {url}\n")
                    elif response.status_code == 403:
                        result_file.write(f"[SAFE] Access denied to: {url}\n")
                    elif response.status_code == 404:
                        result_file.write(f"[SAFE] Path not found: {url}\n")
                    else:
                        result_file.write(f"[Need to Check] Unexpected response code {response.status_code} for {url}\n")
                
                except requests.exceptions.RequestException as e:
                    result_file.write(f"[ERROR] Unable to access {url}. Error: {e}\n")


    def check_api_access_control(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check API access control... =====\n")
            result_file.write("[INFO] Checking API access control.\n")
            if not self.api_path:
                result_file.write("[INFO] Skipping API access control check (API path not provided).\n")
                return

            api_endpoints = {self.api_path: ['GET', 'POST', 'DELETE']}
            for endpoint, methods in api_endpoints.items():
                for method in methods:
                    url = self.base_url + endpoint
                    try:
                        response = requests.request(method, url, allow_redirects=False)
                        if response.status_code == 200 and method in ['POST', 'PUT', 'DELETE']:
                            result_file.write(f"[CAUTION] {method} allowed without authentication: {url}\n")
                        elif response.status_code == 403:
                            result_file.write(f"[SAFE] Access forbidden: {url}\n")
                        else:
                            result_file.write(f"[Need to Check] Status code {response.status_code} for {method} request to {url}\n")
                    except requests.RequestException as e:
                        result_file.write(f"[ERROR] Unable to perform {method} on {url}. Error: {e}\n")

    def check_session_expiration(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check session exiration... ======\n")
            result_file.write("[INFO] Checking Session expiration.\n")
            if not (self.login_path and self.base_url):
                result_file.write("[INFO] Skipping session expiration check (Login path or Base URL not provided).\n")
                return

            with requests.Session() as session:
                login_url = self.base_url + self.login_path
                login_data = {'username': self.username,'password': self.password}
                session.post(login_url, data=login_data)
                session.cookies.clear()  # 세션 만료 시뮬레이션
                response = session.get(self.base_url + self.admin_path, allow_redirects=False)
                if response.status_code == 200:
                    result_file.write(f"[CAUTION] Access allowed after session expiration: {self.admin_path}\n")
                elif response.status_code == 403:
                    result_file.write(f"[SAFE] Access denied after session expiration: {self.admin_path}\n")

    def metadata_manipulation_check(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check for possible modulation of metadata =====\n")
            result_file.write("[INFO] Checking metadata manipulation.\n")
            if not (self.original_token and self.secret_key):
                result_file.write("[INFO] Skipping metadata manipulation check (Token or Secret Key not provided).\n")
                return

            if self.check_jwt_usage(result_filename):
                self.jwt_manipulation_check(result_filename, self.original_token)
            else:
                self.cookie_manipulation_check(result_filename)

    def check_jwt_usage(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check whether JWT is used or not. ======\n")
            response = requests.get(self.base_url)
            auth_header = response.headers.get("Authorization")
            if auth_header and "Bearer" in auth_header:
                result_file.write("[INFO] JWT token usage confirmed.\n")
                return True
            else:
                result_file.write("[INFO] JWT token not detected.\n")
                return False

    def jwt_manipulation_check(self, result_filename, original_token):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check if JWT modulation is possible. =====\n")
            manipulated_token = jwt.encode({"role": "admin"}, self.secret_key, algorithm="HS256")
            headers = {"Authorization": f"Bearer {manipulated_token}"}
            response = requests.get(self.base_url + self.admin_path, headers=headers, allow_redirects=False)
            if response.status_code == 200:
                result_file.write("[CAUTION] Manipulated JWT token allowed access.\n")
            elif response.status_code == 403:
                result_file.write("[SAFE] Manipulated JWT token denied access.\n")

    def cookie_manipulation_check(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check for possible cookie manipulation. =====\n=")
            if not (self.admin_path and self.login_path):
                result_file.write("[INFO] Skipping cookie manipulation check (Admin or Login path not provided).\n")
                return

            with requests.Session() as session:
                session.get(self.base_url + self.login_path)
                session.cookies.set("user_role", "admin")
                response = session.get(self.base_url + self.admin_path, allow_redirects=False)
                if response.status_code == 200:
                    result_file.write("[CAUTION] Access allowed with manipulated cookie.\n")
                elif response.status_code == 403:
                    result_file.write("[SAFE] Access denied with manipulated cookie.\n")

    def check_cors_configuration(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check CORS configuration. ======\n")
            result_file.write("[INFO] Checking CORS configuration.\n")
            if not (self.api_path and self.cors_origin):
                result_file.write("[INFO] Skipping CORS configuration check (API path or CORS origin not provided).\n")
                return

            headers = {"Origin": self.cors_origin}
            response = requests.options(self.base_url + self.api_path, headers=headers)
            if "Access-Control-Allow-Origin" in response.headers:
                allowed_origin = response.headers["Access-Control-Allow-Origin"]
                if allowed_origin == "*":
                    result_file.write("[CAUTION] CORS allows all origins ('*').\n")
                else:
                    result_file.write(f"[SAFE] CORS restricted to specific origin: {allowed_origin}\n")
            else:
                result_file.write("[SAFE] CORS configuration not set.\n")

    def check_hidden_fields(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check Hidden fields on Web pages. ======\n")
            result_file.write("[INFO] Checking hidden fields.\n")
            if not self.hidden_field_paths:
                result_file.write("[INFO] Skipping hidden fields check (No pages provided).\n")
                return

            paths = self.hidden_field_paths.split(",")
            for path in paths:
                path = path.strip()
                response = requests.get(self.base_url + path)
                soup = BeautifulSoup(response.text, "html.parser")
                hidden_fields = soup.find_all("input", type="hidden")
                if hidden_fields:
                    result_file.write(f"[CAUTION] Hidden fields found in {path}:\n")
                    for field in hidden_fields:
                        result_file.write(f"Field - name: {field.get('name')}, value: {field.get('value')}\n")
                else:
                    result_file.write(f"[SAFE] No hidden fields found in {path}\n")

    def check_error_messages(self, result_filename):
        with open(result_filename, "a") as result_file:
            result_file.write("\n===== Check Error Messages on Web pages ======\n")
            result_file.write("[INFO] Checking Error messages in web pages.\n")
            if not self.error_message_paths:
                result_file.write("[INFO] Skipping error message check (No pages provided).\n")
                return

            paths = self.error_message_paths.split(",")
            for path in paths:
                path = path.strip()
                response = requests.get(self.base_url + path, allow_redirects=False)
                if response.status_code == 403:
                    if "Access Denied" in response.text or "Unauthorized" in response.text:
                        result_file.write(f"[SAFE] Standard error message for {path}\n")
                    else:
                        result_file.write(f"[CAUTION] Potential sensitive information in error message for {path}\n")
                else:
                    result_file.write(f"[Need Check] Response code {response.status_code} for {path}\n")


def run_diagnosis(result_filename):
    
    tool = AccessControlDiagnosticTool()
    try:
        tool.perform_diagnostics(result_filename)
    except Exception as e:
        with open(result_filename, "a") as result_filename:
            result_filename.write(f"[ERROR] Diagnostic failed: {str(e)}\n")

    with open(result_filename, "a") as result_file:
        result_file.write("\n=== End of A-01 Diagnostics ===\n")