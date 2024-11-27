import re
import importlib
import requests
import json
import os
import platform



config_path = os.path.join(os.path.dirname(__file__), "../settings/config.json")
with open(config_path, "r") as f:
    config = json.load(f)

def append_results_to_file(result_filename, content):
    with open(result_filename, "a") as result_file:
        result_file.write(content + "\n")

db_path = config.get("db_path", "").strip()
if not db_path:
    db_path = "No DB's Path."
    print("[WARNING] DB path is not provided. Using default: 'No DB's Path'.")

table_name = config.get("table_name", "").strip()
if not table_name:
    print("[WARNING] Table name is not provided. Skipping sensitive data checks.")
    table_name = None

column_name = config.get("column_name", "").strip()
if not column_name:
    print("[WARNING] Column name is not provided. Skipping sensitive column checks.")
    column_name = None

url = config.get("url", "").strip()
if not url:
    print("[WARNING] URL is not provided. Skipping HTTPS checks.")
    url = None

host = config.get("db_host", "").strip()
if not host:
    print("[WARNING] DB host is not provided. Skipping DB connection.")
    host = None

user = config.get("db_user", "").strip()
if not user:
    print("[WARNING] DB user is not provided. Skipping DB connection.")
    user = None

password = config.get("db_password", "").strip()
if not password:
    print("[WARNING] DB password is not provided. Skipping DB connection.")
    password = None

database = config.get("database", "").strip()
if not database:
    print("[WARNING] DB name is not provided. Skipping DB connection.")
    database = None


def detect_dbms(db_path):
    if db_path.endswith(".db") or db_path.endswith(".sqlite"):
        return "sqlite"
    elif "mysql" in db_path:
        return "mysql"
    elif "postgresql" in db_path:
        return "postgresql"
    elif "oracle" in db_path or db_path.endswith(".ora"):
        return "oracle"
    elif "mssql" in db_path or "sqlserver" in db_path:
        return "mssql"
    else:
        raise ValueError("Unsupported or undetected DBMS type")
    
def get_odbc_driver():
    if platform.system() == "Windows":
        return "{ODBC Driver 17 for SQL Server}"
    elif platform.system() == "Linux":
        return "{ODBC Driver 18 for SQL Server}"
    else:
        raise ValueError("Unsupported OS for MSSQL ODBC driver")

def get_db_connection(db_type, db_path, **kwargs):
    try:
        if db_type == "sqlite":
            sqlite3 = importlib.import_module("sqlite3")
            return sqlite3.connect(db_path)
        elif db_type == "mysql":
            pymysql = importlib.import_module("pymysql")
            return pymysql.connect(
                host=kwargs.get("host", "localhost"),
                user=kwargs.get("user", "root"),
                password=kwargs.get("password", ""),
                database=kwargs.get("database", db_path)
            )
        elif db_type == "postgresql":
            psycopg2 = importlib.import_module("psycopg2")
            return psycopg2.connect(
                host=kwargs.get("host", "localhost"),
                user=kwargs.get("user", "postgres"),
                password=kwargs.get("password", ""),
                dbname=kwargs.get("database", db_path)
            )
        elif db_type == "oracle":
            cx_Oracle = importlib.import_module("cx_Oracle")
            dsn = cx_Oracle.makedsn(kwargs.get("host", "localhost"), kwargs.get("port", 1521), service_name=kwargs.get("service_name", "ORCL"))
            return cx_Oracle.connect(user=kwargs.get("user", "user"), password=kwargs.get("password", ""), dsn=dsn)
        elif db_type == "mssql":
            pyodbc = importlib.import_module("pyodbc")
            conn_str = f"DRIVER={get_odbc_driver()};SERVER={kwargs.get('host', 'localhost')};DATABASE={kwargs.get('database', db_path)};UID={kwargs.get('user', 'sa')};PWD={kwargs.get('password', '')}"
            return pyodbc.connect(conn_str)
        else:
            raise ValueError("Unsupported DBMS type")
    except Exception as e:
        print(f"[ERROR] Failed to connect to database: {e}")
        return None
    
def get_sensitive_columns(db_type, conn):
    sensitive_keywords = ["password", "pw", "passwd", "ssn", "credit", "card", "email", "phone"]
    sensitive_columns = []
    cursor = conn.cursor()

    if db_type == "sqlite":
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        for table in tables:
            table_name = table[0]
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            for column in columns:
                column_name = column[1]
                if any(keyword in column_name.lower() for keyword in sensitive_keywords):
                    sensitive_columns.append((table_name, column_name))

    elif db_type == "mysql":
        cursor.execute(f"SHOW COLUMNS FROM {table_name};")
        columns = cursor.fetchall()
        for column in columns:
            column_name = column[0]
            if any(keyword in column_name.lower() for keyword in sensitive_keywords):
                sensitive_columns.append(column_name)

    elif db_type == "postgresql":
        cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name}';")
        columns = cursor.fetchall()
        for column in columns:
            column_name = column[0]
            if any(keyword in column_name.lower() for keyword in sensitive_keywords):
                sensitive_columns.append(column_name)

    elif db_type == "oracle":
        cursor.execute(f"SELECT column_name FROM all_tab_columns WHERE table_name = UPPER('{table_name}')")
        columns = cursor.fetchall()
        for column in columns:
            column_name = column[0]
            if any(keyword in column_name.lower() for keyword in sensitive_keywords):
                sensitive_columns.append(column_name)

    elif db_type == "mssql":
        cursor.execute(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}';")
        columns = cursor.fetchall()
        for column in columns:
            column_name = column[0]
            if any(keyword in column_name.lower() for keyword in sensitive_keywords):
                sensitive_columns.append(column_name)

    return sensitive_columns


def check_hashed(data, result_filename):
    append_results_to_file(result_filename,"\n===== Check for hashing of data. =====")
    if len(data) in [60, 64] and re.match(r'^[a-fA-F0-9]+$', data):
        append_results_to_file(result_filename, "[INFO] Data is hashed.")
        return True
    else:
        append_results_to_file(result_filename, "[CAUTION] Data may not be hashed.")
        return False
    
def check_sensitive_data_encrypted(data, result_filename):
    append_results_to_file(result_filename,"\n===== Check for sensitive data encryption. ===== ")
    sensitive_patterns = [
        r"\b\d{6}-\d{7}\b",             # 주민등록번호
        r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", # 카드번호
        r"\b\d{10,}\b",                 # 전화번호
        r"\b\w+@\w+\.\w+\b"             # 이메일주소
    ]
    for pattern in sensitive_patterns:
        if re.search(pattern, data):
            append_results_to_file(result_filename, "[CAUTION] Plain text sensitive data detected")
            return False
    append_results_to_file(result_filename, "[SAFE] Data appears encrypted or hashed")
    return True

def validate_encryption(data, result_filename):
    append_results_to_file(result_filename,"\n===== Check encryption validation. =====")
    if isinstance(data, bytes) and len(data) >= 32:
        append_results_to_file(result_filename, "[INFO] Data likely encrypted with a strong algorithm.")
        return True
    else:
        append_results_to_file(result_filename, "[CAUTION] Data may not be encrypted with a secure algorithm.")
        return False
    
def diagnose_sensitive_columns(db_type, conn, table_name, column_name, result_filename):
    append_results_to_file(result_filename,"\n===== Check the sensitive column. =====")
    cursor = conn.cursor()
    cursor.execute(f"SELECT {column_name} FROM {table_name}")
    rows = cursor.fetchall()
    for row in rows:
        data = row[0]

        append_results_to_file(result_filename, f"\nChecking data in {column_name} of table {table_name}:")
        check_sensitive_data_encrypted(data, result_filename)
        
        if not check_hashed(data, result_filename):
            append_results_to_file(result_filename, f"[CAUTION] Data in {column_name} is not hashed with a secure algorithm.")
        
        validate_encryption(data, result_filename)




def check_https_encrypted(url, result_filename):
    append_results_to_file(result_filename,"\n===== Checks HTTP protocol for encryption. =====")
    try:
        response = requests.get(url, verify=True)
        if response.url.startswith("https://"):
            append_results_to_file(result_filename, "[SAFE] Using HTTPS Protocol and SSL Certificate is valid.")
        else:
            append_results_to_file(result_filename, "[CAUTION] Does not use HTTPS Protocol")

        # Check HSTS header
        if 'Strict-Transport-Security' in response.headers:
            append_results_to_file(result_filename, "[SAFE] HSTS is enabled.")
        else:
            append_results_to_file(result_filename, "[CAUTION] HSTS is not enabled.")

    except requests.exceptions.SSLError:
        append_results_to_file(result_filename, "[CAUTION] SSL certificate is invalid or expired.")
    except requests.exceptions.RequestException as e:
        append_results_to_file(result_filename, f"[ERROR] An error occurred: {e}")


DIR = config.get("check_hardcoded_secretkey_target_dir")
def check_hardcoded_secret_key(DIR, result_filename):
    append_results_to_file(result_filename,"\n===== Check the encryption key for hard coding. =====")
    file_extensions = [ext.lower() for ext in config.get("file_extensions", [])]
    secret_key_pattern = re.compile(r'(secret|key|token)\s*=\s*[\'"][a-zA-Z0-9+/=]+[\'"]', re.IGNORECASE)
    sensitive_files = []

    for root, _, files in os.walk(DIR):
        for file in files:
            if any(file.lower().endswith(ext) for ext in file_extensions):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if secret_key_pattern.search(content):
                        append_results_to_file(result_filename, f"[CAUTION] Hardcoded secret key detected in: {file_path}")
                        sensitive_files.append(file_path)

    if not sensitive_files:
        append_results_to_file(result_filename, "[SAFE] No hardcoded secret key detected in the code.")


def run_diagnosis(result_filename):
    append_results_to_file(result_filename, "\n=======================================")
    append_results_to_file(result_filename, "=== A-02 OWASP Cryptograph Failures ===")
    append_results_to_file(result_filename, "=======================================")
    
    try:
        db_type = detect_dbms(db_path)
        conn = get_db_connection(db_type, db_path, host=host, user=user, password=password, database=database)
        if conn:
            try:
                append_results_to_file(result_filename, "[INFO] Connected to database successfully.")
                diagnose_sensitive_columns(db_type, conn, table_name, column_name, result_filename)
            except Exception as e:
                append_results_to_file(result_filename, f"[ERROR] Error during sensitive column diagnosis: {e}")
            finally:
                conn.close()
                append_results_to_file(result_filename, "[INFO] Database connection closed.")
    except ValueError as ve:
        append_results_to_file(result_filename, f"[ERROR] Database type detection failed: {ve}")
    except Exception as e:
        append_results_to_file(result_filename, f"[ERROR] An error occurred during database connection: {e}")

    
    check_https_encrypted(url, result_filename)

    if DIR:  
        check_hardcoded_secret_key(DIR, result_filename)
    else:
        append_results_to_file(result_filename, "[WARNING] No directory specified for hardcoded secret key check.")

    append_results_to_file(result_filename, "\n=== End of A-02 Diagnostics ===\n")



