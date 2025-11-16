import mysql.connector, os, hashlib, base64

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 3306)),
    "user": os.getenv("DB_USER", "scuser"),
    "password": os.getenv("DB_PASSWORD", "scpass"),
    "database": os.getenv("DB_NAME", "securechat"),
}

def get_conn():
    return mysql.connector.connect(**DB_CONFIG)

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode()).hexdigest()

def create_user(username: str, password: str):
    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, pwd_hash, salt) VALUES (%s,%s,%s)",
                   (username, pwd_hash, salt))
    conn.commit()
    cursor.close()
    conn.close()

def verify_user(username: str, password: str) -> bool:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT pwd_hash, salt FROM users WHERE username=%s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row:
        return False
    stored_hash, salt = row
    return stored_hash == hash_password(password, salt)

def init_db():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE,
            pwd_hash CHAR(64),
            salt VARBINARY(16)
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print("DB initialized")
