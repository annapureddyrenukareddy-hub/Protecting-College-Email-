"""Local SQLite accounts and encrypted message mailbox for the Streamlit portals."""
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "portal.sqlite3"
PASSWORD_ITERATIONS = 350_000


def urn_key(urn):
    return "".join(str(urn or "").split()).upper()


def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _init_db():
    with _connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                role TEXT NOT NULL CHECK(role IN ('faculty', 'student')),
                display_name TEXT NOT NULL,
                urn TEXT,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                private_key_salt BLOB,
                encrypted_private_key BLOB,
                public_key_der BLOB,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_student_urn ON users(urn) WHERE role = 'student'")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS mailbox (
                id TEXT PRIMARY KEY,
                sender_username TEXT NOT NULL,
                recipient_urn TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS mailbox_recipient ON mailbox(recipient_urn, created_at DESC)")


_init_db()


def _password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)


def _fernet_key(password, salt):
    derived = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def register_user(username, password, role, display_name, urn=None):
    username = str(username or "").strip()
    display_name = str(display_name or "").strip()
    role = str(role or "").strip().lower()
    normalized_urn = urn_key(urn) if role == "student" else None
    if len(username) < 3:
        raise ValueError("Username must contain at least 3 characters.")
    if len(password or "") < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if role not in ("faculty", "student"):
        raise ValueError("Choose a valid account type.")
    if not display_name:
        raise ValueError("Enter your name.")
    if role == "student" and not normalized_urn:
        raise ValueError("Enter a student URN.")

    password_salt = os.urandom(16)
    password_hash = _password_digest(password, password_salt)
    private_key_salt = encrypted_private_key = public_key_der = None
    if role == "student":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_key_salt = os.urandom(16)
        encrypted_private_key = _fernet_key(password, private_key_salt).encrypt(private_pem)

    try:
        with _connect() as connection:
            connection.execute("""
                INSERT INTO users (username, role, display_name, urn, password_salt, password_hash,
                                   private_key_salt, encrypted_private_key, public_key_der, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                username, role, display_name, normalized_urn, password_salt, password_hash,
                private_key_salt, encrypted_private_key, public_key_der,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ))
    except sqlite3.IntegrityError as error:
        if "urn" in str(error).lower():
            raise ValueError("An account already exists for that URN.") from error
        raise ValueError("That username is already in use.") from error


def authenticate(username, password):
    if not username or not password:
        return None, None
    with _connect() as connection:
        row = connection.execute("SELECT * FROM users WHERE username = ?", (str(username).strip(),)).fetchone()
    if row is None:
        return None, None
    candidate = _password_digest(password, row["password_salt"])
    if not hmac.compare_digest(candidate, row["password_hash"]):
        return None, None
    private_key = None
    if row["role"] == "student":
        try:
            private_pem = _fernet_key(password, row["private_key_salt"]).decrypt(row["encrypted_private_key"])
            private_key = serialization.load_pem_private_key(private_pem, password=None)
        except (InvalidToken, ValueError):
            return None, None
    user = {
        "username": row["username"],
        "role": row["role"],
        "display_name": row["display_name"],
        "urn": row["urn"],
    }
    return user, private_key


def list_students():
    with _connect() as connection:
        rows = connection.execute(
            "SELECT username, display_name, urn, public_key_der FROM users WHERE role = 'student' ORDER BY urn"
        ).fetchall()
    return [{
        "username": row["username"],
        "display_name": row["display_name"],
        "urn": row["urn"],
        "public_key": serialization.load_der_public_key(row["public_key_der"]),
    } for row in rows]


def get_student_by_urn(urn):
    key = urn_key(urn)
    for student in list_students():
        if student["urn"] == key:
            return student
    return None


def add_mail(sender_username, recipient_urn, envelope):

    normalized_urn = urn_key(recipient_urn)
    mail_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect() as connection:
        connection.execute(
            "INSERT INTO mailbox (id, sender_username, recipient_urn, envelope_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (mail_id, sender_username, normalized_urn, json.dumps(envelope, separators=(",", ":")), created_at),
        )
    return mail_id


def list_mail_for_urn(urn):
    key = urn_key(urn)
    with _connect() as connection:
        rows = connection.execute(
            "SELECT id, sender_username, created_at, envelope_json FROM mailbox WHERE recipient_urn = ? ORDER BY created_at DESC",
            (key,),
        ).fetchall()
    return [{
        "id": row["id"],
        "sender_username": row["sender_username"],
        "created_at": row["created_at"],
        "envelope": json.loads(row["envelope_json"]),
    } for row in rows]


