import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional

PASSWORD_ITERATIONS = 310_000
SESSION_TTL_SECONDS = 12 * 60 * 60
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ADMIN_ROLE = "admin"
ANALYST_ROLE = "security_analyst"
ROLE_PERMISSIONS = {
    ADMIN_ROLE: ["*"],
    ANALYST_ROLE: [
        "dataset:upload",
        "analytics:view",
        "baseline:view",
        "analysis:run",
        "incidents:view",
        "incidents:manage",
        "findings:view",
        "reports:export"
    ]
}


def permissions_for_role(role: str) -> list[str]:
    return ROLE_PERMISSIONS.get(role, [])


def _database_path() -> Path:
    configured_path = os.getenv("NETWATCH_AUTH_DB")
    if configured_path:
        path = Path(configured_path).expanduser()
    else:
        path = Path(__file__).resolve().parent.parent / "data" / "netwatch_auth.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    database_path = _database_path()
    connection = sqlite3.connect(database_path, timeout=15)
    if os.name == "posix":
        os.chmod(database_path, 0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'security_analyst',
            created_at INTEGER NOT NULL
        )"""
    )
    account_columns = {row["name"] for row in connection.execute("PRAGMA table_info(accounts)")}
    if "role" not in account_columns:
        connection.execute("ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'security_analyst'")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id TEXT,
            actor_email TEXT,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )"""
    )
    return connection


def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), PASSWORD_ITERATIONS
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_account(email: str, password: str, role: str = ANALYST_ROLE) -> Dict[str, Any]:
    normalized_email = email.strip().lower()
    if len(normalized_email) > 254 or not EMAIL_PATTERN.fullmatch(normalized_email):
        raise ValueError("Enter a valid email address.")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    if len(password) > 1024:
        raise ValueError("Password is too long.")
    if role not in ROLE_PERMISSIONS:
        raise ValueError("Unknown account role.")

    connection = _connect()
    try:
        cursor = connection.execute(
            "INSERT INTO accounts (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (normalized_email, _hash_password(password), role, int(time.time()))
        )
        connection.commit()
        return {"id": str(cursor.lastrowid), "email": normalized_email, "role": role}
    except sqlite3.IntegrityError as error:
        raise ValueError("An account with this email already exists.") from error
    finally:
        connection.close()


def authenticate_account(email: str, password: str) -> Optional[Dict[str, Any]]:
    normalized_email = email.strip().lower()
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT id, email, password_hash, role FROM accounts WHERE email = ?",
            (normalized_email,)
        ).fetchone()
        if row is None or not _verify_password(password, row["password_hash"]):
            return None
        return {
            "id": str(row["id"]),
            "email": row["email"],
            "role": row["role"],
            "permissions": permissions_for_role(row["role"])
        }
    finally:
        connection.close()


def create_session_token(user: Dict[str, Any], secret: str) -> str:
    payload = json.dumps({
        "sub": user["id"],
        "email": user["email"],
        "exp": int(time.time()) + SESSION_TTL_SECONDS
    }, separators=(",", ":")).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{encoded_payload}.{encoded_signature}"


def get_session_user(token: Optional[str], secret: str) -> Optional[Dict[str, Any]]:
    if not token or not secret:
        return None
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected_signature = hmac.new(
            secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
        ).digest()
        padding = "=" * (-len(encoded_signature) % 4)
        supplied_signature = base64.urlsafe_b64decode(encoded_signature + padding)
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return None
        payload_padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload + payload_padding))
        if int(payload.get("exp", 0)) <= int(time.time()):
            return None
        connection = _connect()
        try:
            row = connection.execute(
                "SELECT id, email, role FROM accounts WHERE id = ? AND email = ?",
                (payload.get("sub"), payload.get("email"))
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "email": row["email"],
            "role": row["role"],
            "permissions": permissions_for_role(row["role"])
        }
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def list_accounts() -> list[Dict[str, Any]]:
    connection = _connect()
    try:
        rows = connection.execute(
            "SELECT id, email, role, created_at FROM accounts ORDER BY created_at, id"
        ).fetchall()
        return [
            {"id": str(row["id"]), "email": row["email"], "role": row["role"], "created_at": row["created_at"]}
            for row in rows
        ]
    finally:
        connection.close()


def change_account_role(account_id: str, role: str) -> Dict[str, Any]:
    if role not in ROLE_PERMISSIONS:
        raise ValueError("Unknown account role.")
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT id, email, role, created_at FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Account not found.")
        if row["role"] == ADMIN_ROLE and role != ADMIN_ROLE:
            admin_count = connection.execute(
                "SELECT COUNT(*) FROM accounts WHERE role = ?", (ADMIN_ROLE,)
            ).fetchone()[0]
            if admin_count <= 1:
                raise ValueError("Cannot remove the last administrator.")
        connection.execute("UPDATE accounts SET role = ? WHERE id = ?", (role, account_id))
        connection.commit()
        return {"id": str(row["id"]), "email": row["email"], "role": role, "created_at": row["created_at"]}
    finally:
        connection.close()


def write_audit_event(
    action: str,
    actor: Optional[Dict[str, Any]] = None,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    connection = _connect()
    try:
        connection.execute(
            "INSERT INTO audit_events (actor_id, actor_email, action, target, details, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                actor.get("id") if actor else None,
                actor.get("email") if actor else None,
                action,
                target,
                json.dumps(details or {}, sort_keys=True),
                int(time.time())
            )
        )
        connection.commit()
    finally:
        connection.close()


def list_audit_events(limit: int = 200) -> list[Dict[str, Any]]:
    connection = _connect()
    try:
        rows = connection.execute(
            "SELECT id, actor_id, actor_email, action, target, details, created_at "
            "FROM audit_events ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit), 500)),)
        ).fetchall()
        return [
            {
                "id": row["id"],
                "actor_id": row["actor_id"],
                "actor_email": row["actor_email"],
                "action": row["action"],
                "target": row["target"],
                "details": json.loads(row["details"]),
                "created_at": row["created_at"]
            }
            for row in rows
        ]
    finally:
        connection.close()


def _ensure_configured_account(email: str, password: str, role: str) -> bool:
    if not email or not password:
        raise ValueError(f"Email and password must both be configured for the {role} account.")
    try:
        create_account(email, password, role)
        return True
    except ValueError as error:
        if "already exists" not in str(error):
            raise
    existing = authenticate_account(email, password)
    if existing is None or existing["role"] != role:
        raise ValueError(f"The configured {role} account does not match its stored credentials and role.")
    return True


def bootstrap_configured_accounts() -> None:
    admin_email = os.getenv("NETWATCH_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    admin_password = os.getenv("NETWATCH_BOOTSTRAP_ADMIN_PASSWORD", "")
    if admin_email or admin_password:
        _ensure_configured_account(admin_email, admin_password, ADMIN_ROLE)
    if os.getenv("NETWATCH_ENABLE_DEMO_ACCOUNTS", "false").lower() == "true":
        for role in (ADMIN_ROLE, ANALYST_ROLE):
            prefix = "NETWATCH_DEMO_ADMIN" if role == ADMIN_ROLE else "NETWATCH_DEMO_ANALYST"
            _ensure_configured_account(
                os.getenv(f"{prefix}_EMAIL", "").strip(),
                os.getenv(f"{prefix}_PASSWORD", ""),
                role
            )


def configured_demo_accounts() -> list[Dict[str, str]]:
    if os.getenv("NETWATCH_ENABLE_DEMO_ACCOUNTS", "false").lower() != "true":
        return []
    demo_accounts = []
    for role, title, prefix in (
        (ADMIN_ROLE, "Admin demo", "NETWATCH_DEMO_ADMIN"),
        (ANALYST_ROLE, "Security Analyst demo", "NETWATCH_DEMO_ANALYST")
    ):
        email = os.getenv(f"{prefix}_EMAIL", "").strip()
        password = os.getenv(f"{prefix}_PASSWORD", "")
        account = authenticate_account(email, password) if email and password else None
        if account and account["role"] == role:
            demo_accounts.append({"label": title, "email": email, "password": password, "role": role})
    return demo_accounts
