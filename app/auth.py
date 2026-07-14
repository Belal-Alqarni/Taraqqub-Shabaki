import base64
import hashlib
import hmac
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from time import monotonic

from fastapi import Depends, HTTPException, Request, Response, status

from app.config import get_settings
from app.database import connect, insert_and_get_id, is_integrity_error


SESSION_COOKIE = "taraqqub_session"
PASSWORD_ITERATIONS = 310_000
LOGIN_WINDOW_SECONDS = 300
LOGIN_ATTEMPT_LIMIT = 10
_login_attempts: dict[str, list[float]] = defaultdict(list)
_demo_attempts: dict[str, list[float]] = defaultdict(list)
_signup_attempts: dict[str, list[float]] = defaultdict(list)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return (
        f"pbkdf2_sha256${PASSWORD_ITERATIONS}$"
        f"{base64.urlsafe_b64encode(salt).decode()}$"
        f"{base64.urlsafe_b64encode(digest).decode()}"
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_value, digest_value = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_value)
        expected = base64.urlsafe_b64decode(digest_value)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_workspace(conn, name: str) -> int:
    return insert_and_get_id(
        conn,
        "INSERT INTO workspaces (name, created_at) VALUES (?, ?)",
        (name.strip()[:80], utc_now().isoformat()),
    )


def ensure_admin_user() -> None:
    settings = get_settings()
    admin_username = settings.admin_username.strip().lower()
    if settings.app_env == "production":
        if (
            not settings.admin_password
            or settings.admin_password == "Taraqqub!2026"
            or len(settings.admin_password) < 12
        ):
            raise RuntimeError(
                "Production requires TARAQQUB_ADMIN_PASSWORD with at least 12 characters."
            )

    with connect() as conn:
        existing = conn.execute(
            "SELECT id, workspace_id, password_hash FROM users WHERE username = ?",
            (admin_username,),
        ).fetchone()
        if not existing:
            workspace_id = create_workspace(conn, "Primary Workspace")
            conn.execute(
                """
                INSERT INTO users (
                    workspace_id, username, password_hash, role, is_active, created_at
                ) VALUES (?, ?, ?, 'admin', 1, ?)
                """,
                (
                    workspace_id,
                    admin_username,
                    hash_password(settings.admin_password),
                    utc_now().isoformat(),
                ),
            )
        else:
            if not existing["workspace_id"]:
                workspace_id = create_workspace(conn, "Primary Workspace")
                conn.execute(
                    "UPDATE users SET workspace_id = ? WHERE id = ?",
                    (workspace_id, existing["id"]),
                )
            if settings.app_env == "production" and not verify_password(
                settings.admin_password, existing["password_hash"]
            ):
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(settings.admin_password), existing["id"]),
                )


def ensure_demo_user() -> None:
    if not get_settings().public_demo:
        return

    with connect() as conn:
        existing = conn.execute(
            "SELECT id, workspace_id FROM users WHERE username = 'demo'"
        ).fetchone()
        if not existing:
            workspace_id = create_workspace(conn, "Public Demo")
            conn.execute(
                """
                INSERT INTO users (
                    workspace_id, username, password_hash, role, is_active,
                    must_change_password, created_at
                ) VALUES (?, 'demo', ?, 'viewer', 1, 0, ?)
                """,
                (
                    workspace_id,
                    hash_password(secrets.token_urlsafe(32)),
                    utc_now().isoformat(),
                ),
            )
        elif not existing["workspace_id"]:
            workspace_id = create_workspace(conn, "Public Demo")
            conn.execute(
                "UPDATE users SET workspace_id = ? WHERE id = ?",
                (workspace_id, existing["id"]),
            )


def check_login_rate_limit(client_ip: str) -> None:
    now = monotonic()
    recent = [
        timestamp
        for timestamp in _login_attempts[client_ip]
        if now - timestamp < LOGIN_WINDOW_SECONDS
    ]
    _login_attempts[client_ip] = recent
    if len(recent) >= LOGIN_ATTEMPT_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
        )


def check_demo_rate_limit(client_ip: str) -> None:
    now = monotonic()
    recent = [
        timestamp
        for timestamp in _demo_attempts[client_ip]
        if now - timestamp < LOGIN_WINDOW_SECONDS
    ]
    if len(recent) >= 30:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many demo sessions. Try again later.",
        )
    recent.append(now)
    _demo_attempts[client_ip] = recent


def check_signup_rate_limit(client_ip: str) -> None:
    now = monotonic()
    recent = [
        timestamp
        for timestamp in _signup_attempts[client_ip]
        if now - timestamp < LOGIN_WINDOW_SECONDS
    ]
    if len(recent) >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many signup attempts. Try again later.",
        )
    recent.append(now)
    _signup_attempts[client_ip] = recent


def get_demo_user(client_ip: str) -> dict:
    if not get_settings().public_demo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    check_demo_rate_limit(client_ip)
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = 'demo' AND is_active = 1"
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Demo account is unavailable.",
        )
    return dict(row)


def authenticate(username: str, password: str, client_ip: str) -> dict | None:
    check_login_rate_limit(client_ip)
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username.strip().lower(),),
        ).fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        _login_attempts[client_ip].append(monotonic())
        return None

    _login_attempts.pop(client_ip, None)
    return dict(row)


def create_session(user_id: int, response: Response) -> str:
    settings = get_settings()
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = utc_now() + timedelta(hours=settings.session_hours)

    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (utc_now().isoformat(),))
        conn.execute(
            """
            INSERT INTO sessions (user_id, token_hash, csrf_token, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                token_hash(session_token),
                csrf_token,
                expires_at.isoformat(),
                utc_now().isoformat(),
            ),
        )

    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/",
    )
    return csrf_token


def get_user_from_request(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None

    with connect() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, u.must_change_password,
                   u.workspace_id, s.id AS session_id, s.csrf_token
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1
            """,
            (token_hash(token), utc_now().isoformat()),
        ).fetchone()
    return dict(row) if row else None


def require_session_user(request: Request) -> dict:
    user = get_user_from_request(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required."
        )
    return user


def require_user(user: dict = Depends(require_session_user)) -> dict:
    if user["must_change_password"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required.",
        )
    return user


def validate_csrf(request: Request, user: dict) -> dict:
    supplied = request.headers.get("X-CSRF-Token", "")
    if not supplied or not hmac.compare_digest(supplied, user["csrf_token"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token."
        )
    return user


def require_session_csrf(
    request: Request, user: dict = Depends(require_session_user)
) -> dict:
    return validate_csrf(request, user)


def require_csrf(
    request: Request, user: dict = Depends(require_user)
) -> dict:
    return validate_csrf(request, user)


def require_admin(user: dict = Depends(require_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required."
        )
    return user


def require_admin_csrf(user: dict = Depends(require_csrf)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required."
        )
    return user


def require_operator_csrf(user: dict = Depends(require_csrf)) -> dict:
    if user["role"] not in {"operator", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator or administrator role required.",
        )
    return user


def list_user_accounts(workspace_id: int) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, username, role, is_active, must_change_password, created_at
            FROM users
            WHERE workspace_id = ?
            ORDER BY id
            """,
            (workspace_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_user_account(username: str, role: str, workspace_id: int) -> dict:
    temporary_password = secrets.token_urlsafe(14)
    normalized_username = username.strip().lower()
    with connect() as conn:
        user_id = insert_and_get_id(
            conn,
            """
            INSERT INTO users (
                workspace_id, username, password_hash, role, is_active,
                must_change_password, created_at
            ) VALUES (?, ?, ?, ?, 1, 1, ?)
            """,
            (
                workspace_id,
                normalized_username,
                hash_password(temporary_password),
                role,
                utc_now().isoformat(),
            ),
        )
        row = conn.execute(
            """
            SELECT id, username, role, is_active, must_change_password, created_at
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    result = dict(row)
    result["temporary_password"] = temporary_password
    return result


def create_signup_account(
    username: str, password: str, workspace_name: str, client_ip: str
) -> dict:
    if not get_settings().allow_signup:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    check_signup_rate_limit(client_ip)
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least 12 characters.",
        )

    normalized_username = username.strip().lower()
    try:
        with connect() as conn:
            workspace_id = create_workspace(conn, workspace_name)
            user_id = insert_and_get_id(
                conn,
                """
                INSERT INTO users (
                    workspace_id, username, password_hash, role, is_active,
                    must_change_password, created_at
                ) VALUES (?, ?, ?, 'admin', 1, 0, ?)
                """,
                (
                    workspace_id,
                    normalized_username,
                    hash_password(password),
                    utc_now().isoformat(),
                ),
            )
            return {
                "id": user_id,
                "workspace_id": workspace_id,
                "username": normalized_username,
                "role": "admin",
                "must_change_password": False,
            }
    except Exception as exc:
        if not is_integrity_error(exc):
            raise
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists.",
        ) from exc


def change_user_password(
    user: dict, current_password: str, new_password: str
) -> None:
    if len(new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must contain at least 12 characters.",
        )
    if hmac.compare_digest(current_password, new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different.",
        )

    with connect() as conn:
        account = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if not account or not verify_password(current_password, account["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect.",
            )
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, must_change_password = 0
            WHERE id = ?
            """,
            (hash_password(new_password), user["id"]),
        )
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND id != ?",
            (user["id"], user["session_id"]),
        )


def destroy_session(user: dict, response: Response) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE id = ?", (user["session_id"],))
    response.delete_cookie(SESSION_COOKIE, path="/")


def audit(user_id: int | None, action: str, details: str, request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (user_id, action, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, action, details, client_ip, utc_now().isoformat()),
        )
