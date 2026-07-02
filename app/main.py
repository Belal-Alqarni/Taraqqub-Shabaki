import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.advisor import analyze_incident
from app.auth import (
    audit,
    authenticate,
    change_user_password,
    create_user_account,
    create_session,
    destroy_session,
    ensure_admin_user,
    ensure_demo_user,
    get_demo_user,
    get_user_from_request,
    list_user_accounts,
    require_admin,
    require_admin_csrf,
    require_csrf,
    require_operator_csrf,
    require_session_csrf,
    require_session_user,
    require_user,
)
from app.collectors import collect_once, monitor_loop
from app.config import get_settings
from app.database import init_db
from app.discovery import scan_local_network
from app.schemas import (
    DeviceCreate,
    IncidentQuestion,
    LoginRequest,
    PasswordChange,
    UserCreate,
)
from app.services import (
    acknowledge_alert,
    add_device,
    discovery_preview,
    list_alerts,
    list_devices,
    recent_metrics,
    topology,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_admin_user()
    ensure_demo_user()
    collect_once()
    task = asyncio.create_task(monitor_loop())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Taraqqub Shabaki", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if get_settings().app_env == "production" and get_settings().secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/")
def index(request: Request):
    user = get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    if user["must_change_password"]:
        return RedirectResponse(
            "/change-password", status_code=status.HTTP_303_SEE_OTHER
        )
    return FileResponse("app/static/index.html")


@app.get("/login")
def login_page(request: Request):
    user = get_user_from_request(request)
    if user and user["must_change_password"]:
        return RedirectResponse(
            "/change-password", status_code=status.HTTP_303_SEE_OTHER
        )
    if user:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return FileResponse("app/static/login.html")


@app.get("/change-password")
def change_password_page(request: Request):
    user = get_user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    if not user["must_change_password"]:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return FileResponse("app/static/change-password.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "taraqqub-shabaki"}


@app.get("/api/public-config")
def public_config():
    return {"public_demo": get_settings().public_demo}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    user = authenticate(payload.username, payload.password, client_ip)
    if not user:
        audit(None, "login.failed", f"username={payload.username}", request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials."
        )

    csrf_token = create_session(user["id"], response)
    audit(user["id"], "login.success", "Authenticated successfully", request)
    return {
        "username": user["username"],
        "role": user["role"],
        "csrf_token": csrf_token,
        "must_change_password": bool(user["must_change_password"]),
    }


@app.post("/api/auth/demo")
def demo_login(request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    user = get_demo_user(client_ip)
    csrf_token = create_session(user["id"], response)
    audit(user["id"], "demo.login", "Public demo session created", request)
    return {
        "username": user["username"],
        "role": user["role"],
        "csrf_token": csrf_token,
        "must_change_password": False,
    }


@app.get("/api/auth/session")
def auth_session(user: dict = Depends(require_session_user)):
    return {
        "username": user["username"],
        "role": user["role"],
        "csrf_token": user["csrf_token"],
        "must_change_password": bool(user["must_change_password"]),
    }


@app.post("/api/auth/change-password")
def change_password(
    payload: PasswordChange,
    request: Request,
    user: dict = Depends(require_session_csrf),
):
    change_user_password(user, payload.current_password, payload.new_password)
    audit(user["id"], "password.change", "Password changed", request)
    return {"status": "ok"}


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: dict = Depends(require_session_csrf),
):
    audit(user["id"], "logout", "Session ended", request)
    destroy_session(user, response)
    return {"status": "ok"}


@app.get("/api/admin/users")
def users_admin(_user: dict = Depends(require_admin)):
    return list_user_accounts()


@app.post("/api/admin/users", status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    user: dict = Depends(require_admin_csrf),
):
    try:
        account = create_user_account(payload.username, payload.role)
        audit(
            user["id"],
            "user.create",
            f"user_id={account['id']} role={account['role']}",
            request,
        )
        return account
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Username already exists.") from exc


@app.get("/api/devices")
def devices(_user: dict = Depends(require_user)):
    return list_devices()


@app.post("/api/devices", status_code=201)
def create_device(
    payload: DeviceCreate,
    request: Request,
    user: dict = Depends(require_admin_csrf),
):
    try:
        device = add_device(payload)
        audit(user["id"], "device.create", f"device_id={device['id']}", request)
        return device
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/metrics")
def metrics(
    device_id: int | None = None,
    limit: int = 120,
    _user: dict = Depends(require_user),
):
    return recent_metrics(device_id=device_id, limit=limit)


@app.get("/api/alerts")
def alerts(_user: dict = Depends(require_user)):
    return list_alerts()


@app.post("/api/alerts/{alert_id}/ack")
def ack_alert(
    alert_id: int,
    request: Request,
    user: dict = Depends(require_operator_csrf),
):
    result = acknowledge_alert(alert_id)
    audit(user["id"], "alert.acknowledge", f"alert_id={alert_id}", request)
    return result


@app.get("/api/topology")
def get_topology(_user: dict = Depends(require_user)):
    return topology()


@app.post("/api/discovery/preview")
def preview_discovery(_user: dict = Depends(require_admin_csrf)):
    return discovery_preview()


@app.post("/api/discovery/scan")
def live_discovery(
    request: Request,
    user: dict = Depends(require_admin_csrf),
):
    if get_settings().public_demo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Network discovery is disabled in public demo mode.",
        )
    try:
        result = scan_local_network()
        audit(
            user["id"],
            "network.discovery",
            f"network={result['network']} count={result['count']}",
            request,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/advisor/analyze")
def advisor_analyze(
    payload: IncidentQuestion,
    _user: dict = Depends(require_csrf),
):
    return analyze_incident(payload.device_id, payload.symptom)
