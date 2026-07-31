import hashlib
import hmac
import json
import re
import secrets
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.db import add_history, get_conn, init_db
from backend import mail_service
from backend.services import jobs, locks

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"
CONFIG_PATH = ROOT / "config.json"
LOG_PATH = ROOT / "logs" / "app.log"
TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName"
GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/messages?$top=1&$select=id,subject,receivedDateTime"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
HTTP_TIMEOUT = 30
AUTH_COOKIE = "outlook_manage_session"
AUTH_SESSION_MAX_AGE = 12 * 60 * 60
MAX_CONCURRENCY = 20
ABUSE_HINTS = ("service abuse", "abuse mode", "account is locked", "account has been locked")
TOKEN_INVALID_HINTS = (
    "aadsts70000",
    "aadsts700082",
    "aadsts700084",
    "invalid_grant",
    "refresh token has expired",
    "refresh token is invalid",
)


def now_local() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")


CONFIG = load_config()
_CONFIG_LOCK = threading.RLock()
_LOG_LOCK = threading.Lock()
_AUTH_LOCK = threading.Lock()
_AUTH_SESSIONS: set[str] = set()
DB_PATH = ROOT / CONFIG["database"]["path"]
init_db(DB_PATH)
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def normalize_legacy_statuses() -> None:
    timestamp = now_local()
    with get_conn(DB_PATH) as conn:
        conn.execute(
            """UPDATE accounts SET health_status='normal',health_severity='ok',status='alive',updated_at=?
               WHERE graph_status='ok' AND COALESCE(health_status,'') NOT IN ('banned')""",
            (timestamp,),
        )
        conn.commit()


normalize_legacy_statuses()


def get_config() -> dict[str, Any]:
    with _CONFIG_LOCK:
        return CONFIG


def proxy_url() -> str:
    return str((get_config().get("proxy") or {}).get("url") or "").strip()


def clamp_concurrency(value: Any, default: int = 5) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_CONCURRENCY, number))


def log_event(stage: str, message: str, level: str = "INFO") -> None:
    line = f"[{stage}][{level}] {datetime.now().strftime('%H:%M:%S')} | {message}"
    with _LOG_LOCK:
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    print(line)


def hash_admin_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def verify_admin_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_hex, expected_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(actual, bytes.fromhex(expected_hex))
    except (TypeError, ValueError):
        return False


def admin_password_hash() -> str:
    return str((get_config().get("auth") or {}).get("password_hash") or "")


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def global_api_key_hash() -> str:
    api_config = get_config().get("api") or {}
    key = str(api_config.get("key") or "")
    return secret_hash(key) if key else str(api_config.get("key_hash") or "")


def request_api_key(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.query_params.get("api_key", "").strip()


def require_global_api_key(request: Request) -> None:
    supplied, expected = request_api_key(request), global_api_key_hash()
    if not supplied or not expected or not hmac.compare_digest(secret_hash(supplied), expected):
        raise HTTPException(401, "API Key 无效")


def share_active(row: Any) -> bool:
    if not row or not row["enabled"]:
        return False
    expires_at = str(row["expires_at"] or "")
    return not expires_at or datetime.fromisoformat(expires_at) > datetime.now().astimezone()


def get_share_by_page_token(page_token: str):
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT s.*,a.email FROM otp_shares s JOIN accounts a ON a.id=s.account_id WHERE s.page_token=?", (page_token,)).fetchone()
    if not share_active(row):
        raise HTTPException(404, "分享不存在、已停用或已过期")
    return row


def get_share_by_api_key(request: Request):
    supplied = request_api_key(request)
    if not supplied:
        raise HTTPException(401, "分享 API Key 无效")
    supplied_hash = secret_hash(supplied)
    with get_conn(DB_PATH) as conn:
        rows = conn.execute("SELECT s.*,a.email FROM otp_shares s JOIN accounts a ON a.id=s.account_id WHERE s.enabled=1").fetchall()
    row = next((item for item in rows if hmac.compare_digest(str(item["api_key_hash"]), supplied_hash)), None)
    if not share_active(row):
        raise HTTPException(401, "分享 API Key 无效、已停用或已过期")
    return row


def resolve_mail_account(value: str) -> dict[str, Any]:
    raw = value.strip()
    if not raw:
        raise HTTPException(400, "请输入邮箱或完整四段账号信息")
    if "----" in raw:
        try:
            account = parse_account_line(raw)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not account["email"] or account["email"].endswith("@local.invalid"):
            raise HTTPException(400, "临时读取必须提供邮箱四段格式")
        return {**account, "id": None, "temporary": True}
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE lower(email)=lower(?)", (raw,)).fetchone()
    if not row:
        raise HTTPException(404, "账号池中没有该邮箱")
    return {**dict(row), "temporary": False}


def mail_account_by_id(account_id: int) -> dict[str, Any]:
    return {**dict(fetch_account(account_id)), "temporary": False}


def open_mailbox(account: dict[str, Any]):
    try:
        session, _, new_refresh = mail_service.graph_session(account["client_id"], account["refresh_token"], proxy_url())
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    if account.get("id") and new_refresh != account["refresh_token"]:
        with get_conn(DB_PATH) as conn:
            conn.execute("UPDATE accounts SET refresh_token=?,refresh_token_updated_at=?,updated_at=? WHERE id=?", (new_refresh, now_local(), now_local(), account["id"]))
            conn.commit()
    return session


def otp_result(account: dict[str, Any]) -> dict[str, Any]:
    session = open_mailbox(account)
    try:
        messages = mail_service.list_messages(session, 1)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    if not messages:
        raise HTTPException(404, "收件箱和垃圾邮件中没有邮件")
    message = messages[0]
    code = mail_service.extract_otp(message)
    if not code:
        raise HTTPException(404, "最新一封邮件未找到 OTP，邮件可能尚未收到或同步")
    return {"otp": {"mailbox_id": account.get("id"), "full_address": account["email"], "email_id": message["id"], "code": code, "subject": message["subject"], "sender": message["sender"], "received_at": message["received_at"]}}


def expiry_from_days(days: int) -> str:
    if days < 0:
        raise HTTPException(400, "有效期不能小于 0")
    return "" if days == 0 else (datetime.now().astimezone() + timedelta(days=days)).isoformat(timespec="seconds")


def safe_filename(value: str) -> str:
    cleaned = re.sub(r'[\\/\r\n"]+', "_", value).strip()
    return cleaned.encode("ascii", "ignore").decode().strip() or "attachment"


def is_authenticated(request: Request) -> bool:
    token = request.cookies.get(AUTH_COOKIE, "")
    with _AUTH_LOCK:
        return bool(token and token in _AUTH_SESSIONS)


def placeholder_email(client_id: str, refresh_token: str) -> str:
    digest = hashlib.sha256(f"{client_id}:{refresh_token}".encode()).hexdigest()[:20]
    return f"pending-{digest}@local.invalid"


def parse_account_line(line: str) -> dict[str, str]:
    parts = [part.strip() for part in line.strip().split("----")]
    if len(parts) >= 4:
        email, password, client_id, refresh_token = parts[:4]
    elif len(parts) == 3 and "@" in parts[0]:
        email, client_id, refresh_token = parts
        password = ""
    elif len(parts) == 2:
        client_id, refresh_token = parts
        email = placeholder_email(client_id, refresh_token)
        password = ""
    else:
        raise ValueError("格式应为 client_id----refresh_token 或 邮箱----密码----client_id----refresh_token")
    if not client_id or not refresh_token:
        raise ValueError("client_id 和 refresh_token 不能为空")
    return {"email": email, "password": password, "client_id": client_id, "refresh_token": refresh_token}


def parse_accounts(text: str) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    accounts = []
    errors = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            accounts.append(parse_account_line(raw))
        except ValueError as exc:
            errors.append({"line": number, "reason": str(exc)})
    return accounts, errors


def response_text(response: requests.Response, data: Any = None) -> str:
    if data is None:
        try:
            data = response.json()
        except ValueError:
            data = response.text
    return json.dumps(data, ensure_ascii=False) if isinstance(data, (dict, list)) else str(data)


def classify_failure(text: str) -> tuple[str, str, str]:
    lower = text.lower()
    if any(hint in lower for hint in ABUSE_HINTS):
        return "banned", "banned", "微软返回 service abuse/账号锁定"
    if any(hint in lower for hint in TOKEN_INVALID_HINTS):
        return "token_invalid", "fail", text[:1000]
    return "other_error", "fail", text[:1000]


def graph_check(client_id: str, refresh_token: str, proxy: str = "") -> dict[str, Any]:
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    token_response = session.post(
        TOKEN_URL,
        data={
            "client_id": client_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": GRAPH_SCOPE,
        },
        timeout=HTTP_TIMEOUT,
    )
    try:
        token_data = token_response.json()
    except ValueError:
        token_data = {}
    access_token = token_data.get("access_token")
    if not access_token:
        raw = response_text(token_response, token_data or token_response.text)
        status, severity, reason = classify_failure(raw)
        return {"success": False, "health_status": status, "severity": severity, "reason": reason}

    headers = {"Authorization": f"Bearer {access_token}"}
    me_response = session.get(GRAPH_ME_URL, headers=headers, timeout=HTTP_TIMEOUT)
    if not me_response.ok:
        raw = response_text(me_response)
        status, severity, reason = classify_failure(raw)
        return {"success": False, "health_status": status, "severity": severity, "reason": reason}
    me = me_response.json()

    messages_response = session.get(GRAPH_MESSAGES_URL, headers=headers, timeout=HTTP_TIMEOUT)
    if not messages_response.ok:
        raw = response_text(messages_response)
        status, severity, reason = classify_failure(raw)
        return {"success": False, "health_status": status, "severity": severity, "reason": reason}
    messages = messages_response.json().get("value") or []
    return {
        "success": True,
        "health_status": "normal",
        "severity": "ok",
        "reason": "Graph 登录及邮件读取正常",
        "email": str(me.get("mail") or me.get("userPrincipalName") or "").strip(),
        "refresh_token": str(token_data.get("refresh_token") or refresh_token),
        "message_count": len(messages),
    }


def fetch_account(account_id: int):
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        raise HTTPException(404, "账号不存在")
    return row


def test_account(account_id: int) -> dict[str, Any]:
    row = fetch_account(account_id)
    if not locks.try_acquire(account_id):
        return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "账号正在测试"}
    try:
        log_event("GRAPH", f"开始测试 {row['email']}")
        try:
            result = graph_check(row["client_id"], row["refresh_token"], proxy_url())
        except requests.RequestException as exc:
            result = {"success": False, "health_status": "other_error", "severity": "fail", "reason": str(exc)}
        timestamp = now_local()
        email = result.get("email") or row["email"]
        new_refresh = result.get("refresh_token") or row["refresh_token"]
        graph_status = "ok" if result["success"] else "fail"
        with get_conn(DB_PATH) as conn:
            if email != row["email"]:
                exists = conn.execute("SELECT id FROM accounts WHERE email=? AND id<>?", (email, account_id)).fetchone()
                if exists:
                    email = row["email"]
            conn.execute(
                """
                UPDATE accounts SET email=?, refresh_token=?, status=?, health_status=?, health_severity=?,
                    ban_reason=?, error_detail=?, graph_status=?, imap_status='', pop_status='', smtp_status='',
                    last_alive_at=?, last_refresh_at=?, last_refresh_status=?, last_refresh_error='',
                    refresh_token_updated_at=?, last_protocol_test_at=?, updated_at=? WHERE id=?
                """,
                (
                    email,
                    new_refresh,
                    "alive" if result["success"] else "failed",
                    result["health_status"],
                    result["severity"],
                    result["reason"] if result["health_status"] == "banned" else "",
                    "" if result["success"] or result["health_status"] == "banned" else result["reason"],
                    graph_status,
                    timestamp if result["success"] else row["last_alive_at"],
                    timestamp,
                    "ok" if result["success"] else "fail",
                    timestamp if new_refresh != row["refresh_token"] else row["refresh_token_updated_at"],
                    timestamp,
                    timestamp,
                    account_id,
                ),
            )
            add_history(conn, account_id, email, "graph_check", "ok" if result["success"] else "fail", result["reason"], timestamp)
            conn.commit()
        log_event("GRAPH", f"测试完成 {email} | {result['health_status']}", "INFO" if result["success"] else "WARN")
        return {
            "status": "ok" if result["success"] else "fail",
            "account_id": account_id,
            "email": email,
            "health_status": result["health_status"],
            "reason": result["reason"],
        }
    finally:
        locks.release(account_id)


class LoginPayload(BaseModel):
    password: str


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str


class ImportPayload(BaseModel):
    text: str


class BatchPayload(BaseModel):
    ids: list[int] | None = None
    concurrency: int | None = None


class AccountPayload(BaseModel):
    email: str | None = None
    client_id: str | None = None
    refresh_token: str | None = None
    remark: str | None = None


class ConfigPayload(BaseModel):
    proxy_url: str | None = None
    default_concurrency: int | None = None
    api_key: str | None = None


class MailPayload(BaseModel):
    account: str


class SharePayload(BaseModel):
    account_id: int
    expires_days: int = 0
    api_key: str | None = None


class ShareUpdatePayload(BaseModel):
    enabled: bool | None = None
    expires_days: int | None = None
    api_key: str | None = None
    regenerate_page_token: bool = False


app = FastAPI(title="Outlook Graph Checker")
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="assets")


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    public_api = path.startswith("/api/mailboxes/") or path.startswith("/api/otp-share/")
    if path in {"/login", "/api/auth/login"} or path.startswith("/assets/") or path.startswith("/otp-share/") or public_api:
        response = await call_next(request)
    elif is_authenticated(request):
        response = await call_next(request)
    elif path.startswith("/api/"):
        response = JSONResponse({"detail": "请先登录"}, status_code=401)
    else:
        response = RedirectResponse("/login", status_code=303)
    if path in {"/", "/login"} or path.startswith("/assets/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/login")
def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse("/", status_code=303)
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/otp-share/{page_token}")
def share_page(page_token: str):
    get_share_by_page_token(page_token)
    return FileResponse(FRONTEND_DIR / "share.html")


@app.post("/api/auth/login")
def login(payload: LoginPayload, request: Request):
    if not verify_admin_password(payload.password, admin_password_hash()):
        raise HTTPException(401, "密码错误")
    token = secrets.token_urlsafe(32)
    with _AUTH_LOCK:
        _AUTH_SESSIONS.add(token)
    response = JSONResponse({"success": True})
    response.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=AUTH_SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https",
    )
    return response


@app.post("/api/auth/logout")
def logout(request: Request):
    with _AUTH_LOCK:
        _AUTH_SESSIONS.discard(request.cookies.get(AUTH_COOKIE, ""))
    response = JSONResponse({"success": True})
    response.delete_cookie(AUTH_COOKIE)
    return response


@app.put("/api/auth/password")
def change_password(payload: ChangePasswordPayload):
    global CONFIG
    if not verify_admin_password(payload.current_password, admin_password_hash()):
        raise HTTPException(400, "当前密码错误")
    if len(payload.new_password) < 12:
        raise HTTPException(400, "新密码至少需要 12 位")
    with _CONFIG_LOCK:
        config = load_config()
        config.setdefault("auth", {})["password_hash"] = hash_admin_password(payload.new_password)
        save_config(config)
        CONFIG = config
    with _AUTH_LOCK:
        _AUTH_SESSIONS.clear()
    response = JSONResponse({"success": True})
    response.delete_cookie(AUTH_COOKIE)
    return response


@app.get("/api/status")
def status():
    with get_conn(DB_PATH) as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])
        counts = {
            key: int(conn.execute("SELECT COUNT(*) FROM accounts WHERE health_status=?", (key,)).fetchone()[0])
            for key in ("normal", "banned", "token_invalid", "other_error")
        }
        untested = int(conn.execute("SELECT COUNT(*) FROM accounts WHERE COALESCE(health_status,'')='' ").fetchone()[0])
    return {"success": True, "summary": {"total": total, **counts, "untested": untested}}


@app.get("/api/accounts")
def accounts():
    with get_conn(DB_PATH) as conn:
        rows = [dict(row) for row in conn.execute(
            """
            SELECT id,email,client_id,status,health_status,health_severity,ban_reason,error_detail,
                   graph_status,last_alive_at,last_protocol_test_at,remark,created_at,updated_at
            FROM accounts ORDER BY id DESC
            """
        ).fetchall()]
    return {"success": True, "accounts": rows}


@app.get("/api/accounts/{account_id}")
def account_detail(account_id: int):
    row = dict(fetch_account(account_id))
    with get_conn(DB_PATH) as conn:
        history = [dict(item) for item in conn.execute("SELECT * FROM history WHERE account_id=? ORDER BY id DESC LIMIT 20", (account_id,)).fetchall()]
    return {"success": True, "account": row, "history": history}


@app.post("/api/accounts/import-preview")
def import_preview(payload: ImportPayload):
    accounts, errors = parse_accounts(payload.text)
    return {"success": True, "valid": len(accounts), "errors": errors, "preview": accounts[:20]}


@app.post("/api/accounts/import")
def import_accounts(payload: ImportPayload):
    accounts, errors = parse_accounts(payload.text)
    if not accounts:
        raise HTTPException(400, "没有可导入的账号")
    inserted = updated = 0
    timestamp = now_local()
    with get_conn(DB_PATH) as conn:
        for item in accounts:
            existing = conn.execute("SELECT id FROM accounts WHERE email=?", (item["email"],)).fetchone()
            if not existing and item["email"].endswith("@local.invalid"):
                existing = conn.execute("SELECT id FROM accounts WHERE client_id=? AND refresh_token=?", (item["client_id"], item["refresh_token"])).fetchone()
            if existing:
                conn.execute(
                    """UPDATE accounts SET password=?,client_id=?,refresh_token=?,status='new',health_status='',
                       health_severity='',ban_reason='',error_detail='',graph_status='',last_protocol_test_at='',updated_at=? WHERE id=?""",
                    (item["password"], item["client_id"], item["refresh_token"], timestamp, existing["id"]),
                )
                updated += 1
            else:
                conn.execute(
                    """INSERT INTO accounts (email,password,client_id,refresh_token,status,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (item["email"], item["password"], item["client_id"], item["refresh_token"], "new", timestamp, timestamp),
                )
                inserted += 1
        conn.commit()
    log_event("IMPORT", f"导入完成 | 新增 {inserted} | 更新 {updated} | 错误 {len(errors)}")
    return {"success": True, "inserted": inserted, "updated": updated, "errors": errors}


@app.put("/api/accounts/{account_id}")
def edit_account(account_id: int, payload: AccountPayload):
    row = fetch_account(account_id)
    values = {
        "email": payload.email.strip() if payload.email is not None else row["email"],
        "client_id": payload.client_id.strip() if payload.client_id is not None else row["client_id"],
        "refresh_token": payload.refresh_token.strip() if payload.refresh_token is not None else row["refresh_token"],
        "remark": payload.remark.strip() if payload.remark is not None else row["remark"],
    }
    if not values["email"] or not values["client_id"] or not values["refresh_token"]:
        raise HTTPException(400, "邮箱、client_id 和 refresh_token 不能为空")
    try:
        with get_conn(DB_PATH) as conn:
            conn.execute(
                """UPDATE accounts SET email=?,client_id=?,refresh_token=?,remark=?,health_status='',health_severity='',
                   ban_reason='',error_detail='',graph_status='',last_protocol_test_at='',status='new',updated_at=? WHERE id=?""",
                (*values.values(), now_local(), account_id),
            )
            conn.commit()
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            raise HTTPException(400, "邮箱已存在") from exc
        raise
    return {"success": True}


@app.delete("/api/accounts/{account_id}")
def delete_account(account_id: int):
    row = fetch_account(account_id)
    with get_conn(DB_PATH) as conn:
        conn.execute("DELETE FROM history WHERE account_id=?", (account_id,))
        conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        conn.commit()
    log_event("ACCOUNT", f"删除账号 {row['email']}")
    return {"success": True}


@app.post("/api/accounts/{account_id}/test")
def test_one(account_id: int):
    result = test_account(account_id)
    return JSONResponse({"success": result["status"] == "ok", **result}, status_code=200 if result["status"] != "skip" else 409)


@app.post("/api/accounts/batch/test-untested")
def test_untested(payload: BatchPayload):
    with get_conn(DB_PATH) as conn:
        ids = [int(row["id"]) for row in conn.execute("SELECT id FROM accounts WHERE COALESCE(health_status,'')='' ORDER BY id").fetchall()]
    if not ids:
        raise HTTPException(400, "没有未测试账号")
    concurrency = clamp_concurrency(payload.concurrency, (get_config().get("ui") or {}).get("default_concurrency", 5))
    job_id = jobs.submit("graph-check", ids, test_account, max_workers=concurrency)
    log_event("BATCH", f"一键测试未测试 {len(ids)} 个账号 | 并发={concurrency} | job={job_id}")
    return {"success": True, "job_id": job_id, "total": len(ids), "concurrency": concurrency}


@app.post("/api/accounts/test-selected")
def test_selected(payload: BatchPayload):
    ids = list(dict.fromkeys(int(account_id) for account_id in (payload.ids or []) if int(account_id) > 0))
    if not ids:
        raise HTTPException(400, "请先选择账号")
    marks = ",".join("?" for _ in ids)
    with get_conn(DB_PATH) as conn:
        existing_ids = [int(row["id"]) for row in conn.execute(
            f"SELECT id FROM accounts WHERE id IN ({marks}) ORDER BY id", ids
        ).fetchall()]
    if not existing_ids:
        raise HTTPException(400, "所选账号不存在")
    concurrency = clamp_concurrency(payload.concurrency, (get_config().get("ui") or {}).get("default_concurrency", 5))
    job_id = jobs.submit("graph-check", existing_ids, test_account, max_workers=concurrency)
    log_event("BATCH", f"批量测试已选 {len(existing_ids)} 个账号 | 并发={concurrency} | job={job_id}")
    return {"success": True, "job_id": job_id, "total": len(existing_ids), "concurrency": concurrency}


@app.post("/api/accounts/delete-selected")
def delete_selected(payload: BatchPayload):
    ids = list(dict.fromkeys(int(account_id) for account_id in (payload.ids or []) if int(account_id) > 0))
    if not ids:
        raise HTTPException(400, "请先选择账号")
    marks = ",".join("?" for _ in ids)
    with get_conn(DB_PATH) as conn:
        existing_ids = [int(row["id"]) for row in conn.execute(
            f"SELECT id FROM accounts WHERE id IN ({marks})", ids
        ).fetchall()]
        if existing_ids:
            existing_marks = ",".join("?" for _ in existing_ids)
            conn.execute(f"DELETE FROM history WHERE account_id IN ({existing_marks})", existing_ids)
            conn.execute(f"DELETE FROM accounts WHERE id IN ({existing_marks})", existing_ids)
            conn.commit()
    log_event("ACCOUNT", f"批量删除账号 {len(existing_ids)} 个")
    return {"success": True, "deleted": len(existing_ids)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = jobs.get_job(job_id)
    if not job:
        raise HTTPException(404, "任务不存在")
    return {"success": True, "job": job}


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    if not jobs.cancel(job_id):
        raise HTTPException(404, "任务不存在或已经结束")
    return {"success": True}


@app.get("/api/config")
def get_config_api():
    config = get_config()
    return {"success": True, "config": {
        "proxy_url": str((config.get("proxy") or {}).get("url") or ""),
        "default_concurrency": int((config.get("ui") or {}).get("default_concurrency", 5)),
        "api_key_configured": bool((config.get("api") or {}).get("key") or (config.get("api") or {}).get("key_hash")),
        "api_key": str((config.get("api") or {}).get("key") or ""),
    }}


@app.put("/api/config")
def put_config(payload: ConfigPayload):
    global CONFIG
    with _CONFIG_LOCK:
        config = load_config()
        if payload.proxy_url is not None:
            config.setdefault("proxy", {})["url"] = payload.proxy_url.strip()
        if payload.default_concurrency is not None:
            config.setdefault("ui", {})["default_concurrency"] = clamp_concurrency(payload.default_concurrency)
        if payload.api_key is not None:
            if len(payload.api_key.strip()) < 24:
                raise HTTPException(400, "API Key 至少需要 24 位")
            config.setdefault("api", {})["key"] = payload.api_key.strip()
            config["api"]["key_hash"] = secret_hash(payload.api_key.strip())
        save_config(config)
        CONFIG = config
    log_event("CONFIG", "配置已更新")
    return {"success": True}


@app.post("/api/mail/otp")
def admin_mail_otp(payload: MailPayload):
    return {"success": True, **otp_result(resolve_mail_account(payload.account))}


@app.post("/api/mail/messages")
def admin_mail_messages(payload: MailPayload):
    account = resolve_mail_account(payload.account)
    try:
        messages = mail_service.list_messages(open_mailbox(account), 5)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"success": True, "mailbox": {"id": account.get("id"), "full_address": account["email"]}, "emails": messages}


@app.post("/api/mail/messages/{message_id}/detail")
def admin_mail_detail(message_id: str, payload: MailPayload):
    account = resolve_mail_account(payload.account)
    try:
        message = mail_service.get_message(open_mailbox(account), message_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"success": True, "email": message}


@app.post("/api/mail/messages/{message_id}/otp")
def admin_message_otp(message_id: str, payload: MailPayload):
    account = resolve_mail_account(payload.account)
    try:
        message = mail_service.get_message(open_mailbox(account), message_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    code = mail_service.extract_otp(message)
    if not code:
        raise HTTPException(404, "该邮件未找到 OTP")
    return {"success": True, "otp": {"code": code, "email_id": message_id, "subject": message["subject"]}}


@app.post("/api/mail/messages/{message_id}/attachments/{attachment_id}")
def admin_attachment(message_id: str, attachment_id: str, payload: MailPayload):
    account = resolve_mail_account(payload.account)
    try:
        content, filename, content_type = mail_service.download_attachment(open_mailbox(account), message_id, attachment_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return Response(content, media_type=content_type, headers={"Content-Disposition": f'attachment; filename="{safe_filename(filename)}"', "X-Content-Type-Options": "nosniff"})


@app.get("/api/mailboxes/lookup")
def api_mailbox_lookup(address: str, request: Request):
    require_global_api_key(request)
    if "----" in address:
        raise HTTPException(400, "API 仅支持查询账号池已有邮箱")
    account = resolve_mail_account(address)
    return {"mailbox": {"id": account["id"], "full_address": account["email"]}}


@app.get("/api/mailboxes/{account_id}/otp/latest")
def api_mailbox_latest_otp(account_id: int, request: Request, format: str = "json"):
    require_global_api_key(request)
    result = otp_result(mail_account_by_id(account_id))
    return PlainTextResponse(result["otp"]["code"]) if format == "text" else result


def share_account(row: Any) -> dict[str, Any]:
    return mail_account_by_id(int(row["account_id"]))


@app.get("/api/otp-share/latest")
def api_share_latest(request: Request, format: str = "json"):
    result = otp_result(share_account(get_share_by_api_key(request)))
    return PlainTextResponse(result["otp"]["code"]) if format == "text" else result


@app.get("/api/otp-share/emails")
def api_share_emails(request: Request):
    account = share_account(get_share_by_api_key(request))
    try:
        emails = mail_service.list_messages(open_mailbox(account), 5)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"emails": emails}


@app.get("/api/otp-share/emails/{message_id}")
def api_share_email_detail(message_id: str, request: Request):
    account = share_account(get_share_by_api_key(request))
    try:
        return {"email": mail_service.get_message(open_mailbox(account), message_id)}
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/otp-share/emails/{message_id}/otp")
def api_share_email_otp(message_id: str, request: Request):
    account = share_account(get_share_by_api_key(request))
    try:
        message = mail_service.get_message(open_mailbox(account), message_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    code = mail_service.extract_otp(message)
    if not code:
        raise HTTPException(404, "该邮件未找到 OTP")
    return {"otp": {"code": code, "email_id": message_id}}


@app.get("/api/otp-share/emails/{message_id}/attachments/{attachment_id}")
def api_share_attachment(message_id: str, attachment_id: str, request: Request):
    account = share_account(get_share_by_api_key(request))
    try:
        content, filename, content_type = mail_service.download_attachment(open_mailbox(account), message_id, attachment_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return Response(content, media_type=content_type, headers={"Content-Disposition": f'attachment; filename="{safe_filename(filename)}"', "X-Content-Type-Options": "nosniff"})


@app.get("/api/otp-share/page/{page_token}/mailbox")
def page_mailbox(page_token: str):
    row = get_share_by_page_token(page_token)
    return {"mailbox": {"full_address": row["email"]}, "expires_at": row["expires_at"]}


@app.get("/api/otp-share/page/{page_token}/latest")
def page_latest(page_token: str):
    return otp_result(share_account(get_share_by_page_token(page_token)))


@app.get("/api/otp-share/page/{page_token}/emails")
def page_emails(page_token: str):
    account = share_account(get_share_by_page_token(page_token))
    try:
        emails = mail_service.list_messages(open_mailbox(account), 5)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"emails": emails}


@app.get("/api/otp-share/page/{page_token}/emails/{message_id}")
def page_email_detail(page_token: str, message_id: str):
    account = share_account(get_share_by_page_token(page_token))
    try:
        return {"email": mail_service.get_message(open_mailbox(account), message_id)}
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/otp-share/page/{page_token}/emails/{message_id}/otp")
def page_email_otp(page_token: str, message_id: str):
    account = share_account(get_share_by_page_token(page_token))
    try:
        message = mail_service.get_message(open_mailbox(account), message_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    code = mail_service.extract_otp(message)
    if not code:
        raise HTTPException(404, "该邮件未找到 OTP")
    return {"otp": {"code": code, "email_id": message_id}}


@app.get("/api/otp-share/page/{page_token}/emails/{message_id}/attachments/{attachment_id}")
def page_attachment(page_token: str, message_id: str, attachment_id: str):
    account = share_account(get_share_by_page_token(page_token))
    try:
        content, filename, content_type = mail_service.download_attachment(open_mailbox(account), message_id, attachment_id)
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(502, str(exc)) from exc
    return Response(content, media_type=content_type, headers={"Content-Disposition": f'attachment; filename="{safe_filename(filename)}"', "X-Content-Type-Options": "nosniff"})


@app.get("/api/shares")
def list_shares():
    with get_conn(DB_PATH) as conn:
        rows = conn.execute("SELECT s.*,a.email FROM otp_shares s JOIN accounts a ON a.id=s.account_id ORDER BY s.id DESC").fetchall()
    return {"success": True, "shares": [{
        "id": row["id"], "account_id": row["account_id"], "email": row["email"], "enabled": bool(row["enabled"]),
        "expires_at": row["expires_at"], "created_at": row["created_at"], "page_url": f"/otp-share/{row['page_token']}",
        "otp_api": "/api/otp-share/latest", "emails_api": "/api/otp-share/emails",
        "detail_api": "/api/otp-share/emails/{message_id}", "email_otp_api": "/api/otp-share/emails/{message_id}/otp",
        "attachment_api": "/api/otp-share/emails/{message_id}/attachments/{attachment_id}",
    } for row in rows]}


@app.post("/api/shares")
def create_share(payload: SharePayload):
    fetch_account(payload.account_id)
    api_key = (payload.api_key or secrets.token_urlsafe(32)).strip()
    if len(api_key) < 24:
        raise HTTPException(400, "分享 API Key 至少需要 24 位")
    token, timestamp = secrets.token_urlsafe(32), now_local()
    try:
        with get_conn(DB_PATH) as conn:
            cursor = conn.execute("INSERT INTO otp_shares(account_id,page_token,api_key_hash,enabled,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (payload.account_id, token, secret_hash(api_key), 1, expiry_from_days(payload.expires_days), timestamp, timestamp))
            conn.commit()
    except Exception as exc:
        if "UNIQUE constraint" in str(exc):
            raise HTTPException(400, "该邮箱已经设置分享") from exc
        raise
    return {"success": True, "id": cursor.lastrowid, "page_url": f"/otp-share/{token}", "api_key": api_key}


@app.put("/api/shares/{share_id}")
def update_share(share_id: int, payload: ShareUpdatePayload):
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM otp_shares WHERE id=?", (share_id,)).fetchone()
        if not row:
            raise HTTPException(404, "分享不存在")
        enabled = int(payload.enabled) if payload.enabled is not None else row["enabled"]
        expires_at = expiry_from_days(payload.expires_days) if payload.expires_days is not None else row["expires_at"]
        page_token = secrets.token_urlsafe(32) if payload.regenerate_page_token else row["page_token"]
        api_key_hash, raw_api_key = row["api_key_hash"], ""
        if payload.api_key is not None:
            raw_api_key = payload.api_key.strip() or secrets.token_urlsafe(32)
            if len(raw_api_key) < 24:
                raise HTTPException(400, "分享 API Key 至少需要 24 位")
            api_key_hash = secret_hash(raw_api_key)
        conn.execute("UPDATE otp_shares SET page_token=?,api_key_hash=?,enabled=?,expires_at=?,updated_at=? WHERE id=?", (page_token, api_key_hash, enabled, expires_at, now_local(), share_id))
        conn.commit()
    return {"success": True, "page_url": f"/otp-share/{page_token}", "api_key": raw_api_key}


@app.delete("/api/shares/{share_id}")
def delete_share(share_id: int):
    with get_conn(DB_PATH) as conn:
        cursor = conn.execute("DELETE FROM otp_shares WHERE id=?", (share_id,))
        conn.commit()
    if not cursor.rowcount:
        raise HTTPException(404, "分享不存在")
    return {"success": True}


@app.get("/api/logs")
def logs():
    text = LOG_PATH.read_text(encoding="utf-8", errors="replace") if LOG_PATH.exists() else ""
    return PlainTextResponse("\n".join(text.splitlines()[-500:]))


@app.post("/api/logs/clear")
def clear_logs():
    LOG_PATH.write_text("", encoding="utf-8")
    return {"success": True}
