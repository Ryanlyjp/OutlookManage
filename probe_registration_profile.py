import argparse
import base64
import imaplib
import json
import socket
import ssl
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import urllib3

try:
    import socks
except ImportError:
    socks = None

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
DB_PATH = ROOT / "data" / "accounts.db"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"
GRAPH_INBOX_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
IMAP_HOST = "outlook.office365.com"
IMAP_PORT = 993
HTTP_TIMEOUT = 30

socket_proxy_lock = None


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def parse_account_line(line: str) -> dict[str, str]:
    parts = [p.strip() for p in line.strip().split("----")]
    if len(parts) < 4:
        raise ValueError("账号格式错误，必须是 邮箱----密码----client_id----refresh_token")
    return {
        "email": parts[0],
        "password": parts[1],
        "client_id": parts[2],
        "refresh_token": "----".join(parts[3:]).strip(),
    }


def build_session(proxy_url: str) -> requests.Session:
    session = requests.Session()
    session.verify = False
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    return session


def extract_error_text(response: requests.Response) -> str:
    try:
        data = response.json()
    except Exception:
        return response.text[:1000]
    return json.dumps(data, ensure_ascii=False)[:1000]


def request_refresh_token(session: requests.Session, client_id: str, refresh_token: str, scope: str | None = None) -> requests.Response:
    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if scope:
        data["scope"] = scope
    return session.post(TOKEN_URL, data=data, timeout=HTTP_TIMEOUT)


def get_graph_token(session: requests.Session, client_id: str, refresh_token: str) -> dict:
    attempts = []
    for label, scope in (("default", GRAPH_SCOPE), ("original", None)):
        resp = request_refresh_token(session, client_id, refresh_token, scope)
        attempt = {
            "label": label,
            "scope": scope or "(original)",
            "http_status": resp.status_code,
        }
        if resp.status_code == 200:
            payload = resp.json()
            attempt["granted_scope"] = payload.get("scope", "")
            attempts.append(attempt)
            return {
                "success": True,
                "access_token": payload.get("access_token", ""),
                "granted_scope": payload.get("scope", ""),
                "rotated_refresh_token": payload.get("refresh_token", ""),
                "attempts": attempts,
            }
        attempt["error"] = extract_error_text(resp)
        attempts.append(attempt)
    return {"success": False, "attempts": attempts, "error": attempts[-1]["error"] if attempts else "unknown"}


def get_protocol_token(session: requests.Session, client_id: str, refresh_token: str, scope: str, protocol: str) -> dict:
    resp = request_refresh_token(session, client_id, refresh_token, scope=scope)
    if resp.status_code != 200:
        return {
            "success": False,
            "status_code": resp.status_code,
            "protocol": protocol,
            "error": extract_error_text(resp),
        }
    payload = resp.json()
    return {
        "success": bool(payload.get("access_token")),
        "status_code": resp.status_code,
        "protocol": protocol,
        "access_token": payload.get("access_token", ""),
        "rotated_refresh_token": payload.get("refresh_token", ""),
    }


def graph_get(session: requests.Session, access_token: str, url: str, params: dict | None = None) -> requests.Response:
    return session.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params=params,
        timeout=HTTP_TIMEOUT,
    )


def graph_profile(session: requests.Session, access_token: str) -> dict:
    resp = graph_get(
        session,
        access_token,
        GRAPH_ME_URL,
        params={"$select": "id,displayName,mail,userPrincipalName,createdDateTime,country,preferredLanguage"},
    )
    if resp.status_code != 200:
        return {"ok": False, "http_status": resp.status_code, "error": extract_error_text(resp)}
    data = resp.json()
    return {
        "ok": True,
        "http_status": resp.status_code,
        "id": data.get("id", ""),
        "display_name": data.get("displayName", ""),
        "mail": data.get("mail") or data.get("userPrincipalName") or "",
        "createdDateTime": data.get("createdDateTime", ""),
        "country": data.get("country", ""),
        "preferredLanguage": data.get("preferredLanguage", ""),
        "raw": data,
    }


def graph_earliest_message(session: requests.Session, access_token: str) -> dict:
    queries = [
        (GRAPH_INBOX_URL, {"$top": 1, "$select": "id,subject,receivedDateTime,from", "$orderby": "receivedDateTime asc"}),
        ("https://graph.microsoft.com/v1.0/me/messages", {"$top": 1, "$select": "id,subject,receivedDateTime,from", "$orderby": "receivedDateTime asc"}),
    ]
    errors = []
    for url, params in queries:
        resp = graph_get(session, access_token, url, params)
        if resp.status_code == 200:
            items = resp.json().get("value", [])
            if items:
                item = items[0]
                return {
                    "ok": True,
                    "source": "graph_mail",
                    "http_status": resp.status_code,
                    "id": item.get("id", ""),
                    "subject": item.get("subject", ""),
                    "receivedDateTime": item.get("receivedDateTime", ""),
                    "from": (((item.get("from") or {}).get("emailAddress") or {}).get("address") or ""),
                }
            return {"ok": True, "source": "graph_mail", "http_status": resp.status_code, "empty": True}
        errors.append({"url": url, "http_status": resp.status_code, "error": extract_error_text(resp)})
    return {"ok": False, "source": "graph_mail", "errors": errors}


def build_xoauth2(email_addr: str, access_token: str) -> str:
    payload = f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


@contextmanager
def proxy_socket_context(proxy_url: str):
    global socket_proxy_lock
    if not proxy_url:
        yield
        return
    if not socks:
        raise RuntimeError("缺少 PySocks，无法通过代理测试 IMAP")
    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or "").lower()
    proxy_type_map = {
        "socks5": socks.SOCKS5,
        "socks5h": socks.SOCKS5,
        "socks4": socks.SOCKS4,
        "http": socks.HTTP,
        "https": socks.HTTP,
    }
    proxy_type = proxy_type_map.get(scheme)
    if not proxy_type or not parsed.hostname or not parsed.port:
        raise RuntimeError(f"不支持的代理: {proxy_url}")
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    rdns = scheme == "socks5h"
    if socket_proxy_lock is None:
        import threading
        socket_proxy_lock = threading.Lock()
    with socket_proxy_lock:
        original_socket = socket.socket
        try:
            socks.set_default_proxy(
                proxy_type,
                parsed.hostname,
                parsed.port,
                username=username,
                password=password,
                rdns=rdns,
            )
            socket.socket = socks.socksocket
            yield
        finally:
            socket.socket = original_socket
            socks.set_default_proxy()


def _to_iso(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def imap_earliest_message(email_addr: str, access_token: str, proxy_url: str) -> dict:
    auth_payload = build_xoauth2(email_addr, access_token)
    with proxy_socket_context(proxy_url):
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ssl.create_default_context(), timeout=HTTP_TIMEOUT)
            conn.authenticate("XOAUTH2", lambda _: auth_payload.encode("utf-8"))
            select_type, _ = conn.select("INBOX", readonly=True)
            if select_type != "OK":
                return {"ok": False, "source": "imap_mail", "error": f"select failed: {select_type}"}
            search_type, search_data = conn.uid("search", None, "ALL")
            if search_type != "OK" or not search_data:
                return {"ok": False, "source": "imap_mail", "error": "search failed"}
            raw = search_data[0].decode("utf-8", errors="ignore") if isinstance(search_data[0], bytes) else str(search_data[0] or "")
            uids = [uid for uid in raw.split() if uid]
            if not uids:
                return {"ok": True, "source": "imap_mail", "empty": True}
            fetch_type, fetch_data = conn.uid("fetch", uids[0], "(BODY.PEEK[HEADER.FIELDS (SUBJECT DATE FROM)])")
            if fetch_type != "OK" or not fetch_data:
                return {"ok": False, "source": "imap_mail", "error": f"fetch failed: {fetch_type}"}
            header_bytes = b""
            for item in fetch_data:
                if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                    header_bytes = item[1]
                    break
            parsed = BytesParser().parsebytes(header_bytes)
            dt = None
            try:
                dt = parsedate_to_datetime(parsed.get("Date", ""))
            except Exception:
                dt = None
            return {
                "ok": True,
                "source": "imap_mail",
                "uid": uids[0],
                "subject": parsed.get("Subject", ""),
                "from": parsed.get("From", ""),
                "receivedDateTime": _to_iso(dt),
                "header": header_bytes.decode("utf-8", errors="ignore")[:500],
            }
        except Exception as exc:
            return {"ok": False, "source": "imap_mail", "error": str(exc)}
        finally:
            try:
                if conn is not None:
                    conn.logout()
            except Exception:
                pass


def pick_normal_account_from_db() -> dict[str, str]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT email, password, client_id, refresh_token
        FROM accounts
        WHERE graph_status='ok' OR imap_status='ok' OR pop_status='ok'
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    conn.close()
    if not row:
        raise RuntimeError("数据库中没有可用的正常账号")
    return dict(row)


def infer_registration(graph_profile_result: dict, graph_mail_result: dict, imap_mail_result: dict) -> dict:
    if graph_profile_result.get("ok") and graph_profile_result.get("createdDateTime"):
        return {
            "registered_at": graph_profile_result["createdDateTime"],
            "registered_source": "graph_profile_createdDateTime",
        }
    if graph_mail_result.get("ok") and graph_mail_result.get("receivedDateTime"):
        return {
            "registered_at": graph_mail_result["receivedDateTime"],
            "registered_source": "graph_earliest_mail",
        }
    if imap_mail_result.get("ok") and imap_mail_result.get("receivedDateTime"):
        return {
            "registered_at": imap_mail_result["receivedDateTime"],
            "registered_source": "imap_earliest_mail",
        }
    return {"registered_at": "", "registered_source": ""}


def main() -> int:
    parser = argparse.ArgumentParser(description="单账号测试：注册时间 / 国家地区 / 语言 / 最早邮件")
    parser.add_argument("--account", help="账号行：邮箱----密码----client_id----refresh_token")
    parser.add_argument("--pick-normal", action="store_true", help="从本地数据库自动选 1 个正常账号")
    parser.add_argument("--proxy", default="", help="覆盖 config.json 中的代理")
    args = parser.parse_args()

    config = load_config()
    proxy_url = args.proxy.strip() or ((config.get("proxy") or {}).get("url") or "").strip()
    if args.account:
        account = parse_account_line(args.account)
    else:
        account = pick_normal_account_from_db() if args.pick_normal or not args.account else {}

    session = build_session(proxy_url)
    token_result = get_graph_token(session, account["client_id"], account["refresh_token"])
    graph_profile_result = {}
    graph_mail_result = {}
    imap_mail_result = {}

    if token_result.get("success"):
        access_token = token_result["access_token"]
        graph_profile_result = graph_profile(session, access_token)
        graph_mail_result = graph_earliest_message(session, access_token)
        if not graph_mail_result.get("ok"):
            imap_token_result = get_protocol_token(session, account["client_id"], account["refresh_token"], IMAP_SCOPE, "imap_registration")
            if imap_token_result.get("success"):
                imap_mail_result = imap_earliest_message(account["email"], imap_token_result.get("access_token", ""), proxy_url)
            else:
                imap_mail_result = {"ok": False, "source": "imap_mail", "error": imap_token_result.get("error", "")}
    else:
        graph_profile_result = {"ok": False, "error": token_result.get("error", "graph token failed")}
        graph_mail_result = {"ok": False, "error": token_result.get("error", "graph token failed")}

    registration = infer_registration(graph_profile_result, graph_mail_result, imap_mail_result)
    result = {
        "success": bool(token_result.get("success")),
        "email": account["email"],
        "proxy": proxy_url,
        "graph_token": {
            "success": token_result.get("success", False),
            "granted_scope": token_result.get("granted_scope", ""),
            "attempts": token_result.get("attempts", []),
            "error": token_result.get("error", ""),
        },
        "profile": graph_profile_result,
        "graph_earliest_mail": graph_mail_result,
        "imap_earliest_mail": imap_mail_result,
        "registration": registration,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
