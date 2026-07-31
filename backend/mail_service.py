import base64
import html
import re
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests

TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
HTTP_TIMEOUT = 30

OTP_KEYWORDS = r"(?:otp|code|验证码|驗證碼|校验码|security code|verification code|passcode|一次性密码)"
OTP_VALUE = r"(?<![A-Za-z0-9])([A-Za-z0-9]{4,8})(?![A-Za-z0-9])"


def graph_session(client_id: str, refresh_token: str, proxy: str = "") -> tuple[requests.Session, str, str]:
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    response = session.post(TOKEN_URL, data={
        "client_id": client_id,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "scope": GRAPH_SCOPE,
    }, timeout=HTTP_TIMEOUT)
    try:
        data = response.json()
    except ValueError:
        data = {}
    if not response.ok or not data.get("access_token"):
        detail = data.get("error_description") or data.get("error") or response.text or "刷新令牌失败"
        raise ValueError(str(detail)[:1000])
    session.headers.update({"Authorization": f"Bearer {data['access_token']}"})
    return session, data["access_token"], str(data.get("refresh_token") or refresh_token)


def graph_get(session: requests.Session, path: str, **kwargs) -> dict[str, Any]:
    response = session.get(f"{GRAPH_ROOT}{path}", timeout=HTTP_TIMEOUT, **kwargs)
    if not response.ok:
        try:
            detail = response.json().get("error", {}).get("message")
        except ValueError:
            detail = response.text
        raise ValueError(str(detail or f"Graph HTTP {response.status_code}")[:1000])
    return response.json()


def sender_text(message: dict[str, Any]) -> str:
    sender = (message.get("from") or {}).get("emailAddress") or {}
    name, address = str(sender.get("name") or ""), str(sender.get("address") or "")
    return f"{name} <{address}>" if name and address else address or name


def normalize_message(message: dict[str, Any]) -> dict[str, Any]:
    body = message.get("body") or {}
    return {
        "id": str(message.get("id") or ""),
        "subject": str(message.get("subject") or "(无主题)"),
        "sender": sender_text(message),
        "received_at": str(message.get("receivedDateTime") or ""),
        "body_html": str(body.get("content") or "") if str(body.get("contentType") or "").lower() == "html" else "",
        "body_text": str(body.get("content") or "") if str(body.get("contentType") or "").lower() != "html" else "",
        "has_attachments": bool(message.get("hasAttachments")),
        "internet_message_id": str(message.get("internetMessageId") or ""),
    }


def list_messages(session: requests.Session, limit: int = 5) -> list[dict[str, Any]]:
    requested = max(1, min(int(limit), 20))
    fields = "id,subject,from,receivedDateTime,body,hasAttachments,internetMessageId"
    messages: dict[str, dict[str, Any]] = {}
    for folder in ("inbox", "junkemail"):
        path = f"/me/mailFolders/{folder}/messages?$top={requested}&$orderby=receivedDateTime%20desc&$select={fields}"
        for item in graph_get(session, path).get("value") or []:
            normalized = normalize_message(item)
            messages[normalized["id"]] = normalized
    return sorted(messages.values(), key=lambda item: item["received_at"], reverse=True)[:requested]


def get_message(session: requests.Session, message_id: str) -> dict[str, Any]:
    fields = "id,subject,from,receivedDateTime,body,hasAttachments,internetMessageId"
    message = normalize_message(graph_get(session, f"/me/messages/{quote(message_id, safe='')}?$select={fields}"))
    message["attachments"] = list_attachments(session, message_id) if message["has_attachments"] else []
    return message


def list_attachments(session: requests.Session, message_id: str) -> list[dict[str, Any]]:
    data = graph_get(session, f"/me/messages/{quote(message_id, safe='')}/attachments?$select=id,name,contentType,size,isInline")
    return [{
        "id": str(item.get("id") or ""),
        "filename": str(item.get("name") or "attachment"),
        "content_type": str(item.get("contentType") or "application/octet-stream"),
        "size_bytes": int(item.get("size") or 0),
        "inline": bool(item.get("isInline")),
        "type": str(item.get("@odata.type") or ""),
    } for item in data.get("value") or []]


def download_attachment(session: requests.Session, message_id: str, attachment_id: str) -> tuple[bytes, str, str]:
    path = f"/me/messages/{quote(message_id, safe='')}/attachments/{quote(attachment_id, safe='')}"
    data = graph_get(session, path)
    if not str(data.get("@odata.type") or "").endswith("fileAttachment"):
        raise ValueError("当前仅支持下载文件附件")
    try:
        content = base64.b64decode(data.get("contentBytes") or "", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("附件内容无效") from exc
    return content, str(data.get("name") or "attachment"), str(data.get("contentType") or "application/octet-stream")


def visible_text(body_html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", body_html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return html.unescape(re.sub(r"\s+", " ", text))


def extract_otp(message: dict[str, Any]) -> str:
    text = "\n".join((str(message.get("subject") or ""), str(message.get("body_text") or ""), visible_text(str(message.get("body_html") or ""))))
    for keyword in re.finditer(OTP_KEYWORDS, text, re.IGNORECASE):
        after = text[keyword.end():keyword.end() + 60]
        for match in re.finditer(OTP_VALUE, after):
            candidate = match.group(1)
            if any(char.isdigit() for char in candidate):
                return candidate
        before = text[max(0, keyword.start() - 40):keyword.start()]
        candidates = [match.group(1) for match in re.finditer(OTP_VALUE, before) if any(char.isdigit() for char in match.group(1))]
        if candidates:
            return candidates[-1]
    return ""


def parse_expiry(value: str) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)
