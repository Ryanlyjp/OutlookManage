import random
import re
import string
import time
from email import policy
from email.parser import Parser
from typing import Any

import requests

CODE_PATTERNS = [
    re.compile(r"(?<!\d)(\d{6})(?!\d)"),
    re.compile(r"(?<!\d)(\d{4,8})(?!\d)"),
]


def _pick(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def extract_verification_code(mail: dict[str, Any]) -> str:
    raw = _pick(mail, "raw", "source")
    parsed_parts: list[str] = []
    if raw:
        try:
            msg = Parser(policy=policy.default).parsestr(raw)
            parsed_parts.append(str(msg.get("subject", "") or ""))
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_maintype() == "multipart":
                        continue
                    try:
                        parsed_parts.append(part.get_content() or "")
                    except Exception:
                        continue
            else:
                try:
                    parsed_parts.append(msg.get_content() or "")
                except Exception:
                    pass
        except Exception:
            pass
    parts = [
        _pick(mail, "subject", "title"),
        _pick(mail, "text", "plain", "content", "body"),
        _pick(mail, "html"),
        *parsed_parts,
        raw,
    ]
    joined = "\n".join(part for part in parts if part)
    for pattern in CODE_PATTERNS:
        match = pattern.search(joined)
        if match:
            return match.group(1)
    return ""


class TempMailClient:
    def __init__(self, base_url: str, admin_password: str, domain: str, site_password: str = "", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.admin_password = admin_password
        self.domain = domain
        self.site_password = site_password or ""
        self.timeout = timeout
        self.session = requests.Session()

    def _headers(self) -> dict[str, str]:
        headers = {"x-admin-auth": self.admin_password}
        if self.site_password:
            headers["x-custom-auth"] = self.site_password
        return headers

    def create_random_address(self) -> dict[str, Any]:
        local = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(10, 16)))
        resp = self.session.post(
            f"{self.base_url}/admin/new_address",
            json={"enablePrefix": True, "name": local, "domain": self.domain},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        address = _pick(data, "address")
        if not address:
            raise RuntimeError(f"临时邮箱创建失败: {data}")
        return {"address": address, "jwt": _pick(data, "jwt"), "address_id": data.get("address_id")}

    def list_mails(self, address: str, limit: int = 20) -> list[dict[str, Any]]:
        resp = self.session.get(
            f"{self.base_url}/admin/mails",
            params={"address": address, "limit": limit, "offset": 0},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        mails = data.get("data")
        if not isinstance(mails, list):
            mails = data.get("results")
        return mails if isinstance(mails, list) else []

    def wait_for_code(
        self,
        address: str,
        timeout_sec: int = 180,
        interval_sec: int = 5,
        log_hook=None,
    ) -> dict[str, Any]:
        deadline = time.time() + timeout_sec
        seen: set[str] = set()
        last_count = 0
        while time.time() < deadline:
            mails = self.list_mails(address)
            last_count = len(mails)
            for mail in mails:
                mail_id = str(mail.get("id") or mail.get("_id") or mail.get("created_at") or mail.get("subject") or "")
                if mail_id in seen:
                    continue
                seen.add(mail_id)
                code = extract_verification_code(mail)
                if code:
                    if log_hook:
                        log_hook("TEMPMAIL", f"{address} 收到验证码 {code}", "INFO")
                    return {"code": code, "mail": mail, "mail_id": mail_id, "attempts": len(seen)}
            if log_hook:
                log_hook("TEMPMAIL", f"{address} 暂无验证码，已轮询 {last_count} 封", "INFO")
            time.sleep(interval_sec)
        raise TimeoutError(f"备用邮箱验证码超时未收到（{address}，已轮询 {last_count} 封）")
