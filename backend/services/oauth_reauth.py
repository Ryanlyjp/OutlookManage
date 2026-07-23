import time
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import requests
from patchright.sync_api import sync_playwright

AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
DEFAULT_REDIRECT_URI = "https://localhost"
DEFAULT_SCOPE = "https://graph.microsoft.com/.default offline_access"
EMAIL_SELECTOR = "#i0116"
EMAIL_NEXT_SELECTOR = "#idSIButton9"
PASSWORD_SELECTOR = "#i0118, #passwordEntry, input[type=\"password\"]"
CONSENT_SELECTOR = '[data-testid="appConsentPrimaryButton"]'
PRIMARY_SELECTOR = '[data-testid="primaryButton"],input[data-testid="primaryButton"],input[type="submit"]'
PASSWORD_BYPASS_TEXTS = [
    "使用密码",
    "使用密码登录",
    "Use password instead",
    "Use your password",
    "Sign in with a password",
]
INTERMEDIATE_PRIMARY_TEXTS = {"是", "yes", "继续", "continue", "下一步", "next"}
SKIP_FOR_NOW_TEXTS = {"暂时跳过(7 天后必须输入)", "skip for now"}


def _log(log_hook, stage: str, message: str, level: str = "INFO") -> None:
    if log_hook:
        log_hook(stage, message, level)


def _content(page) -> str:
    try:
        return page.content()
    except Exception:
        return ""


def _extract_code_from_url(url: str) -> str | None:
    if not url or "code=" not in url:
        return None
    parsed = urlparse(url)
    for source in (parsed.query, parsed.fragment):
        if not source:
            continue
        code = parse_qs(source).get("code", [None])[0]
        if code:
            return code
    return None


def build_auth_url(client_id: str, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE) -> str:
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "sso_reload": "true",
    }
    return f"{AUTHORIZE_URL}?{'&'.join(f'{k}={quote(v)}' for k, v in params.items())}"


def _has_password_entry(page) -> bool:
    try:
        for selector in ("#passwordEntry", "#i0118"):
            locator = page.locator(selector)
            count = locator.count()
            for idx in range(count):
                if locator.nth(idx).is_visible():
                    return True
    except Exception:
        pass
    for text in ("密码", "Password"):
        try:
            locator = page.get_by_text(text)
            if locator.count() > 0 and locator.first.is_visible():
                return True
        except Exception:
            pass
    return False


def _current_auth_stage(page) -> str:
    try:
        if page.locator(EMAIL_SELECTOR).count() > 0 and page.locator(EMAIL_SELECTOR).first.is_visible():
            return "email"
    except Exception:
        pass
    if _has_password_entry(page):
        return "password"
    for text in ("让我们来保护你的帐户", "你想添加哪些安全信息?", "暂时跳过(7 天后必须输入)"):
        try:
            locator = page.get_by_text(text)
            if locator.count() > 0 and locator.first.is_visible():
                return "security_info"
        except Exception:
            pass
    if page.locator(CONSENT_SELECTOR).count() > 0 and page.locator(CONSENT_SELECTOR).first.is_visible():
        return "consent"
    return "unknown"


def _wait_auth_stage(page, timeout_ms: int = 15000, poll_ms: int = 300) -> str:
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        stage = _current_auth_stage(page)
        if stage != "unknown":
            return stage
        page.wait_for_timeout(poll_ms)
    return _current_auth_stage(page)


def _submit_email_fill(page, email: str) -> None:
    locator = page.locator(EMAIL_SELECTOR).first
    locator.click(timeout=5000)
    page.keyboard.press("Escape")
    page.wait_for_timeout(150)
    locator.fill("")
    page.wait_for_timeout(100)
    locator.fill(email, timeout=5000)
    page.wait_for_timeout(300)
    page.keyboard.press("Escape")
    page.wait_for_timeout(200)
    page.locator(EMAIL_NEXT_SELECTOR).click(timeout=5000)


def _submit_email_type(page, email: str) -> None:
    locator = page.locator(EMAIL_SELECTOR).first
    locator.click(timeout=5000)
    page.keyboard.press("Control+A")
    page.keyboard.press("Backspace")
    page.wait_for_timeout(100)
    locator.type(email, delay=35, timeout=10000)
    page.wait_for_timeout(250)
    page.keyboard.press("Escape")
    page.wait_for_timeout(200)
    page.locator(EMAIL_NEXT_SELECTOR).click(timeout=5000)


def _submit_email_js_exact(page, email: str) -> None:
    page.wait_for_selector(EMAIL_SELECTOR, state="visible", timeout=10000)
    page.eval_on_selector(
        EMAIL_SELECTOR,
        """(el, value) => {
            el.focus();
            el.setAttribute('autocomplete', 'off');
            const nativeInputValueSetter =
                Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
            nativeInputValueSetter.call(el, value);
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
        }""",
        email,
    )
    page.wait_for_timeout(500)
    page.keyboard.press("Escape")
    page.wait_for_timeout(200)
    page.locator(EMAIL_NEXT_SELECTOR).click(timeout=5000)


def _submit_email(page, email: str, log_hook=None) -> None:
    page.wait_for_selector(EMAIL_SELECTOR, state="visible", timeout=10000)
    methods = [
        ("fill", _submit_email_fill),
        ("type", _submit_email_type),
        ("js_exact", _submit_email_js_exact),
        ("js_exact_retry", _submit_email_js_exact),
    ]
    last_error = None
    for name, method in methods:
        try:
            if page.locator(EMAIL_SELECTOR).count() == 0:
                return
            current = page.eval_on_selector(EMAIL_SELECTOR, "(el) => (el.value || '').trim()")
            _log(log_hook, "oauth_email", f"尝试 {name}，提交前值={current!r}", "INFO")
            method(page, email)
            stage = _wait_auth_stage(page, timeout_ms=12000)
            if stage == "password":
                _log(log_hook, "oauth_email", f"{name} 成功进入密码页", "OK")
                return
            if stage == "consent":
                _log(log_hook, "oauth_email", f"{name} 成功进入同意页", "OK")
                return
            if stage == "security_info":
                _log(log_hook, "oauth_email", f"{name} 成功进入安全信息页", "OK")
                return
            still_here = page.locator(EMAIL_SELECTOR).count() > 0 and page.locator(EMAIL_SELECTOR).first.is_visible()
            err = ""
            if still_here:
                err = page.eval_on_selector("#usernameError", "(el) => (el.innerText || '').trim()") if page.locator("#usernameError").count() > 0 else ""
            _log(log_hook, "oauth_email", f"{name} 后仍未进入下一阶段 stage={stage} error={err!r}", "WARN")
        except Exception as exc:
            last_error = exc
            _log(log_hook, "oauth_email", f"{name} 失败: {exc}", "WARN")
    if last_error:
        raise RuntimeError(f"邮箱提交失败: {last_error}")
    raise RuntimeError("邮箱提交后未进入密码页")


def _click_use_password(page) -> None:
    for text in PASSWORD_BYPASS_TEXTS:
        try:
            btn = page.get_by_role("button", name=text)
            if btn.count() > 0 and btn.first.is_visible():
                btn.first.click(timeout=5000)
                page.wait_for_timeout(1500)
                return
        except Exception:
            pass
        try:
            btn = page.get_by_text(text)
            if btn.count() > 0 and btn.first.is_visible():
                btn.first.click(timeout=5000)
                page.wait_for_timeout(1500)
                return
        except Exception:
            pass


def _has_use_password_option(page) -> bool:
    for text in PASSWORD_BYPASS_TEXTS:
        try:
            locator = page.get_by_role("button", name=text)
            if locator.count() > 0 and locator.first.is_visible():
                return True
        except Exception:
            pass
        try:
            locator = page.get_by_text(text)
            if locator.count() > 0 and locator.first.is_visible():
                return True
        except Exception:
            pass
    return False


def _describe_password_candidates(page) -> str:
    parts: list[str] = []
    for selector in ('#passwordEntry', '#i0118', 'input[type="password"]'):
        try:
            locator = page.locator(selector)
            count = locator.count()
            rows = []
            for idx in range(count):
                item = locator.nth(idx)
                try:
                    visible = item.is_visible()
                except Exception as exc:
                    visible = f"err:{exc.__class__.__name__}"
                try:
                    meta = item.evaluate(
                        """(el) => ({
                            id: el.id || '',
                            name: el.name || '',
                            type: el.getAttribute('type') || '',
                            tabindex: el.getAttribute('tabindex') || '',
                            ariaHidden: el.getAttribute('aria-hidden') || '',
                            readonly: el.hasAttribute('readonly'),
                            disabled: !!el.disabled
                        })"""
                    )
                except Exception:
                    meta = {}
                rows.append(f"{idx}:visible={visible},meta={meta}")
            parts.append(f"{selector} count={count} [{' ; '.join(rows)}]")
        except Exception:
            parts.append(f"{selector} error")
    return " | ".join(parts)


def _password_locator(page, log_hook=None, stage: str = "oauth_password", timeout_ms: int = 15000):
    deadline = time.time() + timeout_ms / 1000
    last_snapshot = ""
    while time.time() < deadline:
        _click_use_password(page)
        for selector in ('#passwordEntry', '#i0118', 'input[type="password"]'):
            try:
                locator = page.locator(selector)
                count = locator.count()
            except Exception:
                continue
            for idx in range(count):
                item = locator.nth(idx)
                try:
                    if item.is_visible():
                        _log(log_hook, stage, f"使用密码框 {selector}[{idx}]", "INFO")
                        return item, f"{selector}[{idx}]"
                except Exception:
                    continue
        last_snapshot = _describe_password_candidates(page)
        page.wait_for_timeout(300)
    _log(log_hook, stage, f"未找到可见密码框，候选={last_snapshot}", "FAIL")
    raise RuntimeError(f"未找到可见密码框：{last_snapshot}")


def _submit_password(page, password: str, log_hook=None, stage: str = "oauth_password") -> None:
    _click_use_password(page)
    _log(log_hook, stage, f"密码候选快照：{_describe_password_candidates(page)}", "INFO")
    locator, locator_name = _password_locator(page, log_hook=log_hook, stage=stage, timeout_ms=15000)
    locator.evaluate(
        """(el, value) => {
            el.focus();
            el.removeAttribute('readonly');
            el.removeAttribute('aria-hidden');
            el.style.opacity = '1';
            el.style.pointerEvents = 'auto';
            const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
            setter.call(el, value);
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
        }""",
        password,
    )
    page.wait_for_timeout(200)
    try:
        filled_len = locator.evaluate("(el) => (el.value || '').length")
        _log(log_hook, stage, f"{locator_name} 已写入密码，长度={filled_len}", "INFO")
    except Exception:
        _log(log_hook, stage, f"{locator_name} 已写入密码", "INFO")
    page.wait_for_timeout(400)
    try:
        page.get_by_test_id("primaryButton").click(timeout=5000)
        _log(log_hook, stage, "点击 data-testid=primaryButton 提交密码", "INFO")
    except Exception:
        page.keyboard.press("Enter")
        _log(log_hook, stage, "主按钮点击失败，改用 Enter 提交密码", "WARN")


def _wait_for_code(page, captured_code: list[str | None], timeout_sec: int) -> str | None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if captured_code[0]:
            return captured_code[0]
        code = _extract_code_from_url(page.url)
        if code:
            captured_code[0] = code
            return code
        try:
            code = _extract_code_from_url(page.evaluate("window.location.href"))
            if code:
                captured_code[0] = code
                return code
        except Exception:
            pass
        page.wait_for_timeout(500)
    return None


def _click_intermediate_primary(page, log_hook=None) -> bool:
    try:
        locator = page.locator(PRIMARY_SELECTOR)
        if locator.count() == 0 or not locator.first.is_visible():
            return False
        text = (locator.first.inner_text(timeout=1000) or "").strip().lower()
        if text in INTERMEDIATE_PRIMARY_TEXTS:
            locator.first.click(timeout=5000)
            _log(log_hook, "oauth_primary", f"点击中间页主按钮: {text}", "INFO")
            return True
    except Exception:
        return False
    return False


def _click_skip_for_now(page, log_hook=None) -> bool:
    for text in SKIP_FOR_NOW_TEXTS:
        try:
            locator = page.get_by_text(text)
            if locator.count() > 0 and locator.first.is_visible():
                locator.first.click(timeout=5000)
                _log(log_hook, "oauth_skip", f"点击临时跳过安全信息: {text}", "INFO")
                return True
        except Exception:
            pass
    return False


def _exchange_code(code: str, client_id: str, redirect_uri: str, scope: str, proxy_url: str = "") -> dict[str, Any]:
    session = requests.Session()
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}
    resp = session.post(
        TOKEN_URL,
        data={
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "scope": scope,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    data = resp.json()
    if "refresh_token" not in data:
        raise RuntimeError(f"token请求失败: {data.get('error') or data}")
    return data


def reauthorize_account(
    email: str,
    password: str,
    client_id: str,
    proxy_url: str = "",
    headless: bool = False,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    scope: str = DEFAULT_SCOPE,
    log_hook=None,
) -> dict[str, Any]:
    if not client_id.strip():
        raise RuntimeError("client_id 为空，无法重新授权")
    auth_url = build_auth_url(client_id.strip(), redirect_uri=redirect_uri, scope=scope)
    p = sync_playwright().start()
    browser = None
    page = None
    captured_code: list[str | None] = [None]
    try:
        launch_kwargs: dict[str, Any] = {
            "headless": headless,
            "args": [
                "--lang=zh-CN",
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-features=WebAuthenticationConditionalUI",
                "--disable-save-password-bubble",
                "--disable-password-manager-reauthentication",
            ],
        }
        if proxy_url:
            launch_kwargs["proxy"] = {"server": proxy_url}
        browser = p.chromium.launch(**launch_kwargs)
        page = browser.new_page()

        def on_request(request):
            code = _extract_code_from_url(request.url)
            if code:
                captured_code[0] = code

        def on_frame(frame):
            code = _extract_code_from_url(frame.url)
            if code:
                captured_code[0] = code

        page.on("request", on_request)
        page.on("framenavigated", on_frame)
        page.goto(auth_url, timeout=45000, wait_until="domcontentloaded")
        _log(log_hook, "oauth_goto", "已进入授权页面", "INFO")

        try:
            if page.get_by_text("使用其他帐户").count() > 0:
                page.get_by_text("使用其他帐户").first.click(timeout=3000)
                page.wait_for_timeout(1500)
        except Exception:
            pass

        stage = _wait_auth_stage(page, timeout_ms=12000)
        _log(log_hook, "oauth_stage", f"初始阶段={stage}", "INFO")

        if stage == "email":
            _submit_email(page, email, log_hook=log_hook)
            _log(log_hook, "oauth_email", "已提交邮箱", "INFO")
            stage = _wait_auth_stage(page, timeout_ms=15000)
            _log(log_hook, "oauth_stage", f"邮箱提交后阶段={stage}", "INFO")

        if stage == "unknown":
            raise RuntimeError("OAuth 页面阶段识别失败（unknown），未进入邮箱/密码/同意/安全信息页")

        if "找不到使用该用户名的帐户" in _content(page):
            raise RuntimeError("微软提示账号不存在")

        if stage == "password" or _has_use_password_option(page):
            _submit_password(page, password, log_hook=log_hook, stage="oauth_password")
            _log(log_hook, "oauth_password", "已提交密码", "INFO")
            page.wait_for_timeout(1500)
        elif stage == "consent" or page.locator(CONSENT_SELECTOR).count() > 0:
            _log(log_hook, "oauth_password", "检测到已登录态，跳过密码输入", "INFO")
        elif stage == "security_info":
            _log(log_hook, "oauth_password", "检测到安全信息页，跳过密码输入", "INFO")

        content = _content(page)
        if "此密码不是你的 Microsoft 帐户的正确密码" in content or "This password is incorrect" in content:
            raise RuntimeError("微软提示密码错误")

        code = _wait_for_code(page, captured_code, 12)
        if code:
            _log(log_hook, "oauth_code", "密码提交后直接捕获到 code", "OK")
        else:
            clicked = False
            for _ in range(8):
                if page.locator(CONSENT_SELECTOR).count() > 0 and page.locator(CONSENT_SELECTOR).first.is_visible():
                    page.locator(CONSENT_SELECTOR).first.click(timeout=8000)
                    _log(log_hook, "oauth_consent", "点击授权同意按钮", "INFO")
                    clicked = True
                    break
                if _click_skip_for_now(page, log_hook=log_hook):
                    clicked = True
                    code = _wait_for_code(page, captured_code, 8)
                    if code:
                        break
                if _click_intermediate_primary(page, log_hook=log_hook):
                    clicked = True
                code = _wait_for_code(page, captured_code, 4)
                if code:
                    break
            if not code:
                code = _wait_for_code(page, captured_code, 25 if clicked else 12)
        if not code:
            raise RuntimeError("未捕获到授权 code")

        data = _exchange_code(code, client_id.strip(), redirect_uri, scope, proxy_url=proxy_url)
        _log(log_hook, "oauth_token", "重新授权成功并换取 refresh_token", "OK")
        return {
            "success": True,
            "refresh_token": data["refresh_token"],
            "scope": data.get("scope", ""),
            "access_token": data.get("access_token", ""),
            "code": code,
        }
    finally:
        try:
            if page:
                page.close()
        except Exception:
            pass
        try:
            if browser:
                browser.close()
        except Exception:
            pass
        p.stop()
