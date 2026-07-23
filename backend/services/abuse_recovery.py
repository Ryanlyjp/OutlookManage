import math
import random
import time
from typing import Any

from patchright.sync_api import sync_playwright

from backend.services.oauth_reauth import _submit_email, _submit_password, reauthorize_account
from backend.services.temp_mail import TempMailClient

MAIL_URL = "https://outlook.office.com/mail/?hl=zh_TW"
PRIMARY_SELECTOR = 'button[data-testid="primaryButton"],input[data-testid="primaryButton"],input[type="submit"]'
EMAIL_INPUT_SELECTOR = "#i0116"
BACKUP_EMAIL_SELECTOR = "#EmailAddress"
VERIFY_CODE_SELECTOR = "#iOttText"
NEXT_SELECTOR = "#iNext"

ABUSE_TEXTS = [
    "我们检测到违反 Microsoft 服务协议的活动",
    "检测到违反 Microsoft 服务协议的活动",
    "We detected activity that violates Microsoft Services Agreement",
]
SERVICE_RETRY_TEXTS = [
    "服务出现问题。请重试。",
    "如果问题仍然存在，请稍后再试",
    "Something went wrong",
]
UNRECOVERABLE_TEXTS = [
    "我们检测到一些异常活动，并已阻止恢复此帐户。",
    "已阻止恢复此帐户",
    "blocked recovery of this account",
]
UNBLOCKED_TEXTS = [
    "已取消阻止你的帐户",
    "已取消阻止",
    "Your account has been unblocked",
]
OTHER_ACCOUNT_TEXTS = ("使用其他帐户", "Use another account")


def _log(log_hook, stage: str, message: str, level: str = "INFO") -> None:
    if log_hook:
        log_hook(stage, message, level)


def _text_exists(page, text: str) -> bool:
    try:
        locator = page.get_by_text(text)
        return locator.count() > 0 and locator.first.is_visible()
    except Exception:
        return False


def _any_text_exists(page, texts: list[str]) -> bool:
    return any(_text_exists(page, text) for text in texts)


def _visible(page, selector: str) -> bool:
    try:
        locator = page.locator(selector)
        return locator.count() > 0 and locator.first.is_visible()
    except Exception:
        return False


def _click_first_visible(page, selectors: list[str], log_hook=None, stage: str = "click") -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector)
            if locator.count() > 0 and locator.first.is_visible():
                locator.first.click(timeout=5000)
                _log(log_hook, stage, f"点击 {selector}", "INFO")
                return True
        except Exception:
            continue
    return False


def _content(page) -> str:
    try:
        return page.content()
    except Exception:
        return ""


def _click_use_other_account(page) -> None:
    for text in OTHER_ACCOUNT_TEXTS:
        try:
            locator = page.get_by_text(text)
            if locator.count() > 0 and locator.first.is_visible():
                locator.first.click(timeout=3000)
                page.wait_for_timeout(1200)
                return
        except Exception:
            pass


def _has_other_account_entry(page) -> bool:
    for text in OTHER_ACCOUNT_TEXTS:
        try:
            locator = page.get_by_text(text)
            if locator.count() > 0 and locator.first.is_visible():
                return True
        except Exception:
            pass
    return False


def _ensure_email_entered(page, email: str, log_hook=None) -> None:
    _submit_email(page, email, log_hook=log_hook)
    current = page.eval_on_selector(EMAIL_INPUT_SELECTOR, "(el) => (el.value || '').trim()") if _visible(page, EMAIL_INPUT_SELECTOR) else ""
    _log(log_hook, "recover_email", f"邮箱框当前值={current!r}", "INFO")


def _wait_login_stage(page, timeout_ms: int = 15000) -> str:
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        if _visible(page, EMAIL_INPUT_SELECTOR):
            return "email"
        try:
            for selector in ("#passwordEntry", "#i0118", "input[type=\"password\"]"):
                locator = page.locator(selector)
                count = locator.count()
                for idx in range(count):
                    if locator.nth(idx).is_visible():
                        return "password"
        except Exception:
            pass
        if _has_other_account_entry(page):
            _click_use_other_account(page)
        page.wait_for_timeout(300)
    if _visible(page, EMAIL_INPUT_SELECTOR):
        return "email"
    try:
        for selector in ("#passwordEntry", "#i0118", "input[type=\"password\"]"):
            locator = page.locator(selector)
            count = locator.count()
            for idx in range(count):
                if locator.nth(idx).is_visible():
                    return "password"
    except Exception:
        pass
    if _has_other_account_entry(page):
        return "account_picker"
    return "unknown"


def _build_run_log_hook(account: dict[str, Any], outer_log_hook=None):
    debug_ref = "logs/app.log"

    def hook(stage: str, message: str, level: str = "INFO") -> None:
        _log(outer_log_hook, stage, message, level)

    return hook, debug_ref


class CaptchaSolver:
    def __init__(self, max_attempts: int, log_hook=None):
        self.max_attempts = max_attempts
        self.log_hook = log_hook

    def solve(self, page) -> bool:
        if not self._wait_for_captcha_frame(page):
            _log(self.log_hook, "captcha", "未检测到验证码 iframe", "FAIL")
            return False
        frame1 = page.frame_locator('iframe[title="验证质询"]')
        frame2 = frame1.frame_locator('iframe[style*="display: block"]')
        self._human_prelude(page)
        btn2_seen = False
        for attempt in range(self.max_attempts):
            _log(self.log_hook, "captcha", f"开始按压尝试 {attempt + 1}/{self.max_attempts}", "INFO")
            page.wait_for_timeout(random.randint(200, 600))
            box, label = self._find_target(frame2, attempt)
            if not box:
                continue
            cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
            pos_name, x, y = self._pick_position(box, cx, cy)
            _log(self.log_hook, "captcha", f"target={label} pos={pos_name}", "INFO")
            from_x, from_y = x + random.uniform(-250, 250), y + random.uniform(-250, 250)
            page.mouse.move(from_x, from_y, steps=1)
            page.wait_for_timeout(random.randint(40, 150))
            self._natural_move(page, from_x, from_y, x, y)
            page.mouse.down()
            page.wait_for_timeout(random.randint(25, 55))
            page.mouse.up()
            page.wait_for_timeout(random.randint(80, 220))
            page.mouse.down()
            page.wait_for_timeout(random.randint(25, 55))
            page.mouse.up()
            page.wait_for_timeout(random.randint(120, 380))
            page.mouse.down()
            appeared = self._hold_and_wait(page, frame2, x, y)
            if not appeared:
                page.mouse.up()
                continue
            btn2_seen = True
            if not self._execute_b2(page, frame2, x, y, random.choice(["click", "dblclick"])):
                continue
            success, retry = self._check_captcha_result(page, frame1, frame2)
            if not success:
                break
            if not retry:
                _log(self.log_hook, "captcha", "验证码通过", "OK")
                return True
        _log(self.log_hook, "captcha", "验证码未通过", "FAIL")
        if not btn2_seen:
            _log(self.log_hook, "captcha", "按钮2从未出现", "WARN")
        return False

    def _wait_for_captcha_frame(self, page) -> bool:
        for _ in range(15):
            try:
                frame1 = page.frame_locator('iframe[title="验证质询"]')
                if frame1.locator("iframe").count() > 0:
                    frame2 = frame1.frame_locator('iframe[style*="display: block"]')
                    for selector in ('[aria-label="可访问性挑战"]', "circle", "svg", '[role="button"]'):
                        try:
                            cnt = frame2.locator(selector).count()
                            if cnt > 0:
                                box = frame2.locator(selector).first.bounding_box()
                                if box and box["width"] > 5:
                                    page.wait_for_timeout(random.randint(500, 1500))
                                    return True
                        except Exception:
                            continue
            except Exception:
                pass
            page.wait_for_timeout(1000)
        return False

    def _human_prelude(self, page) -> None:
        for _ in range(random.randint(1, 4)):
            act = random.random()
            if act < 0.3:
                page.evaluate(f"window.scrollBy(0, {random.randint(-200, 200)})")
            elif act < 0.5:
                page.mouse.move(random.randint(100, 600), random.randint(100, 500), steps=random.randint(3, 8))
            elif act < 0.75:
                page.wait_for_timeout(random.randint(500, 2500))
            else:
                try:
                    pos = page.evaluate("() => ({x: 400 + Math.random()*100, y: 300 + Math.random()*100})")
                    page.mouse.move(pos["x"], pos["y"], steps=1)
                except Exception:
                    pass
            page.wait_for_timeout(random.randint(100, 800))

    def _natural_move(self, page, x1, y1, x2, y2) -> None:
        cpx = (x1 + x2) / 2 + random.uniform(-150, 150)
        cpy = (y1 + y2) / 2 + random.uniform(-120, 120)
        steps = random.randint(8, 18)
        for i in range(steps + 1):
            t = i / steps
            ease = 1 - (1 - t) ** 3
            px = (1 - ease) * x1 + ease * x2
            py = (1 - ease) * y1 + ease * y2
            bx = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cpx + t**2 * x2
            py = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cpy + t**2 * y2
            px = px * 0.6 + bx * 0.4
            page.mouse.move(px, py, steps=1)
            page.wait_for_timeout(random.randint(6, 18))
        if random.random() < 0.6:
            page.mouse.move(
                x2 + random.uniform(2, 8) * random.choice([-1, 1]),
                y2 + random.uniform(2, 6) * random.choice([-1, 1]),
                steps=1,
            )
            page.wait_for_timeout(random.randint(30, 80))
        page.mouse.move(x2, y2, steps=1)

    def _find_target(self, frame2, attempt: int):
        for selector in ('[aria-label="可访问性挑战"]', "circle", "ellipse", "svg circle", "svg ellipse", '[role="button"]', "svg"):
            try:
                candidates = frame2.locator(selector)
                cnt = candidates.count()
                if cnt > 0:
                    box = candidates.nth(attempt % min(cnt, 3)).bounding_box()
                    if box and box["width"] > 8 and box["height"] > 8:
                        return box, f"{selector}[{attempt % min(cnt, 3)}/{cnt}]"
            except Exception:
                continue
        return None, ""

    def _pick_position(self, box, cx, cy):
        r = random.random()
        if r < 0.12:
            return "center", cx + random.uniform(-3, 3), cy + random.uniform(-3, 3)
        if r < 0.3:
            edge = random.choice(["t", "b", "l", "r"])
            if edge == "t":
                return f"edge.{edge}", cx + random.uniform(-box["width"] * 0.3, box["width"] * 0.3), box["y"] + random.uniform(1, 5)
            if edge == "b":
                return f"edge.{edge}", cx + random.uniform(-box["width"] * 0.3, box["width"] * 0.3), box["y"] + box["height"] - random.uniform(1, 5)
            if edge == "l":
                return f"edge.{edge}", box["x"] + random.uniform(1, 5), cy + random.uniform(-box["height"] * 0.3, box["height"] * 0.3)
            return f"edge.{edge}", box["x"] + box["width"] - random.uniform(1, 5), cy + random.uniform(-box["height"] * 0.3, box["height"] * 0.3)
        if r < 0.48:
            corner = random.choice(["tl", "tr", "bl", "br"])
            if corner == "tl":
                return f"corner.{corner}", box["x"] + random.uniform(2, 8), box["y"] + random.uniform(2, 8)
            if corner == "tr":
                return f"corner.{corner}", box["x"] + box["width"] - random.uniform(2, 8), box["y"] + random.uniform(2, 8)
            if corner == "bl":
                return f"corner.{corner}", box["x"] + random.uniform(2, 8), box["y"] + box["height"] - random.uniform(2, 8)
            return f"corner.{corner}", box["x"] + box["width"] - random.uniform(2, 8), box["y"] + box["height"] - random.uniform(2, 8)
        return "random", cx + random.uniform(-box["width"] * 0.4, box["width"] * 0.4), cy + random.uniform(-box["height"] * 0.4, box["height"] * 0.4)

    def _hold_and_wait(self, page, frame2, x, y) -> bool:
        self._circular_tremor(page, x, y, duration_ms=random.randint(600, 1800))
        appeared = False
        for selector in ('[aria-label="再次按下"]', '[aria-label*="再次"]', '[aria-label*="按下"]'):
            try:
                frame2.locator(selector).wait_for(state="visible", timeout=10000)
                appeared = True
                break
            except Exception:
                continue
        if appeared:
            extra_ms = random.randint(1500, 4500)
            _log(self.log_hook, "captcha", f"btn2出现, 延续{extra_ms}ms", "INFO")
            self._circular_tremor(page, x, y, duration_ms=extra_ms)
        return appeared

    def _circular_tremor(self, page, x, y, duration_ms: int) -> None:
        steps = max(duration_ms // 50, 5)
        radius = random.uniform(0.3, 2.0)
        for i in range(steps):
            angle = 2 * math.pi * i / steps + random.uniform(-0.3, 0.3)
            tx = x + math.cos(angle) * radius * random.uniform(0.7, 1.3)
            ty = y + math.sin(angle) * radius * random.uniform(0.7, 1.3)
            page.mouse.move(tx, ty, steps=1)
            page.wait_for_timeout(random.randint(35, 70))

    def _execute_b2(self, page, frame2, x, y, mode: str) -> bool:
        page.wait_for_timeout(random.randint(300, 900))
        btn_box = None
        for selector in ('[aria-label="再次按下"]', '[aria-label*="再次"]', '[aria-label*="按下"]'):
            try:
                btn_box = frame2.locator(selector).bounding_box()
                if btn_box:
                    break
            except Exception:
                continue
        if not btn_box:
            return False
        bcx, bcy = btn_box["x"] + btn_box["width"] / 2, btn_box["y"] + btn_box["height"] / 2
        x2 = bcx + random.uniform(-btn_box["width"] * 0.35, btn_box["width"] * 0.35)
        y2 = bcy + random.uniform(-btn_box["height"] * 0.35, btn_box["height"] * 0.35)
        page.mouse.move(x2, y2, steps=random.randint(3, 10))
        page.wait_for_timeout(random.randint(50, 180))
        if mode == "dblclick":
            page.mouse.click(x2, y2)
            page.wait_for_timeout(random.randint(80, 200))
            page.mouse.click(x2 + random.uniform(-3, 3), y2 + random.uniform(-3, 3))
        else:
            page.mouse.click(x2, y2)
        return True

    def _check_captcha_result(self, page, frame1, frame2):
        try:
            page.locator(".draw").wait_for(state="detached")
            try:
                page.locator('[role="status"][aria-label="正在加载..."]').wait_for(timeout=5000)
                page.wait_for_timeout(8000)
                if page.get_by_text("一些异常活动").count() > 0 or page.get_by_text("此站点正在维护").count() > 0:
                    return False, False
                if frame2.locator('[aria-label="可访问性挑战"]').count() > 0:
                    return True, True
                return True, False
            except Exception:
                if page.get_by_text("取消").count() > 0:
                    return True, False
                frame1.get_by_text("请再试一次").wait_for(timeout=15000)
                return True, True
        except Exception:
            if page.get_by_text("取消").count() > 0:
                return True, False
            return False, False


def _build_temp_client(config: dict[str, Any]) -> TempMailClient:
    mail_cfg = config.get("temp_mail") or {}
    return TempMailClient(
        base_url=mail_cfg.get("base_url", ""),
        admin_password=mail_cfg.get("admin_password", ""),
        domain=mail_cfg.get("domain", ""),
        site_password=mail_cfg.get("site_password", ""),
        timeout=30,
    )


def _submit_backup_mail(page, address: str, log_hook=None) -> None:
    page.locator(BACKUP_EMAIL_SELECTOR).first.wait_for(state="visible", timeout=15000)
    page.locator(BACKUP_EMAIL_SELECTOR).first.fill(address, timeout=10000)
    _click_first_visible(page, [NEXT_SELECTOR], log_hook=log_hook, stage="backup_submit")


def _submit_backup_code(page, code: str, log_hook=None) -> None:
    page.locator(VERIFY_CODE_SELECTOR).first.wait_for(state="visible", timeout=15000)
    page.locator(VERIFY_CODE_SELECTOR).first.fill(code, timeout=10000)
    _click_first_visible(page, [NEXT_SELECTOR], log_hook=log_hook, stage="code_submit")


def recover_abuse_account(account: dict[str, Any], config: dict[str, Any], proxy_url: str = "", log_hook=None) -> dict[str, Any]:
    recovery_cfg = config.get("recovery") or {}
    wait_after_code_submit_sec = int(recovery_cfg.get("wait_after_code_submit_sec", 8) or 8)
    headless = bool(recovery_cfg.get("headless", False))
    captcha_max_attempts = int(recovery_cfg.get("captcha_max_attempts", 4) or 4)
    temp_client = _build_temp_client(config)
    p = sync_playwright().start()
    browser = None
    page = None
    temp_mail_address = ""
    code_mail = None
    run_log_hook, run_log_path = _build_run_log_hook(account, outer_log_hook=log_hook)
    try:
        _log(run_log_hook, "recover_start", f"开始恢复 account_id={account.get('id', '')} email={account.get('email', '')}", "INFO")
        _log(run_log_hook, "recover_config", f"headless={headless} proxy={proxy_url or '(none)'} wait_after_code_submit_sec={wait_after_code_submit_sec}", "INFO")
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
        page.goto(MAIL_URL, timeout=45000, wait_until="domcontentloaded")
        _log(run_log_hook, "recover_open", f"已打开 Outlook 邮箱页面 url={page.url}", "INFO")
        _click_use_other_account(page)
        stage = _wait_login_stage(page, timeout_ms=15000)
        _log(run_log_hook, "recover_stage", f"初始登录阶段={stage}", "INFO")
        if stage == "account_picker":
            _click_use_other_account(page)
            stage = _wait_login_stage(page, timeout_ms=12000)
            _log(run_log_hook, "recover_stage", f"切换其他账号后阶段={stage}", "INFO")
        if stage in ("email", "unknown"):
            if stage == "unknown":
                _log(run_log_hook, "recover_stage", f"初始阶段 unknown，回退到邮箱输入流程 url={page.url}", "WARN")
            _ensure_email_entered(page, account["email"], log_hook=run_log_hook)
            stage = _wait_login_stage(page, timeout_ms=12000)
            _log(run_log_hook, "recover_stage", f"邮箱提交后阶段={stage}", "INFO")
            if stage != "password":
                err = page.eval_on_selector("#usernameError", "(el) => (el.innerText || '').trim()") if page.locator("#usernameError").count() > 0 else ""
                _log(run_log_hook, "recover_fail", f"邮箱提交后未进入密码页 err={err!r} url={page.url}", "FAIL")
                return {
                    "success": False,
                    "status": "fail",
                    "reason_code": "service_retryable",
                    "reason": f"邮箱提交后未进入密码页: {err or 'unknown'}",
                    "temp_mail": temp_mail_address,
                    "debug_log": str(run_log_path),
                }
        elif stage != "password":
            _log(run_log_hook, "recover_fail", f"未识别到邮箱页或密码页 url={page.url}", "FAIL")
            return {
                "success": False,
                "status": "fail",
                "reason_code": "service_retryable",
                "reason": "未识别到邮箱页或密码页",
                "temp_mail": temp_mail_address,
                "debug_log": str(run_log_path),
            }
        _submit_password(page, account["password"], log_hook=run_log_hook, stage="recover_password")
        _log(run_log_hook, "recover_password", f"已提交密码，当前url={page.url}", "INFO")
        solver = CaptchaSolver(max_attempts=captcha_max_attempts, log_hook=log_hook)
        for _ in range(80):
            page.wait_for_timeout(1200)
            if _any_text_exists(page, UNRECOVERABLE_TEXTS):
                _log(run_log_hook, "recover_fail", "微软阻止恢复该账号", "FAIL")
                return {
                    "success": False,
                    "status": "fail",
                    "reason_code": "unrecoverable_abuse",
                    "reason": "微软阻止恢复该账号",
                    "temp_mail": temp_mail_address,
                    "debug_log": str(run_log_path),
                }
            if _any_text_exists(page, SERVICE_RETRY_TEXTS):
                _log(run_log_hook, "recover_retry", f"命中服务异常重试页 url={page.url}", "WARN")
                if _click_first_visible(page, [PRIMARY_SELECTOR], log_hook=run_log_hook, stage="recover_retry"):
                    continue
                return {
                    "success": False,
                    "status": "fail",
                    "reason_code": "service_retryable",
                    "reason": "微软服务异常页无法自动重试",
                    "temp_mail": temp_mail_address,
                    "debug_log": str(run_log_path),
                }
            if _any_text_exists(page, ABUSE_TEXTS):
                _log(run_log_hook, "recover_abuse", "命中 ABUSE 锁定页，准备点击下一步", "INFO")
                _click_first_visible(page, [PRIMARY_SELECTOR], log_hook=run_log_hook, stage="recover_abuse_next")
                continue
            if _visible(page, 'iframe[title="验证质询"]'):
                if not solver.solve(page):
                    _log(run_log_hook, "recover_fail", "人机验证未通过", "FAIL")
                    return {
                        "success": False,
                        "status": "fail",
                        "reason_code": "captcha_failed",
                        "reason": "人机验证未通过",
                        "temp_mail": temp_mail_address,
                        "debug_log": str(run_log_path),
                    }
                continue
            if _any_text_exists(page, UNBLOCKED_TEXTS):
                _log(run_log_hook, "recover_unblocked", "已检测到账号解封提示，点击继续", "INFO")
                _click_first_visible(page, [PRIMARY_SELECTOR], log_hook=run_log_hook, stage="recover_continue")
                continue
            if _visible(page, BACKUP_EMAIL_SELECTOR):
                if not temp_mail_address:
                    mailbox = temp_client.create_random_address()
                    temp_mail_address = mailbox["address"]
                    _log(run_log_hook, "temp_mail", f"已创建备用邮箱 {temp_mail_address}", "INFO")
                    _submit_backup_mail(page, temp_mail_address, log_hook=run_log_hook)
                continue
            if _visible(page, VERIFY_CODE_SELECTOR):
                if not temp_mail_address:
                    _log(run_log_hook, "recover_fail", "未创建备用邮箱即进入验证码页", "FAIL")
                    return {
                        "success": False,
                        "status": "fail",
                        "reason_code": "temp_mail_timeout",
                        "reason": "未创建备用邮箱即进入验证码页",
                        "temp_mail": temp_mail_address,
                        "debug_log": str(run_log_path),
                    }
                code_mail = temp_client.wait_for_code(
                    temp_mail_address,
                    timeout_sec=int(recovery_cfg.get("mail_poll_timeout_sec", 180) or 180),
                    interval_sec=int(recovery_cfg.get("mail_poll_interval_sec", 5) or 5),
                    log_hook=run_log_hook,
                )
                _submit_backup_code(page, code_mail["code"], log_hook=run_log_hook)
                _log(run_log_hook, "recover_code", f"验证码已提交，等待 {wait_after_code_submit_sec} 秒后关闭浏览器", "INFO")
                page.wait_for_timeout(wait_after_code_submit_sec * 1000)
                break
            if "outlook.live.com/mail/" in page.url or "outlook.office.com/mail/" in page.url:
                _log(run_log_hook, "recover_mail", "检测到已进入邮箱，直接开始重新授权", "INFO")
                break
        else:
            _log(run_log_hook, "recover_fail", f"恢复流程超时，未进入可重新授权状态 url={page.url}", "FAIL")
            return {
                "success": False,
                "status": "fail",
                "reason_code": "service_retryable",
                "reason": "恢复流程超时，未进入可重新授权状态",
                "temp_mail": temp_mail_address,
                "debug_log": str(run_log_path),
            }
    except TimeoutError as exc:
        _log(run_log_hook, "recover_fail", f"TimeoutError: {exc}", "FAIL")
        return {
            "success": False,
            "status": "fail",
            "reason_code": "temp_mail_timeout",
            "reason": str(exc),
            "temp_mail": temp_mail_address,
            "debug_log": str(run_log_path),
        }
    except Exception as exc:
        _log(run_log_hook, "recover_fail", f"Exception: {exc}", "FAIL")
        return {
            "success": False,
            "status": "fail",
            "reason_code": "service_retryable",
            "reason": str(exc),
            "temp_mail": temp_mail_address,
            "debug_log": str(run_log_path),
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

    try:
        oauth = reauthorize_account(
            email=account["email"],
            password=account["password"],
            client_id=account["client_id"],
            proxy_url=proxy_url,
            headless=headless,
            log_hook=run_log_hook,
        )
        _log(run_log_hook, "recover_done", "ABUSE 解封并重新授权成功", "OK")
        return {
            "success": True,
            "status": "ok",
            "reason_code": "recoverable_abuse",
            "reason": "ABUSE 解封并重新授权成功",
            "refresh_token": oauth["refresh_token"],
            "oauth_scope": oauth.get("scope", ""),
            "temp_mail": temp_mail_address,
            "code_mail_id": (code_mail or {}).get("mail_id", ""),
            "debug_log": str(run_log_path),
        }
    except Exception as exc:
        _log(run_log_hook, "recover_fail", f"reauth_failed: {exc}", "FAIL")
        return {
            "success": False,
            "status": "fail",
            "reason_code": "reauth_failed",
            "reason": str(exc),
            "temp_mail": temp_mail_address,
            "code_mail_id": (code_mail or {}).get("mail_id", ""),
            "debug_log": str(run_log_path),
        }
