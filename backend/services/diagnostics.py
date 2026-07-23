"""错误码解析与健康分类：把微软 AADSTS 码 / 协议探测结果翻译成明确的中文原因与严重级。

severity 取值：ok（绿）/ warn（黄）/ fail（红）/ banned（红，账号级失效或封禁）。
"""
import json
import re
from typing import Any

# AADSTS 码 -> (中文原因, severity)
AADSTS_REASONS: dict[str, tuple[str, str]] = {
    "50034": ("账号不存在或已被删除", "banned"),
    "50053": ("账号被锁定（风控/多次失败/异常登录）", "banned"),
    "50055": ("密码已过期", "fail"),
    "50056": ("账号无密码或密码无效", "fail"),
    "50057": ("账号已被禁用", "banned"),
    "50058": ("会话信息不足，需要重新交互登录", "fail"),
    "50059": ("无法识别租户", "fail"),
    "50076": ("需要多因素认证(MFA)", "fail"),
    "50079": ("需要注册多因素认证(MFA)", "fail"),
    "50126": ("用户名或密码错误", "fail"),
    "50128": ("租户无效（域名不存在）", "fail"),
    "50173": ("Token 已失效（密码被改/会话被撤销），需重新授权", "fail"),
    "65001": ("用户或管理员未同意应用所需权限", "fail"),
    "650051": ("应用未配置所请求的权限", "fail"),
    "650053": ("应用未声明该 scope（如 IMAP/POP/SMTP 权限未授予）", "fail"),
    "70000": ("授权许可无效（refresh token 失效）", "fail"),
    "70008": ("Refresh token 已过期或被撤销", "fail"),
    "700082": ("Refresh token 因 90 天未使用而过期", "fail"),
    "700084": ("Refresh token 已超过最长有效期", "fail"),
    "7000218": ("请求缺少 client_secret/client_assertion（应用需要密钥）", "fail"),
    "7000222": ("client_secret 已过期", "fail"),
    "9002313": ("请求格式错误（invalid request）", "fail"),
    "900023": ("指定租户标识无效", "fail"),
    "90002": ("租户不存在", "fail"),
}

_AADSTS_RE = re.compile(r"AADSTS(\d+)")
_OAUTH_ERR_RE = re.compile(r'"error"\s*:\s*"([a-z_]+)"')

# OAuth error 字段兜底（无 AADSTS 码时）
OAUTH_ERROR_REASONS: dict[str, tuple[str, str]] = {
    "invalid_grant": ("授权失效：refresh token 已过期或被撤销", "fail"),
    "invalid_client": ("客户端无效：client_id 错误或应用配置异常", "fail"),
    "invalid_request": ("请求无效：参数缺失或格式错误", "fail"),
    "unauthorized_client": ("应用未被授权使用该授权类型", "fail"),
    "invalid_scope": ("请求的权限范围无效", "fail"),
    "interaction_required": ("需要用户交互（MFA/同意）", "fail"),
    "consent_required": ("需要用户/管理员授予权限", "fail"),
}

RECOVERY_REASON_REASONS: dict[str, tuple[str, str]] = {
    "recoverable_abuse": ("账号处于可恢复的 ABUSE 封禁流程", "warn"),
    "unrecoverable_abuse": ("微软判定该账号当前不可恢复", "banned"),
    "captcha_failed": ("人机验证未通过", "fail"),
    "temp_mail_timeout": ("备用邮箱验证码超时未收到", "fail"),
    "code_invalid": ("备用邮箱验证码无效或提交失败", "fail"),
    "reauth_failed": ("解封后重新授权失败", "fail"),
    "service_retryable": ("微软服务异常，可稍后重试", "fail"),
    "not_abuse": ("当前账号不是 ABUSE 恢复目标", "warn"),
}


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def analyze_error(error: Any) -> dict[str, str]:
    """解析刷新/取 token 的错误文本，返回 {code, reason, severity, raw}。"""
    raw = _to_text(error)
    if not raw:
        return {"code": "", "reason": "未知错误", "severity": "fail", "raw": ""}

    low = raw.lower()
    # 特例：微软风控/滥用封禁（常见于 AADSTS70000 但语义是封号）
    if "service abuse" in low or "abuse mode" in low:
        return {"code": "ABUSE", "reason": "账号被微软风控判定为滥用并封禁（service abuse mode）", "severity": "banned", "raw": raw[:1000]}
    if "account is locked" in low or "account locked" in low:
        return {"code": "LOCKED", "reason": "账号被锁定", "severity": "banned", "raw": raw[:1000]}

    code_match = _AADSTS_RE.search(raw)
    if code_match:
        code = code_match.group(1)
        if code in AADSTS_REASONS:
            reason, severity = AADSTS_REASONS[code]
            return {"code": f"AADSTS{code}", "reason": reason, "severity": severity, "raw": raw[:1000]}
        return {"code": f"AADSTS{code}", "reason": f"微软返回错误 AADSTS{code}", "severity": "fail", "raw": raw[:1000]}

    oauth_match = _OAUTH_ERR_RE.search(raw)
    if oauth_match:
        key = oauth_match.group(1)
        if key in OAUTH_ERROR_REASONS:
            reason, severity = OAUTH_ERROR_REASONS[key]
            return {"code": key, "reason": reason, "severity": severity, "raw": raw[:1000]}
        return {"code": key, "reason": key, "severity": "fail", "raw": raw[:1000]}

    return {"code": "", "reason": raw[:200], "severity": "fail", "raw": raw[:1000]}


def analyze_recovery_reason(code: str, detail: Any = "") -> dict[str, str]:
    raw = _to_text(detail)
    if code in RECOVERY_REASON_REASONS:
        reason, severity = RECOVERY_REASON_REASONS[code]
        if raw:
            reason = f"{reason}：{raw[:200]}"
        return {"code": code, "reason": reason, "severity": severity, "raw": raw[:1000]}
    if raw:
        return {"code": code, "reason": raw[:200], "severity": "fail", "raw": raw[:1000]}
    return {"code": code, "reason": code or "未知恢复错误", "severity": "fail", "raw": raw[:1000]}


# 协议层失败原因翻译
def _protocol_reason(item: dict[str, Any]) -> str:
    text = _to_text(item).lower()
    if "disabled" in text:
        return "协议被禁用（租户/账号未开启该协议）"
    if "authenticationfailed" in text or "loginfailed" in text or "auth" in text and "fail" in text:
        return "协议认证失败"
    if not item.get("token_ok", True):
        analysis = analyze_error(item.get("error", ""))
        return f"取 token 失败：{analysis['reason']}"
    if "not connected" in text or "timed out" in text or "timeout" in text:
        return "连接超时/网络不通（检查代理）"
    return "协议探测失败"


def build_health(result: dict[str, Any]) -> dict[str, Any]:
    """由 test_protocols.py 的结果 JSON 生成统一健康视图。

    返回：health_status, health_severity, ban_reason, error_detail,
          graph_status, imap_status, pop_status, smtp_status, problems[]。
    """
    baseline = result.get("baseline", {}) or {}
    protocols = result.get("protocols", {}) or {}
    account_health = baseline.get("account_health", "")

    graph_token_ok = baseline.get("graph_token_ok", False)
    graph_profile_ok = baseline.get("graph_profile_ok", False)
    graph_read_ok = baseline.get("graph_read_ok", False)

    # 账号级失效（取 token 都失败）：直接判死，不再堆叠各协议的重复错误
    if not graph_token_ok:
        attempts = baseline.get("graph_token_attempts", []) or []
        last_detail = attempts[-1].get("details", "") if attempts else ""
        analysis = analyze_error(last_detail)
        ban_reason = f"[{analysis['code']}] {analysis['reason']}" if analysis["code"] else analysis["reason"]
        severity = "banned" if analysis["severity"] == "banned" else "fail"
        health = "banned" if severity == "banned" else "token_invalid"
        return {
            "health_status": health,
            "health_severity": severity,
            "ban_reason": ban_reason,
            "error_detail": ban_reason,
            "graph_status": "fail",
            "imap_status": "fail",
            "pop_status": "fail",
            "smtp_status": "fail",
            "problems": [f"Graph 取 token 失败：{ban_reason}"],
        }

    problems: list[str] = []

    def proto_status(name: str) -> str:
        item = protocols.get(name, {}) or {}
        if item.get("ok"):
            return "ok"
        text = _to_text(item).lower()
        if "disabled" in text:
            problems.append(f"{name.upper()} 被禁用")
            return "disabled"
        if item.get("token_ok") and not item.get("ok"):
            problems.append(f"{name.upper()} 取 token 成功但连接/认证失败：{_protocol_reason(item)}")
            return "token_only"
        problems.append(f"{name.upper()} 不可用：{_protocol_reason(item)}")
        return "fail"

    imap_status = proto_status("imap")
    pop_status = proto_status("pop")
    smtp_status = proto_status("smtp")  # 仍计算并在表格显示，但不参与 Health 分类

    if graph_profile_ok and graph_read_ok:
        graph_status = "ok"
    elif not graph_profile_ok:
        graph_status = "fail"
        problems.insert(0, "Graph 取 token 成功但读取账户信息(/me)失败")
    else:
        graph_status = "warn"
        problems.insert(0, "Graph 可登录但读取邮件失败（可能缺 Mail.Read 权限）")

    # Health 分类（仅看 Graph 与 IMAP/POP，忽略 SMTP）：
    #   all        Graph + IMAP/POP 均可用
    #   graph_only 仅 Graph 可用
    #   imap_pop   仅 IMAP/POP 可用（Graph 受限）
    #   banned     可取 token 但 Graph/IMAP/POP 全不可用（疑似受限）
    g_ok = graph_status in ("ok", "warn")
    ip_ok = imap_status == "ok" or pop_status == "ok"
    ban_reason = ""
    if g_ok and ip_ok:
        health, severity = "all", "ok"
    elif g_ok:
        health, severity = "graph_only", "warn"
    elif ip_ok:
        health, severity = "imap_pop", "warn"
    else:
        health, severity = "banned", "banned"
        ban_reason = "可取 token 但 Graph/IMAP/POP 均不可用（疑似受限）"

    error_detail = "；".join(dict.fromkeys(problems[:6]))  # 去重保序

    return {
        "health_status": health,
        "health_severity": severity,
        "ban_reason": ban_reason,
        "error_detail": error_detail,
        "graph_status": graph_status,
        "imap_status": imap_status,
        "pop_status": pop_status,
        "smtp_status": smtp_status,
        "problems": problems,
    }
