import json
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
import urllib3
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.db import add_history, get_conn, init_db
from backend.services import diagnostics, jobs, locks
from backend.services.abuse_recovery import recover_abuse_account
from backend.services.protocols import run_protocol_test
from backend.services.remote_pool import (
    IMPORT_BATCH_SIZE,
    build_session,
    chunked,
    delete_account_remote,
    find_account,
    get_account_detail,
    get_csrf,
    import_accounts,
    index_accounts_by_email,
    list_accounts as list_remote_accounts,
    login,
    update_remote_token,
)

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"
LOG_PATH = ROOT / "logs" / "app.log"
CONFIG_PATH = ROOT / "config.json"
TEST_SCRIPT = ROOT / "test_protocols.py"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
HTTP_TIMEOUT = 30
SUSPECTED_RESTRICTED_REASON = "可取 token 但 Graph/IMAP/POP 均不可用（疑似受限）"
ABUSE_HINTS = (
    "service abuse",
    "abuse mode",
    "[abuse]",
    "账号被微软风控判定为滥用并封禁",
    "违反 microsoft 服务协议",
    "锁定了你的帐户",
)

PYTHON_EXE = sys.executable


def now_local() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_time_value(value: str | None) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return dt.timestamp()
    except ValueError:
        return None


def token_time(row: dict[str, Any] | Any) -> str:
    if isinstance(row, dict):
        return str(row.get("refresh_token_updated_at") or row.get("last_refresh_at") or "").strip()
    return str(row["refresh_token_updated_at"] or row["last_refresh_at"] or "").strip()


def load_config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


CONFIG = load_config()
_CONFIG_LOCK = threading.RLock()
_LOG_LOCK = threading.Lock()
DB_PATH = ROOT / CONFIG["database"]["path"]
init_db(DB_PATH)
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_config() -> dict[str, Any]:
    with _CONFIG_LOCK:
        return CONFIG


def proxy_url() -> str:
    cfg = get_config()
    return ((cfg.get("proxy") or {}).get("url") or "").strip()

def group_for_email(email: str):
    """按邮箱后缀返回目标远程分组 id；未映射且 skip_unmapped 时返回 None（跳过）。"""
    remote = get_config()["remote"]
    gmap = {str(k).lower(): int(v) for k, v in (remote.get("group_map") or {}).items()}
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    if domain in gmap:
        return gmap[domain]
    if remote.get("skip_unmapped", True):
        return None
    return remote.get("default_group_id") or remote.get("group_id") or 1


def resync_target_group(email: str, current_gid):
    """resync 时的分组纠正目标：仅当账号当前位于批量分组(如 3/8)且与域名不符时返回正确分组；
    个人(1)/临时(2)/默认(9)等非批量分组一律返回 None=保留，绝不挪动用户手动归类的账号。"""
    remote = get_config()["remote"]
    gmap = {str(k).lower(): int(v) for k, v in (remote.get("group_map") or {}).items()}
    bulk = set(gmap.values())
    try:
        current_gid = int(current_gid)
    except (TypeError, ValueError):
        current_gid = None
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
    domain_gid = gmap.get(domain)
    if domain_gid is not None and current_gid in bulk and current_gid != domain_gid:
        return domain_gid
    return None


def log_event(stage: str, message: str, level: str = "INFO") -> None:
    line = f"[{stage}][{level}] {datetime.now().strftime('%H:%M:%S')} | {message}"
    with _LOG_LOCK:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line)


def is_banned_row(row: dict[str, Any] | Any) -> bool:
    """统一封禁判定：health_status 或 health_severity 任一为 banned。"""
    if isinstance(row, dict):
        hs = str(row.get("health_status") or "").strip()
        sev = str(row.get("health_severity") or "").strip()
    else:
        hs = str(row["health_status"] or "").strip()
        sev = str(row["health_severity"] or "").strip()
    return hs == "banned" or sev == "banned"


SQL_NOT_BANNED = (
    "(COALESCE(health_status, '') != 'banned' AND COALESCE(health_severity, '') != 'banned')"
)


def account_line(row) -> str:
    return f"{row['email']}----{row['password']}----{row['client_id']}----{row['refresh_token']}"


def row_text(row: dict[str, Any] | Any, *keys: str) -> str:
    if isinstance(row, dict):
        return " ".join(str(row.get(key, "") or "") for key in keys).lower()
    return " ".join(str(row[key] or "") for key in keys).lower()


def is_abuse_candidate(row: dict[str, Any] | Any) -> bool:
    # 滥用封禁 = ABUSE 候选（与 is_banned_row 一致）
    return is_banned_row(row)


def is_normal_account(row: dict[str, Any] | Any) -> bool:
    getter = row.get if isinstance(row, dict) else row.__getitem__
    return any((getter(key) or "") == "ok" for key in ("graph_status", "imap_status", "pop_status"))


def is_untested_account(row: dict[str, Any] | Any) -> bool:
    getter = row.get if isinstance(row, dict) else row.__getitem__
    return not (getter("health_status") or "") and not (getter("last_protocol_test_at") or "") and not (getter("error_detail") or "")


def is_other_error_account(row: dict[str, Any] | Any) -> bool:
    getter = row.get if isinstance(row, dict) else row.__getitem__
    if is_normal_account(row) or is_banned_row(row) or is_untested_account(row):
        return False
    return (getter("health_status") or "") in ("other_error", "token_invalid") or (getter("status") or "") == "proto_error" or bool(getter("error_detail") or "")


def summarize_protocol_error(outcome: dict[str, Any]) -> str:
    parts = []
    for key in ("error", "stderr", "stdout"):
        value = str(outcome.get(key) or "").strip()
        if value:
            parts.append(value.replace("\n", " | "))
    text = " | ".join(parts)
    return text[:1000] if text else "协议测试失败"


def suspected_restricted(health: dict[str, Any]) -> bool:
    return (health.get("ban_reason") or "") == SUSPECTED_RESTRICTED_REASON


def to_other_error(health: dict[str, Any], reason: str) -> dict[str, Any]:
    patched = dict(health)
    patched["health_status"] = "other_error"
    patched["health_severity"] = "fail"
    patched["ban_reason"] = ""
    patched["error_detail"] = reason
    return patched


def is_alive_health(health: dict[str, Any]) -> bool:
    return (health.get("health_severity") or "") in ("ok", "warn")


def run_cancellable(items, workers: int, worker, is_cancelled) -> None:
    item_iter = iter(items)
    pending = set()

    def submit_next(pool: ThreadPoolExecutor) -> bool:
        if is_cancelled():
            return False
        try:
            item = next(item_iter)
        except StopIteration:
            return False
        pending.add(pool.submit(worker, item))
        return True

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for _ in range(workers):
            submit_next(pool)
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                future.result()
            if is_cancelled():
                break
            for _ in range(len(done)):
                submit_next(pool)


# ---------------- Pydantic ----------------
class ImportPayload(BaseModel):
    text: str


class BatchPayload(BaseModel):
    ids: list[int] | None = None
    concurrency: int | None = None


MAX_CONCURRENCY = 100


def clamp_concurrency(value, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_CONCURRENCY, n))


class ConfigPayload(BaseModel):
    proxy_url: str | None = None
    remote_base_url: str | None = None
    remote_password: str | None = None
    group_map: dict[str, int] | None = None
    skip_unmapped: bool | None = None
    external_recipient: str | None = None
    default_concurrency: int | None = None


class EditPayload(BaseModel):
    password: str | None = None
    client_id: str | None = None
    refresh_token: str | None = None
    remark: str | None = None


class RecoveryBatchPayload(BaseModel):
    ids: list[int] | None = None
    concurrency: int | None = None
    include_over_limit: bool = False


app = FastAPI(title="Outlook Manage WebUI")
app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="assets")


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/scope.md")
def scope_doc():
    return FileResponse(ROOT / "scope.md")


# ---------------- 状态统计（DB 缓存，启动秒开） ----------------
_stats_lock = threading.Lock()
_stats_refresh_timer: threading.Timer | None = None
_STATS_DEBOUNCE_SEC = 1.2


def _compute_stats_summary(conn) -> dict[str, Any]:
    def count(where: str = "", params: tuple = ()) -> int:
        sql = "SELECT COUNT(*) FROM accounts" + (f" WHERE {where}" if where else "")
        return int(conn.execute(sql, params).fetchone()[0])

    normal = count("graph_status='ok' OR imap_status='ok' OR pop_status='ok'")
    banned = count("health_status='banned' OR health_severity='banned'")
    untested = count(
        "COALESCE(health_status,'')='' AND COALESCE(last_protocol_test_at,'')='' "
        "AND COALESCE(error_detail,'')=''"
    )
    other_error = count(
        "(health_status IN ('token_invalid','other_error') OR status='proto_error') "
        "AND COALESCE(health_status,'') != 'banned' AND COALESCE(health_severity,'') != 'banned'"
    )
    # never_synced：正常可用且未进入远程 ready 状态
    never_synced = count(
        "(graph_status='ok' OR imap_status='ok' OR pop_status='ok') "
        "AND COALESCE(remote_sync_status,'') NOT IN ('imported','exists','synced')"
    )
    return {
        "total_accounts": count(),
        "total": count(),  # 前端别名
        "healthy": normal,
        "normal": normal,
        "graph_only": count("health_status='graph_only'"),
        "banned": banned,
        "other_error": other_error,
        "untested": untested,
        "graph": count("graph_status='ok'"),
        "imap_pop": count("imap_status='ok' OR pop_status='ok'"),
        "refreshed": count("last_refresh_at != '' AND last_refresh_at IS NOT NULL"),
        "remote_ready": count("remote_sync_status IN ('imported','exists','synced')"),
        "synced": count(
            "(graph_status='ok' OR imap_status='ok' OR pop_status='ok') "
            "AND remote_sync_status IN ('imported','exists','synced')"
        ),
        "remote_dirty": count("remote_sync_status='dirty'"),
        "never_synced": never_synced,
        "pop_disabled": count("pop_status='disabled'"),
        "smtp_disabled": count("smtp_status='disabled'"),
        "imap_disabled": count("imap_status='disabled'"),
    }


def rebuild_stats_cache() -> dict[str, Any]:
    """全表聚合一次并写入 stats_cache，供 /api/status 快速读取。"""
    ts = now_local()
    with get_conn(DB_PATH) as conn:
        summary = _compute_stats_summary(conn)
        summary["cached_at"] = ts
        conn.execute(
            """
            INSERT INTO stats_cache (id, payload, updated_at) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at
            """,
            (json.dumps(summary, ensure_ascii=False), ts),
        )
        conn.commit()
    return summary


def read_stats_cache() -> dict[str, Any] | None:
    try:
        with get_conn(DB_PATH) as conn:
            row = conn.execute("SELECT payload, updated_at FROM stats_cache WHERE id=1").fetchone()
        if not row:
            return None
        data = json.loads(row["payload"] or "{}")
        if not isinstance(data, dict) or not data:
            return None
        data.setdefault("cached_at", row["updated_at"] or "")
        return data
    except Exception:
        return None


def schedule_stats_refresh(delay: float | None = None) -> None:
    """账号变更后防抖刷新统计缓存（后台线程，不挡请求）。"""
    global _stats_refresh_timer
    wait = _STATS_DEBOUNCE_SEC if delay is None else max(0.0, float(delay))

    def _run() -> None:
        global _stats_refresh_timer
        try:
            rebuild_stats_cache()
        except Exception as exc:  # noqa: BLE001
            try:
                log_event("STATS", f"统计缓存刷新失败：{exc}", "WARN")
            except Exception:
                pass
        finally:
            with _stats_lock:
                _stats_refresh_timer = None

    with _stats_lock:
        if _stats_refresh_timer is not None:
            try:
                _stats_refresh_timer.cancel()
            except Exception:
                pass
        t = threading.Timer(wait, _run)
        t.daemon = True
        _stats_refresh_timer = t
        t.start()


# 启动时预热统计缓存（空则同步算一次；已有则后台刷新）
def _bootstrap_stats_cache() -> None:
    cached = read_stats_cache()
    if cached is None:
        try:
            rebuild_stats_cache()
        except Exception:
            pass
    else:
        schedule_stats_refresh(0.05)


_bootstrap_stats_cache()


@app.get("/api/status")
def status(refresh: bool = False):
    """优先读 DB 缓存；无缓存或 refresh=1 时现算并回写。"""
    summary = None if refresh else read_stats_cache()
    from_cache = summary is not None
    if summary is None:
        summary = rebuild_stats_cache()
        from_cache = False
    return {
        "success": True,
        "summary": summary,
        "from_cache": from_cache,
        "server_time": now_local(),
    }


_LIST_PUBLIC_COLS = (
    "id,email,client_id,status,health_status,health_severity,ban_reason,error_detail,"
    "graph_status,imap_status,pop_status,smtp_status,registered_at,registered_source,"
    "last_alive_at,last_refresh_at,last_refresh_status,last_refresh_error,"
    "refresh_token_updated_at,last_protocol_test_at,remote_sync_status,remote_sync_at,"
    "remote_sync_error,remote_last_refresh_at,remote_last_refresh_status,token_sync_status,"
    "remote_id,remark,created_at,updated_at,recovery_status,recovery_attempts,"
    "recovery_last_at,recovery_last_reason,oauth_reauth_at,oauth_reauth_status"
)


@app.get("/api/accounts")
def list_accounts(include_secrets: bool = False):
    """列表默认不返回 password/refresh_token（减体积、降泄露面）；详情接口仍返回完整字段。"""
    with get_conn(DB_PATH) as conn:
        if include_secrets:
            rows = conn.execute("SELECT * FROM accounts ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                f"SELECT {_LIST_PUBLIC_COLS} FROM accounts ORDER BY id DESC"
            ).fetchall()
    return {"success": True, "items": [dict(row) for row in rows], "secrets": bool(include_secrets)}


@app.get("/api/logs")
def list_logs(limit: int = 300):
    if not LOG_PATH.exists():
        return {"success": True, "lines": []}
    limit = max(1, min(int(limit or 300), 2000))
    # 大日志避免整文件读入：倒序读尾部
    try:
        with _LOG_LOCK:
            with LOG_PATH.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                block = 8192
                data = b""
                while size > 0 and data.count(b"\n") <= limit:
                    step = min(block, size)
                    size -= step
                    f.seek(size)
                    data = f.read(step) + data
                text = data.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        if lines and not text.endswith("\n") and size > 0:
            # 首行可能被截断
            lines = lines[1:]
        return {"success": True, "lines": lines[-limit:]}
    except Exception:
        with _LOG_LOCK:
            lines = LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
        return {"success": True, "lines": lines[-limit:]}


@app.post("/api/logs/clear")
def clear_logs():
    if LOG_PATH.exists():
        LOG_PATH.write_text("", encoding="utf-8")
    log_event("LOG", "日志已清空")
    return {"success": True}


# ---------------- 导出（筛选存活账号 → 下载 → 仅删除已导出） ----------------
_export_cache: dict[str, dict[str, Any]] = {}
_export_cache_lock = threading.Lock()
EXPORT_CACHE_TTL_SEC = 3600


def _parse_account_dt(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(text[:19], fmt)
                break
            except ValueError:
                dt = None  # type: ignore[assignment]
        else:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def _account_registered_dt(row: dict[str, Any] | Any) -> datetime | None:
    getter = row.get if isinstance(row, dict) else row.__getitem__
    return _parse_account_dt(getter("registered_at")) or _parse_account_dt(getter("created_at"))


def _email_domain(email: str) -> str:
    parts = str(email or "").strip().lower().rsplit("@", 1)
    return parts[1] if len(parts) == 2 else ""


def _domain_bucket(email: str) -> str:
    d = _email_domain(email)
    if d == "outlook.com":
        return "outlook.com"
    if d == "hotmail.com":
        return "hotmail.com"
    return ""


def split_export_quota(count: int, domain: str) -> dict[str, int]:
    """全部时 outlook=ceil(n/2), hotmail=floor(n/2)；单后缀时一侧为 count。"""
    n = max(0, int(count))
    domain = (domain or "all").strip().lower()
    if domain in ("outlook.com", "outlook"):
        return {"outlook.com": n, "hotmail.com": 0}
    if domain in ("hotmail.com", "hotmail"):
        return {"outlook.com": 0, "hotmail.com": n}
    # all
    return {"outlook.com": (n + 1) // 2, "hotmail.com": n // 2}


def is_export_alive(row: dict[str, Any] | Any) -> bool:
    """导出候选：非 banned 且 graph/imap/pop 任一 ok。"""
    if is_banned_row(row):
        return False
    return is_normal_account(row)


def is_min_registered_days(row: dict[str, Any] | Any, min_days: int, now: datetime | None = None) -> bool:
    days = max(0, int(min_days))
    if days <= 0:
        return True  # 不限制注册天数
    reg = _account_registered_dt(row)
    if not reg:
        return False
    base = now or datetime.now()
    return (base - reg).total_seconds() >= days * 86400


def list_export_eligible(
    domain: str,
    min_registered_days: int,
    *,
    now: datetime | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """按后缀返回已排序的候选账号（注册时间升序）。"""
    domain = (domain or "all").strip().lower()
    with get_conn(DB_PATH) as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM accounts").fetchall()]
    now = now or datetime.now()
    buckets: dict[str, list[dict[str, Any]]] = {"outlook.com": [], "hotmail.com": []}
    for row in rows:
        if not is_export_alive(row):
            continue
        if not is_min_registered_days(row, min_registered_days, now=now):
            continue
        bucket = _domain_bucket(row.get("email") or "")
        if domain in ("outlook.com", "outlook") and bucket != "outlook.com":
            continue
        if domain in ("hotmail.com", "hotmail") and bucket != "hotmail.com":
            continue
        if domain in ("all", "", "全部") and bucket not in buckets:
            continue
        if bucket in buckets:
            buckets[bucket].append(row)

    def sort_key(r: dict[str, Any]) -> tuple:
        dt = _account_registered_dt(r) or datetime.max
        return (dt, int(r.get("id") or 0))

    for key in buckets:
        buckets[key].sort(key=sort_key)
    return buckets


def plan_export_selection(
    count: int,
    domain: str,
    min_registered_days: int,
) -> dict[str, Any]:
    quota = split_export_quota(count, domain)
    buckets = list_export_eligible(domain, min_registered_days)
    selected_outlook = buckets["outlook.com"][: quota["outlook.com"]]
    selected_hotmail = buckets["hotmail.com"][: quota["hotmail.com"]]
    # 合并后按注册时间全局排序输出
    selected = selected_outlook + selected_hotmail
    selected.sort(key=lambda r: (_account_registered_dt(r) or datetime.max, int(r.get("id") or 0)))
    plan_total = quota["outlook.com"] + quota["hotmail.com"]
    exported = len(selected)
    return {
        "quota": quota,
        "eligible_outlook": len(buckets["outlook.com"]),
        "eligible_hotmail": len(buckets["hotmail.com"]),
        "eligible_total": len(buckets["outlook.com"]) + len(buckets["hotmail.com"]),
        "plan_outlook": quota["outlook.com"],
        "plan_hotmail": quota["hotmail.com"],
        "plan_total": plan_total,
        "selected": selected,
        "selected_outlook": len(selected_outlook),
        "selected_hotmail": len(selected_hotmail),
        "export_count": exported,
        "shortfall": max(0, plan_total - exported),
    }


def _export_cache_put(job_id: str, filename: str, content: str, account_ids: list[int]) -> None:
    with _export_cache_lock:
        _export_cache[job_id] = {
            "filename": filename,
            "content": content,
            "account_ids": list(account_ids),
            "created_at": time.time(),
        }
        # 清理过期
        now = time.time()
        dead = [k for k, v in _export_cache.items() if now - float(v.get("created_at") or 0) > EXPORT_CACHE_TTL_SEC]
        for k in dead:
            _export_cache.pop(k, None)


def _export_cache_get(job_id: str) -> dict[str, Any] | None:
    with _export_cache_lock:
        item = _export_cache.get(job_id)
        if not item:
            return None
        if time.time() - float(item.get("created_at") or 0) > EXPORT_CACHE_TTL_SEC:
            _export_cache.pop(job_id, None)
            return None
        return item


class ExportPayload(BaseModel):
    count: int = 10
    domain: str = "all"  # all | outlook.com | hotmail.com
    min_registered_days: int = 7
    retest: bool = True  # 默认导出前复测
    concurrency: int | None = None


@app.post("/api/accounts/export/preview")
def export_preview(payload: ExportPayload):
    if payload.count < 1:
        raise HTTPException(status_code=400, detail="数量必须 ≥ 1")
    if payload.min_registered_days < 0:
        raise HTTPException(status_code=400, detail="注册满天数不能为负")
    plan = plan_export_selection(payload.count, payload.domain, payload.min_registered_days)
    return {
        "success": True,
        "count": payload.count,
        "domain": payload.domain,
        "min_registered_days": payload.min_registered_days,
        "eligible_total": plan["eligible_total"],
        "eligible_outlook": plan["eligible_outlook"],
        "eligible_hotmail": plan["eligible_hotmail"],
        "plan_outlook": plan["plan_outlook"],
        "plan_hotmail": plan["plan_hotmail"],
        "plan_total": plan["plan_total"],
        "will_export": plan["export_count"],
        "shortfall": plan["shortfall"],
    }


@app.post("/api/accounts/export/run")
def export_run(payload: ExportPayload):
    if payload.count < 1:
        raise HTTPException(status_code=400, detail="数量必须 ≥ 1")
    if payload.min_registered_days < 0:
        raise HTTPException(status_code=400, detail="注册满天数不能为负")
    workers = clamp_concurrency(payload.concurrency, 8)
    plan0 = plan_export_selection(payload.count, payload.domain, payload.min_registered_days)
    if plan0["export_count"] <= 0 and not payload.retest:
        raise HTTPException(status_code=400, detail="没有符合条件的可导出账号")

    filename = f"{time.strftime('%Y%m%d%H%M%S')}-Microsoft-mail.txt"
    # total：预估处理量（复测时=候选上限，否则=将导出数）
    est_total = max(1, plan0["plan_total"] if payload.retest else plan0["export_count"] or plan0["plan_total"])

    def runner(progress, is_cancelled):
        progress.set_total(est_total)
        jobs.update_job(progress.job_id, export_phase="selecting", export_filename=filename)
        plan = plan_export_selection(payload.count, payload.domain, payload.min_registered_days)
        candidates = list(plan["selected"])
        quota = plan["quota"]

        if payload.retest and candidates:
            jobs.update_job(progress.job_id, export_phase="retesting")
            alive_rows: list[dict[str, Any]] = []
            # 保持原排序，逐个测；取消则停止
            for row in candidates:
                if is_cancelled():
                    break
                aid = int(row["id"])
                try:
                    res = protocol_one(aid, job_id=progress.job_id)
                except Exception as exc:  # noqa: BLE001
                    res = {"status": "fail", "account_id": aid, "reason": str(exc)}
                # 重新读库判断是否仍存活
                try:
                    fresh = dict(fetch_account(aid))
                except Exception:
                    fresh = row
                if is_export_alive(fresh) and not is_banned_row(fresh):
                    alive_rows.append(fresh)
                    progress(status="ok", account_id=aid, email=fresh.get("email"), reason="复测存活")
                else:
                    progress(
                        status="skip",
                        account_id=aid,
                        email=fresh.get("email") or row.get("email"),
                        reason=res.get("reason") or "复测未存活/已封禁",
                    )
            # 按配额重新截取
            by_domain: dict[str, list[dict[str, Any]]] = {"outlook.com": [], "hotmail.com": []}
            for r in alive_rows:
                b = _domain_bucket(r.get("email") or "")
                if b in by_domain:
                    by_domain[b].append(r)
            for key in by_domain:
                by_domain[key].sort(
                    key=lambda r: (_account_registered_dt(r) or datetime.max, int(r.get("id") or 0))
                )
            selected = by_domain["outlook.com"][: quota["outlook.com"]] + by_domain["hotmail.com"][: quota["hotmail.com"]]
            selected.sort(key=lambda r: (_account_registered_dt(r) or datetime.max, int(r.get("id") or 0)))
        else:
            selected = candidates

        if is_cancelled():
            jobs.update_job(progress.job_id, export_phase="cancelled")
            return
        if not selected:
            jobs.update_job(progress.job_id, export_phase="done", error="没有可导出的存活账号")
            return

        jobs.update_job(progress.job_id, export_phase="building")
        # 导出前再取一次密钥字段，确保与库一致
        final_rows: list[dict[str, Any]] = []
        for r in selected:
            try:
                full = dict(fetch_account(int(r["id"])))
            except Exception:
                continue
            if is_banned_row(full) or not is_export_alive(full):
                continue
            final_rows.append(full)

        lines = [account_line(r) for r in final_rows]
        content = "\n".join(lines) + ("\n" if lines else "")
        ids = [int(r["id"]) for r in final_rows]
        n_out = sum(1 for r in final_rows if _domain_bucket(r.get("email") or "") == "outlook.com")
        n_hot = sum(1 for r in final_rows if _domain_bucket(r.get("email") or "") == "hotmail.com")
        _export_cache_put(progress.job_id, filename, content, ids)
        jobs.update_job(
            progress.job_id,
            export_phase="deleting",
            export_filename=filename,
            export_count=len(ids),
            export_outlook=n_out,
            export_hotmail=n_hot,
            export_ready=True,
        )

        # 删除：远程 + 本地（远程失败仍删本地，避免重复出货）
        remote_fail = 0
        if ids:
            try:
                session, base, csrf_token, csrf_disabled, _ = _remote_session(pool=min(8, workers + 2))
            except Exception as exc:  # noqa: BLE001
                session = None
                log_event("EXPORT", f"远程会话失败，将仅删本地：{exc}", "WARN")

            for r in final_rows:
                if is_cancelled():
                    break
                email = r["email"]
                aid = int(r["id"])
                remote_ok = True
                remote_reason = "远程已删除或未配置"
                if session is not None:
                    try:
                        res = delete_account_remote(session, base, csrf_token, csrf_disabled, email)
                        remote_ok = bool(res.get("success", False)) or res.get("http_status") in (200, 204, 404)
                        if not remote_ok:
                            remote_fail += 1
                            remote_reason = f"远程失败:{res.get('error') or res.get('http_status')}"
                        else:
                            remote_reason = "远程已删除"
                    except Exception as exc:  # noqa: BLE001
                        remote_fail += 1
                        remote_ok = False
                        remote_reason = f"远程异常:{exc}"
                with get_conn(DB_PATH) as conn:
                    conn.execute("DELETE FROM accounts WHERE id=?", (aid,))
                    conn.execute("DELETE FROM history WHERE account_id=?", (aid,))
                    conn.commit()
                if not payload.retest:
                    progress(
                        status="ok" if remote_ok else "ok",
                        account_id=aid,
                        email=email,
                        reason=f"已导出并删除本地；{remote_reason}",
                    )

        jobs.update_job(
            progress.job_id,
            export_phase="done",
            export_remote_failed=remote_fail,
            export_ready=True,
        )
        schedule_stats_refresh(0.2)
        log_event(
            "EXPORT",
            f"导出完成 file={filename} count={len(ids)} outlook={n_out} hotmail={n_hot} remote_fail={remote_fail}",
        )

    job_id = jobs.submit_custom(
        "export",
        est_total,
        runner,
        job_extra={
            "export_filename": filename,
            "export_ready": False,
            "export_phase": "queued",
            "export_count": 0,
            "export_outlook": 0,
            "export_hotmail": 0,
        },
    )
    log_event(
        "EXPORT",
        f"导出任务启动 job={job_id} count={payload.count} domain={payload.domain} "
        f"min_days={payload.min_registered_days} retest={payload.retest}",
    )
    return {
        "success": True,
        "job_id": job_id,
        "filename": filename,
        "plan_total": plan0["plan_total"],
        "eligible_total": plan0["eligible_total"],
    }


@app.get("/api/accounts/export/download/{job_id}")
def export_download(job_id: str):
    item = _export_cache_get(job_id)
    if not item:
        # 任务可能仍在跑
        job = jobs.get_job(job_id)
        if job and job.get("state") == "running":
            raise HTTPException(status_code=409, detail="导出尚未完成，请稍候")
        raise HTTPException(status_code=404, detail="导出文件不存在或已过期，请重新导出")
    filename = item["filename"]
    content = item["content"]
    log_event("EXPORT", f"下载导出文件 {filename} | job={job_id}")
    return PlainTextResponse(
        content,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Count": str(len(item.get("account_ids") or [])),
            "X-Export-Job": job_id,
        },
    )


@app.get("/api/accounts/{account_id}/detail")
def account_detail(account_id: int):
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="账号不存在")
        history = conn.execute(
            "SELECT action, status, detail, created_at FROM history WHERE account_id=? ORDER BY id DESC LIMIT 50",
            (account_id,),
        ).fetchall()
    return {
        "success": True,
        "account": dict(row),
        "history": [dict(h) for h in history],
        "locked": locks.is_locked(account_id),
    }


@app.get("/api/accounts/{account_id}/recovery-detail")
def recovery_detail(account_id: int):
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="账号不存在")
        history = conn.execute(
            """
            SELECT action, status, detail, created_at
            FROM history
            WHERE account_id=? AND action IN ('recover_abuse', 'bind_backup_email', 'oauth_reauth', 'captcha')
            ORDER BY id DESC LIMIT 50
            """,
            (account_id,),
        ).fetchall()
    return {
        "success": True,
        "account": dict(row),
        "history": [dict(h) for h in history],
        "locked": locks.is_locked(account_id),
    }


# ---------------- 导入 ----------------
def parse_lines(text: str) -> tuple[list[dict], list[dict]]:
    """返回 (valid_records, errors)。"""
    valid = []
    errors = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("----")]
        if len(parts) < 4 or not parts[0] or "@" not in parts[0]:
            errors.append({"line_no": line_no, "line": line[:80], "error": "格式错误（需 邮箱----密码----client_id----refresh_token）"})
            continue
        valid.append({
            "email": parts[0],
            "password": parts[1],
            "client_id": parts[2],
            "refresh_token": "----".join(parts[3:]).strip(),
        })
    return valid, errors


@app.post("/api/accounts/import-preview")
def import_preview(payload: ImportPayload):
    valid, errors = parse_lines(payload.text)
    with get_conn(DB_PATH) as conn:
        existing_emails = {r[0] for r in conn.execute("SELECT email FROM accounts").fetchall()}
    seen: set[str] = set()
    new_count = overwrite_count = dup_in_input = 0
    for rec in valid:
        email = rec["email"]
        if email in seen:
            dup_in_input += 1
            continue
        seen.add(email)
        if email in existing_emails:
            overwrite_count += 1
        else:
            new_count += 1
    return {
        "success": True,
        "total_lines": len(valid) + len(errors),
        "valid": len(valid),
        "new": new_count,
        "overwrite": overwrite_count,
        "dup_in_input": dup_in_input,
        "errors": errors[:50],
        "error_count": len(errors),
    }


def _do_import(text: str) -> dict[str, Any]:
    valid, errors = parse_lines(text)
    inserted = updated = 0
    ts = now_local()
    with get_conn(DB_PATH) as conn:
        for rec in valid:
            existing = conn.execute("SELECT id FROM accounts WHERE email=?", (rec["email"],)).fetchone()
            if existing:
                # 覆盖导入：更新密钥字段并重置缓存的健康/协议/远程状态
                conn.execute(
                    """
                    UPDATE accounts
                    SET password=?, client_id=?, refresh_token=?,
                        status='new', health_status='', health_severity='', ban_reason='', error_detail='',
                        graph_status='', imap_status='', pop_status='', smtp_status='',
                        last_protocol_test_at='',
                        remote_sync_status='dirty', refresh_token_updated_at=?,
                        token_sync_status='local_newer',
                        updated_at=?
                    WHERE email=?
                    """,
                    (rec["password"], rec["client_id"], rec["refresh_token"], ts, ts, rec["email"]),
                )
                updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO accounts (
                        email, password, client_id, refresh_token,
                        status, remote_sync_status, refresh_token_updated_at, token_sync_status, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, 'new', 'dirty', ?, 'local_newer', ?, ?)
                    """,
                    (rec["email"], rec["password"], rec["client_id"], rec["refresh_token"], ts, ts, ts),
                )
                inserted += 1
        conn.commit()
    schedule_stats_refresh()
    log_event("IMPORT", f"导入完成 | 新增 {inserted} | 覆盖 {updated} | 错误 {len(errors)}")
    return {"success": True, "inserted": inserted, "updated": updated, "errors": errors[:50], "error_count": len(errors)}


@app.post("/api/accounts/import-text")
def import_accounts_text(payload: ImportPayload):
    return _do_import(payload.text)


@app.post("/api/accounts/import-file")
async def import_accounts_file(file: UploadFile = File(...)):
    raw = await file.read()
    return _do_import(raw.decode("utf-8", errors="ignore"))


def default_import_path() -> Path:
    """默认导入文件：优先 config.default_import_file，否则取注册项目产出的 oauth2.txt。"""
    cfg_path = (get_config().get("default_import_file") or "").strip()
    if cfg_path:
        p = Path(cfg_path)
        return p if p.is_absolute() else (ROOT / p)
    return ROOT.parent / "OutlookRegister" / "Results" / "oauth2.txt"


@app.get("/api/accounts/load-default-file")
def load_default_file():
    file_path = default_import_path()
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"默认导入文件不存在：{file_path}")
    text = file_path.read_text(encoding="utf-8")
    result = _do_import(text)
    # 导入后清空源文件：移除所有已成功解析的账号行，仅保留无法解析的异常行（防误删）
    remaining = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split("----")]
        if len(parts) < 4 or not parts[0] or "@" not in parts[0]:
            remaining.append(raw)  # 异常行保留，便于排查
    file_path.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
    result["source_cleared"] = True
    result["remaining_lines"] = len(remaining)
    log_event("IMPORT", f"已清空 {file_path.name}（移除已导入账号，保留 {len(remaining)} 个异常行）")
    return result


@app.put("/api/accounts/{account_id}")
def edit_account(account_id: int, payload: EditPayload):
    row = fetch_account(account_id)
    fields = []
    values: list[Any] = []
    for col in ("password", "client_id", "refresh_token", "remark"):
        val = getattr(payload, col)
        if val is not None:
            fields.append(f"{col}=?")
            values.append(val)
    if not fields:
        return {"success": True, "message": "无更新"}
    ts = now_local()
    if payload.refresh_token is not None and payload.refresh_token != row["refresh_token"]:
        fields.append("remote_sync_status=?")
        values.append("dirty")
        fields.append("refresh_token_updated_at=?")
        values.append(ts)
        fields.append("token_sync_status=?")
        values.append("local_newer")
    fields.append("updated_at=?")
    values.append(ts)
    values.append(account_id)
    with get_conn(DB_PATH) as conn:
        conn.execute(f"UPDATE accounts SET {', '.join(fields)} WHERE id=?", values)
        conn.commit()
    return {"success": True}


@app.delete("/api/accounts/{account_id}")
def delete_account(account_id: int, remote: bool = False):
    row = fetch_account(account_id)
    remote_result = None
    if remote:
        try:
            session, base, csrf_token, csrf_disabled, _ = _remote_session()
            remote_result = delete_account_remote(session, base, csrf_token, csrf_disabled, row["email"])
        except Exception as exc:  # noqa: BLE001
            remote_result = {"success": False, "error": str(exc)}
    with get_conn(DB_PATH) as conn:
        conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        conn.execute("DELETE FROM history WHERE account_id=?", (account_id,))
        conn.commit()
    schedule_stats_refresh()
    log_event("ACCOUNT", f"删除账号 {row['email']} | 远程={'是' if remote else '否'}", "WARN")
    return {"success": True, "remote": remote_result}


class DeletePayload(BaseModel):
    ids: list[int]
    remote: bool = False
    concurrency: int | None = None


@app.post("/api/accounts/batch/delete")
def batch_delete(payload: DeletePayload):
    if not payload.ids:
        raise HTTPException(status_code=400, detail="未指定账号")
    with get_conn(DB_PATH) as conn:
        marks = ",".join("?" for _ in payload.ids)
        rows = [dict(r) for r in conn.execute(
            f"SELECT id, email FROM accounts WHERE id IN ({marks})", payload.ids).fetchall()]
    if not rows:
        raise HTTPException(status_code=400, detail="账号不存在")

    if not payload.remote:
        # 仅本地删除：一次事务完成，立即返回
        with get_conn(DB_PATH) as conn:
            conn.execute(f"DELETE FROM accounts WHERE id IN ({marks})", payload.ids)
            conn.execute(f"DELETE FROM history WHERE account_id IN ({marks})", payload.ids)
            conn.commit()
        schedule_stats_refresh()
        log_event("ACCOUNT", f"批量删除 {len(rows)} 个账号（仅本地）", "WARN")
        return {"success": True, "deleted": len(rows), "remote": False}

    # 含远程删除：后台任务逐个删远程 + 本地
    workers = clamp_concurrency(payload.concurrency, 4)

    def runner(progress, is_cancelled):
        session, base, csrf_token, csrf_disabled, _ = _remote_session(pool=workers + 2)

        def do_one(r):
            res = delete_account_remote(session, base, csrf_token, csrf_disabled, r["email"])
            ok = bool(res.get("success", False)) or res.get("http_status") in (200, 204, 404)
            # 远程硬失败时保留本地，避免「本地没了远程还在」
            if ok:
                with get_conn(DB_PATH) as conn:
                    conn.execute("DELETE FROM accounts WHERE id=?", (r["id"],))
                    conn.execute("DELETE FROM history WHERE account_id=?", (r["id"],))
                    conn.commit()
                reason = "本地+远程已删除"
            else:
                reason = f"远程删除失败，本地已保留：{res.get('error') or res.get('http_status')}"
            progress(status="ok" if ok else "fail", account_id=r["id"], email=r["email"], reason=reason)

        run_cancellable(rows, workers, do_one, is_cancelled)
        schedule_stats_refresh()
        log_event("ACCOUNT", f"批量删除任务{'已终止' if is_cancelled() else '完成'}（本地+远程）", "WARN")

    job_id = jobs.submit_custom("delete", len(rows), runner)
    return {"success": True, "job_id": job_id, "total": len(rows), "remote": True}


@app.post("/api/accounts/{account_id}/remote-remove")
def remote_remove_one(account_id: int):
    """从远程移除该账号，本地保留（标记 remote_sync_status=removed）。"""
    row = fetch_account(account_id)
    auto_remote_delete(account_id, row["email"])
    return {"success": True}


@app.post("/api/accounts/batch/remote-remove")
def batch_remote_remove(payload: DeletePayload):
    """批量从远程移除，本地全部保留。"""
    if not payload.ids:
        raise HTTPException(status_code=400, detail="未指定账号")
    with get_conn(DB_PATH) as conn:
        marks = ",".join("?" for _ in payload.ids)
        rows = [dict(r) for r in conn.execute(
            f"SELECT id, email FROM accounts WHERE id IN ({marks})", payload.ids).fetchall()]
    if not rows:
        raise HTTPException(status_code=400, detail="账号不存在")
    workers = clamp_concurrency(payload.concurrency, 4)

    def runner(progress, is_cancelled):
        session, base, csrf_token, csrf_disabled, _ = _remote_session(pool=workers + 2)

        def do_one(r):
            res = delete_account_remote(session, base, csrf_token, csrf_disabled, r["email"])
            ok = bool(res.get("success", False)) or res.get("http_status") in (200, 204, 404)
            ts = now_local()
            with get_conn(DB_PATH) as conn:
                conn.execute("UPDATE accounts SET remote_sync_status=?, remote_sync_at=?, remote_sync_error=?, updated_at=? WHERE id=?",
                             ("removed" if ok else "fail", ts, "" if ok else str(res.get("error") or res.get("http_status"))[:300], ts, r["id"]))
                add_history(conn, r["id"], r["email"], "remote-remove", "ok" if ok else "fail",
                            "已从远程移除(本地保留)" if ok else "远程移除失败", ts)
                conn.commit()
            progress(status="ok" if ok else "fail", account_id=r["id"], email=r["email"],
                     reason="已从远程移除(本地保留)" if ok else "远程移除失败")

        run_cancellable(rows, workers, do_one, is_cancelled)
        log_event("ACCOUNT", f"批量从远程移除任务{'已终止' if is_cancelled() else '完成'}（本地保留）", "WARN")

    job_id = jobs.submit_custom("remote-remove", len(rows), runner)
    return {"success": True, "job_id": job_id, "total": len(rows)}


def fetch_account(account_id: int):
    with get_conn(DB_PATH) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="账号不存在")
    return row


# ---------------- 刷新 token ----------------
def refresh_with_graph(client_id: str, refresh_token: str, proxy: str | None):
    session = requests.Session()
    session.verify = False
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    attempts = []
    for label, scope in (("default", GRAPH_SCOPE), ("original", None)):
        data = {"client_id": client_id, "grant_type": "refresh_token", "refresh_token": refresh_token}
        if scope:
            data["scope"] = scope
        resp = session.post(TOKEN_URL, data=data, timeout=HTTP_TIMEOUT)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:500]}
        attempts.append({"label": label, "status_code": resp.status_code, "body": body})
        if resp.status_code == 200 and body.get("access_token"):
            return {"success": True, "access_token": body.get("access_token", ""),
                    "refresh_token": body.get("refresh_token", ""), "scope": body.get("scope", ""), "attempts": attempts}
    return {"success": False, "attempts": attempts, "error": attempts[-1]["body"] if attempts else "unknown"}


def refresh_one(account_id: int) -> dict[str, Any]:
    row = fetch_account(account_id)
    if not locks.try_acquire(account_id):
        return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "账号正在执行其他任务"}
    post_sync = False
    post_delete = False
    out: dict[str, Any] = {
        "status": "fail",
        "account_id": account_id,
        "email": row["email"],
        "reason": "未知错误",
    }
    try:
        # 远程同步/删除放到 release 之后，缩短账号锁占用
        result = refresh_with_graph(row["client_id"], row["refresh_token"], proxy_url())
        ts = now_local()
        with get_conn(DB_PATH) as conn:
            if result["success"]:
                new_refresh = result.get("refresh_token") or row["refresh_token"]
                conn.execute(
                    """UPDATE accounts SET refresh_token=?,
                       last_refresh_at=?, last_refresh_status='ok', last_refresh_error='',
                       refresh_token_updated_at=?, token_sync_status='local_newer',
                       last_alive_at=?,
                       updated_at=? WHERE id=?""",
                    (new_refresh, ts, ts, ts, ts, account_id),
                )
                rotated = bool(result.get("refresh_token"))
                rotated_text = "更新 refresh_token 成功" if rotated else "更新 refresh_token 失败"
                add_history(conn, account_id, row["email"], "refresh", "ok", rotated_text, ts)
                conn.commit()
                schedule_stats_refresh()
                log_event("REFRESH", f"{row['email']} 刷新成功 | {rotated_text}")
                post_sync = True
                out = {
                    "status": "ok",
                    "account_id": account_id,
                    "email": row["email"],
                    "rotated": rotated,
                    "reason": rotated_text,
                    "scope": result.get("scope", ""),
                    "attempts": result["attempts"],
                }
            else:
                analysis = diagnostics.analyze_error(result.get("error", ""))
                reason = f"[{analysis['code']}] {analysis['reason']}" if analysis["code"] else analysis["reason"]
                is_banned = analysis["severity"] == "banned"
                new_health = "banned" if is_banned else ("token_invalid" if analysis["severity"] == "fail" else "")
                new_sev = "banned" if is_banned else (analysis["severity"] or row["health_severity"] or "fail")
                conn.execute(
                    """UPDATE accounts SET status='refresh_fail', health_status=?, health_severity=?,
                       last_refresh_at=?, last_refresh_status='fail', last_refresh_error=?,
                       ban_reason=?, updated_at=? WHERE id=?""",
                    (
                        new_health or row["health_status"],
                        new_sev,
                        ts,
                        reason[:1000],
                        reason if is_banned else "",
                        ts,
                        account_id,
                    ),
                )
                add_history(conn, account_id, row["email"], "refresh", "fail", reason, ts)
                conn.commit()
                schedule_stats_refresh()
                log_event("REFRESH", f"{row['email']} 刷新失败 | {reason}", "FAIL")
                post_delete = is_banned
                out = {
                    "status": "fail",
                    "account_id": account_id,
                    "email": row["email"],
                    "reason": reason,
                    "severity": analysis["severity"],
                    "attempts": result.get("attempts", []),
                }
    except Exception as exc:  # noqa: BLE001
        out = {
            "status": "fail",
            "account_id": account_id,
            "email": row["email"],
            "reason": f"刷新异常：{exc}",
        }
        log_event("REFRESH", f"{row['email']} 刷新异常 | {exc}", "FAIL")
    finally:
        locks.release(account_id)
    if post_sync:
        auto_remote_sync(account_id)
    if post_delete:
        auto_remote_delete(account_id, row["email"])
    return out


@app.post("/api/accounts/{account_id}/refresh")
def refresh_account(account_id: int):
    res = refresh_one(account_id)
    if res["status"] == "ok":
        return {"success": True, **res}
    return JSONResponse({"success": False, **res}, status_code=400 if res["status"] == "fail" else 409)


# ---------------- 协议测试 ----------------
def protocol_one(account_id: int, job_id: str | None = None) -> dict[str, Any]:
    """单账号协议测试。

    批量任务会传入 job_id：走可杀子进程；取消后不再写库，直接 skip。
    """
    row = fetch_account(account_id)
    if job_id and jobs.is_cancelled(job_id):
        return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
    if not locks.try_acquire(account_id):
        return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "账号正在执行其他任务"}
    post_delete = False
    out: dict[str, Any] = {
        "status": "fail",
        "account_id": account_id,
        "email": row["email"],
        "reason": "未知错误",
    }
    try:
        if job_id and jobs.is_cancelled(job_id):
            out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
            return out
        log_event("PROTO", f"开始测试 {row['email']}")
        final_outcome = None
        health = None
        attempts_used = 0
        proto_cfg = (get_config().get("protocol_test") or {})
        ext_rcpt = str(proto_cfg.get("external_recipient") or "")
        for attempt in range(1, 3):
            if job_id and jobs.is_cancelled(job_id):
                out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
                return out
            attempts_used = attempt
            # 有 job_id 时默认子进程（可被 cancel 立刻 kill）；单条点测仍同进程
            final_outcome = run_protocol_test(
                PYTHON_EXE,
                TEST_SCRIPT,
                ROOT,
                account_line(row),
                proxy_url=proxy_url(),
                external_recipient=ext_rcpt,
                protocol_cfg=proto_cfg,
                job_id=job_id,
                use_subprocess=bool(job_id) if job_id else False,
            )
            if job_id and jobs.is_cancelled(job_id):
                out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
                return out
            if final_outcome.get("aborted") and job_id and jobs.is_cancelled(job_id):
                out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
                return out
            if not final_outcome["success"] and "health" not in final_outcome:
                if attempt == 1 and not (job_id and jobs.is_cancelled(job_id)):
                    log_event("PROTO", f"{row['email']} 脚本异常，准备重试 | {summarize_protocol_error(final_outcome)}", "WARN")
                    time.sleep(1)
                    continue
                if job_id and jobs.is_cancelled(job_id):
                    out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
                    return out
                ts = now_local()
                reason = summarize_protocol_error(final_outcome)
                with get_conn(DB_PATH) as conn:
                    conn.execute(
                        """
                        UPDATE accounts
                        SET status='proto_error', health_status='other_error', health_severity='fail',
                            ban_reason='', error_detail=?, graph_status='', imap_status='', pop_status='', smtp_status='',
                            last_protocol_test_at=?, updated_at=?
                        WHERE id=?
                        """,
                        (reason, ts, ts, account_id),
                    )
                    add_history(conn, account_id, row["email"], "protocol", "fail", reason, ts)
                    conn.commit()
                schedule_stats_refresh()
                log_event("PROTO", f"{row['email']} 测试失败 | {reason}", "FAIL")
                out = {
                    "status": "fail",
                    "account_id": account_id,
                    "email": row["email"],
                    "health": "other_error",
                    "severity": "fail",
                    "reason": reason,
                    "stderr": final_outcome.get("stderr", ""),
                }
                return out
            health = final_outcome["health"]
            if suspected_restricted(health) and attempt == 1:
                if job_id and jobs.is_cancelled(job_id):
                    out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
                    return out
                log_event("PROTO", f"{row['email']} 命中疑似受限，准备重试", "WARN")
                time.sleep(1)
                continue
            if suspected_restricted(health):
                health = to_other_error(health, "二次测试仍为疑似受限，已归入其他错误")
            break

        if job_id and jobs.is_cancelled(job_id):
            out = {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "任务已取消"}
            return out

        ts = now_local()
        registration = ((final_outcome or {}).get("result") or {}).get("registration") or {}
        registration_value = str(registration.get("registered_at") or "").strip()
        registration_source_value = str(registration.get("registered_source") or "").strip()
        existing_registered_at = str(row["registered_at"] or "").strip()
        existing_registered_source = str(row["registered_source"] or "").strip()
        created_at_fallback = str(row["created_at"] or "").strip()
        registered_at = registration_value or existing_registered_at or created_at_fallback or ""
        if registration_value:
            registered_source = registration_source_value or existing_registered_source or ""
        elif existing_registered_at:
            registered_source = existing_registered_source or ""
        elif created_at_fallback:
            registered_source = "db_created_at"
        else:
            registered_source = ""
        last_alive_at = ts if is_alive_health(health) else str(row["last_alive_at"] or "")
        with get_conn(DB_PATH) as conn:
            conn.execute(
                """UPDATE accounts SET status=?, health_status=?, health_severity=?, ban_reason=?, error_detail=?,
                   graph_status=?, imap_status=?, pop_status=?, smtp_status=?,
                   registered_at=?, registered_source=?, last_alive_at=?,
                   last_protocol_test_at=?, updated_at=? WHERE id=?""",
                (health["health_status"], health["health_status"], health["health_severity"],
                 health["ban_reason"], health["error_detail"],
                 health["graph_status"], health["imap_status"], health["pop_status"], health["smtp_status"],
                 registered_at, registered_source, last_alive_at,
                 ts, ts, account_id),
            )
            hist_status = "ok" if health["health_severity"] in ("ok", "warn") else health["health_severity"]
            add_history(conn, account_id, row["email"], "protocol", hist_status,
                        health["ban_reason"] or health["error_detail"] or health["health_status"], ts)
            conn.commit()
        schedule_stats_refresh()
        log_event(
            "PROTO",
            f"{row['email']} 测试完成 | health={health['health_status']} severity={health['health_severity']} | attempts={attempts_used}",
        )
        post_delete = health["health_status"] == "banned" or health.get("health_severity") == "banned"
        status = "ok" if health["health_severity"] in ("ok", "warn") else "fail"
        out = {
            "status": status,
            "account_id": account_id,
            "email": row["email"],
            "health": health["health_status"],
            "severity": health["health_severity"],
            "reason": health["ban_reason"] or health["error_detail"],
        }
    finally:
        locks.release(account_id)
    if post_delete and not (job_id and jobs.is_cancelled(job_id)):
        auto_remote_delete(account_id, row["email"])
    return out


@app.post("/api/accounts/{account_id}/protocol-test")
def protocol_test(account_id: int):
    res = protocol_one(account_id)
    if res["status"] == "skip":
        return JSONResponse({"success": False, **res}, status_code=409)
    return {"success": res["status"] == "ok", **res}


def recover_abuse_one(account_id: int) -> dict[str, Any]:
    row = fetch_account(account_id)
    row_dict = dict(row)
    if not locks.try_acquire(account_id):
        return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "账号正在执行其他任务"}
    try:
        log_event("RECOVER", f"开始恢复 account_id={account_id} email={row['email']}")
        cfg = get_config()
        recovery_cfg = cfg.get("recovery") or {}
        if not recovery_cfg.get("enabled", True):
            return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": "恢复功能未启用"}
        if not is_abuse_candidate(row_dict):
            analysis = diagnostics.analyze_recovery_reason("not_abuse")
            return {"status": "skip", "account_id": account_id, "email": row["email"], "reason": analysis["reason"]}

        def hook(stage: str, message: str, level: str = "INFO") -> None:
            log_event(f"RECOVER:{row['email']}", f"{stage} | {message}", level)

        result = recover_abuse_account(row_dict, cfg, proxy_url=proxy_url(), log_hook=hook)
        ts = now_local()
        with get_conn(DB_PATH) as conn:
            if result["success"]:
                new_refresh = result["refresh_token"]
                conn.execute(
                    """
                    UPDATE accounts
                    SET refresh_token=?, status='new', health_status='', health_severity='',
                        ban_reason='', error_detail='',
                        last_protocol_test_at='',
                        refresh_token_updated_at=?, token_sync_status='local_newer',
                        last_alive_at=?,
                        recovery_status='recovered', recovery_last_at=?, recovery_last_reason=?, recovery_last_temp_mail=?,
                        oauth_reauth_at=?, oauth_reauth_status='ok', oauth_reauth_error='',
                        remote_sync_status='dirty', updated_at=?
                    WHERE id=?
                    """,
                    (
                        new_refresh,
                        ts,
                        ts,
                        ts,
                        result["reason"],
                        result.get("temp_mail", ""),
                        ts,
                        ts,
                        account_id,
                    ),
                )
                add_history(conn, account_id, row["email"], "recover_abuse", "ok", result["reason"], ts)
                if result.get("temp_mail"):
                    add_history(conn, account_id, row["email"], "bind_backup_email", "ok", result["temp_mail"], ts)
                add_history(conn, account_id, row["email"], "oauth_reauth", "ok", "refresh_token 已更新", ts)
                conn.commit()
                log_event("RECOVER", f"恢复成功 account_id={account_id} email={row['email']} debug_log={result.get('debug_log', '')}", "INFO")
                out = {
                    "status": "ok",
                    "success": True,
                    "account_id": account_id,
                    "email": row["email"],
                    "reason": result["reason"],
                    "temp_mail": result.get("temp_mail", ""),
                    "debug_log": result.get("debug_log", ""),
                }
            else:
                analysis = diagnostics.analyze_recovery_reason(result.get("reason_code", ""), result.get("reason", ""))
                # 不再累计失败次数，也不区分「不可恢复」——失败统一记为 failed
                status_value = "failed"
                oauth_status = "fail" if result.get("reason_code") == "reauth_failed" else ""
                oauth_at = ts if oauth_status else ""
                oauth_error = analysis["reason"][:1000] if oauth_status else ""
                conn.execute(
                    """
                    UPDATE accounts
                    SET recovery_status=?, recovery_last_at=?, recovery_last_reason=?, recovery_last_temp_mail=?,
                        oauth_reauth_at=?, oauth_reauth_status=?, oauth_reauth_error=?, updated_at=?
                    WHERE id=?
                    """,
                    (
                        status_value,
                        ts,
                        analysis["reason"][:1000],
                        result.get("temp_mail", ""),
                        oauth_at,
                        oauth_status,
                        oauth_error,
                        ts,
                        account_id,
                    ),
                )
                hist_action = "captcha" if result.get("reason_code") == "captcha_failed" else "recover_abuse"
                add_history(conn, account_id, row["email"], hist_action, "fail", analysis["reason"], ts)
                if result.get("temp_mail"):
                    add_history(conn, account_id, row["email"], "bind_backup_email", "ok", result["temp_mail"], ts)
                if result.get("reason_code") == "reauth_failed":
                    add_history(conn, account_id, row["email"], "oauth_reauth", "fail", analysis["reason"], ts)
                conn.commit()
                log_event(
                    "RECOVER",
                    f"恢复失败 account_id={account_id} email={row['email']} code={result.get('reason_code', '')} "
                    f"reason={analysis['reason']} debug_log={result.get('debug_log', '')}",
                    "FAIL",
                )
                out = {
                    "status": "fail",
                    "success": False,
                    "account_id": account_id,
                    "email": row["email"],
                    "reason": analysis["reason"],
                    "severity": analysis["severity"],
                    "temp_mail": result.get("temp_mail", ""),
                    "debug_log": result.get("debug_log", ""),
                }
    except Exception as exc:  # noqa: BLE001
        out = {
            "status": "fail",
            "success": False,
            "account_id": account_id,
            "email": row["email"],
            "reason": f"恢复异常：{exc}",
        }
        log_event("RECOVER", f"恢复异常 account_id={account_id} email={row['email']} | {exc}", "FAIL")
    finally:
        locks.release(account_id)
    return out


@app.post("/api/accounts/batch/recover-abuse")
def batch_recover_abuse(payload: RecoveryBatchPayload):
    with get_conn(DB_PATH) as conn:
        if payload.ids:
            marks = ",".join("?" for _ in payload.ids)
            rows = [dict(r) for r in conn.execute(f"SELECT * FROM accounts WHERE id IN ({marks}) ORDER BY id", payload.ids).fetchall()]
        else:
            rows = [dict(r) for r in conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()]
    rows = [r for r in rows if is_abuse_candidate(r)]
    ids = [int(r["id"]) for r in rows]
    if not ids:
        raise HTTPException(status_code=400, detail="没有可恢复的滥用封禁账号")
    workers = clamp_concurrency(payload.concurrency, 1)
    job_id = jobs.submit("recover-abuse", ids, recover_abuse_one, max_workers=workers)
    log_event("BATCH", f"批量恢复滥用封禁 {len(ids)} 个账号 | 并发={workers} | job={job_id}")
    return {"success": True, "job_id": job_id, "total": len(ids), "concurrency": workers}


@app.post("/api/accounts/{account_id}/recover-abuse")
def recover_abuse_api(account_id: int):
    res = recover_abuse_one(account_id)
    if res["status"] == "ok":
        return {"success": True, **res}
    return JSONResponse({"success": False, **res}, status_code=400 if res["status"] == "fail" else 409)


# ---------------- 批量任务 ----------------
def _ids_or_all(payload: BatchPayload, where_all: str) -> list[int]:
    """指定 ids 时也会叠加 where_all 过滤（修复原先勾选封禁号仍入队的问题）。"""
    with get_conn(DB_PATH) as conn:
        if payload.ids:
            marks = ",".join("?" for _ in payload.ids)
            rows = conn.execute(
                f"SELECT id FROM accounts WHERE id IN ({marks}) AND ({where_all}) ORDER BY id",
                list(payload.ids),
            ).fetchall()
            return [r[0] for r in rows]
        rows = conn.execute(f"SELECT id FROM accounts WHERE {where_all} ORDER BY id").fetchall()
        return [r[0] for r in rows]


@app.post("/api/accounts/batch/refresh")
def batch_refresh(payload: BatchPayload):
    ids = _ids_or_all(payload, SQL_NOT_BANNED)
    if not ids:
        raise HTTPException(status_code=400, detail="没有可处理的账号")
    workers = clamp_concurrency(payload.concurrency, 8)
    job_id = jobs.submit("refresh", ids, refresh_one, max_workers=workers)
    log_event("BATCH", f"批量刷新 {len(ids)} 个账号 | 并发={workers} | job={job_id}")
    return {"success": True, "job_id": job_id, "total": len(ids), "concurrency": workers}


@app.post("/api/accounts/batch/protocol")
def batch_protocol(payload: BatchPayload):
    ids = _ids_or_all(payload, SQL_NOT_BANNED)
    if not ids:
        raise HTTPException(status_code=400, detail="没有可处理的账号")
    workers = clamp_concurrency(payload.concurrency, 4)
    job_id = jobs.submit("protocol", ids, protocol_one, max_workers=workers)
    log_event("BATCH", f"批量协议测试 {len(ids)} 个账号 | 并发={workers} | job={job_id}")
    return {"success": True, "job_id": job_id, "total": len(ids), "concurrency": workers}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="任务不存在")
    # 大批量时只回传最近 100 条明细，避免轮询响应过大
    if len(job.get("items", [])) > 100:
        job = {**job, "items": job["items"][-100:], "items_truncated": True}
    return {"success": True, "job": job}


@app.get("/api/jobs")
def list_jobs():
    return {"success": True, "jobs": jobs.list_jobs()}


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    ok = jobs.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=400, detail="任务不存在或已结束")
    log_event("JOB", f"任务 {job_id} 已取消", "WARN")
    return {"success": True}


# ---------------- 远程导入 / 同步 ----------------
def _remote_session(pool: int = 10, thread_safe: bool = False):
    remote = get_config()["remote"]
    base = remote["base_url"].rstrip("/")
    session = build_session(proxy_url(), pool_maxsize=pool, thread_safe=thread_safe)
    ok, detail = login(session, base, remote["password"])
    if not ok:
        raise RuntimeError(f"远程登录失败: {detail}")
    csrf_token, csrf_disabled = get_csrf(session, base)
    return session, base, csrf_token, csrf_disabled, remote


# 共享远程会话缓存：必须 thread_safe Session，避免多线程共用 requests.Session 踩踏
_remote_cache: dict[str, Any] = {}
_remote_cache_lock = threading.Lock()


def get_cached_remote(ttl: int = 600):
    with _remote_cache_lock:
        if _remote_cache.get("bundle") and (time.time() - _remote_cache.get("ts", 0)) < ttl:
            return _remote_cache["bundle"]
        bundle = _remote_session(pool=20, thread_safe=True)
        _remote_cache["bundle"] = bundle
        _remote_cache["ts"] = time.time()
        return bundle


def invalidate_remote_cache() -> None:
    with _remote_cache_lock:
        _remote_cache.clear()


def auto_remote_delete(account_id: int, email: str) -> None:
    """账号被判封禁时：从远程删除（本地保留），标记 remote_sync_status=removed。最佳努力。"""
    ts = now_local()
    try:
        session, base, csrf_token, csrf_disabled, _ = get_cached_remote()
        result = delete_account_remote(session, base, csrf_token, csrf_disabled, email)
        ok = bool(result.get("success", False)) or result.get("http_status") in (200, 204, 404)
        status = "removed" if ok else "fail"
        err = "" if ok else str(result.get("error") or result.get("message") or result.get("http_status") or "远程删除失败")[:500]
        log_event("REMOTE", f"{email} 封禁 → {'已从远程删除（本地保留）' if ok else err}", "INFO" if ok else "WARN")
    except Exception as exc:  # noqa: BLE001
        status, err = "fail", f"远程删除失败：{exc}"[:500]
        log_event("REMOTE", f"{email} 远程删除失败：{exc}", "WARN")
    with get_conn(DB_PATH) as conn:
        conn.execute("UPDATE accounts SET remote_sync_status=?, remote_sync_at=?, remote_sync_error=?, updated_at=? WHERE id=?",
                     (status, ts, err, ts, account_id))
        conn.commit()


def auto_remote_sync(account_id: int) -> None:
    """刷新成功后：把账号全部信息(含密码)同步到远程（本地为准 upsert）。最佳努力。"""
    row = fetch_account(account_id)
    try:
        session, base, csrf_token, csrf_disabled, remote = get_cached_remote()
        _remote_upsert_one(session, base, csrf_token, csrf_disabled, remote, dict(row), lambda **k: None, "auto-sync")
    except Exception as exc:  # noqa: BLE001
        log_event("REMOTE", f"{row['email']} 自动同步失败：{exc}", "WARN")
        with get_conn(DB_PATH) as conn:
            conn.execute("UPDATE accounts SET remote_sync_status='fail', remote_sync_error=?, updated_at=? WHERE id=?",
                         (f"自动同步失败：{exc}"[:500], now_local(), account_id))
            conn.commit()


def count_pending_upload_untested(conn, ids: list[int] | None = None) -> int:
    clauses = [
        "COALESCE(remote_sync_status, '') NOT IN ('synced','imported','exists')",
        "(last_protocol_test_at IS NULL OR last_protocol_test_at = '')",
        "COALESCE(health_status, '') = ''",
    ]
    params: list[Any] = []
    if ids:
        marks = ",".join("?" for _ in ids)
        clauses.append(f"id IN ({marks})")
        params.extend(ids)
    return conn.execute(f"SELECT COUNT(*) FROM accounts WHERE {' AND '.join(clauses)}", params).fetchone()[0]


@app.post("/api/accounts/batch/test-untested")
def batch_test_untested(payload: BatchPayload):
    """一键测试所有未测试的账号（last_protocol_test_at 为空且非封禁）。"""
    ids = _ids_or_all(
        payload,
        f"(last_protocol_test_at IS NULL OR last_protocol_test_at = '') AND {SQL_NOT_BANNED}",
    )
    if not ids:
        raise HTTPException(status_code=400, detail="没有未测试的账号")
    workers = clamp_concurrency(payload.concurrency, 4)
    job_id = jobs.submit("protocol", ids, protocol_one, max_workers=workers)
    log_event("BATCH", f"一键测试未测试：启动 {len(ids)} 个账号，并发 {workers}")
    return {"success": True, "job_id": job_id, "total": len(ids), "concurrency": workers}


@app.post("/api/accounts/batch/test-missing-registration")
def batch_test_missing_registration(payload: BatchPayload):
    """只测试尚未获取注册时间的账号。"""
    with get_conn(DB_PATH) as conn:
        if payload.ids:
            marks = ",".join("?" for _ in payload.ids)
            rows = conn.execute(
                f"""
                SELECT id FROM accounts
                WHERE id IN ({marks})
                  AND COALESCE(registered_at, '') = ''
                  AND {SQL_NOT_BANNED}
                ORDER BY id
                """,
                payload.ids,
            ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT id FROM accounts
                WHERE COALESCE(registered_at, '') = ''
                  AND {SQL_NOT_BANNED}
                ORDER BY id
                """
            ).fetchall()
    ids = [r[0] for r in rows]
    if not ids:
        raise HTTPException(status_code=400, detail="没有未获取注册时间的账号")
    workers = clamp_concurrency(payload.concurrency, 4)
    job_id = jobs.submit("protocol", ids, protocol_one, max_workers=workers)
    log_event("BATCH", f"补测注册时间：启动 {len(ids)} 个账号，并发 {workers}")
    return {"success": True, "job_id": job_id, "total": len(ids), "concurrency": workers}


@app.post("/api/accounts/batch/sync-never-synced")
def batch_sync_never_synced(payload: BatchPayload):
    """一键同步所有正常且尚未确认同步到远程的账号。"""
    with get_conn(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT * FROM accounts
            WHERE (graph_status='ok' OR imap_status='ok' OR pop_status='ok')
              AND COALESCE(remote_sync_status, '') NOT IN ('synced','imported','exists')
            ORDER BY id
            """
        ).fetchall()
        if not rows:
            pending_untested = count_pending_upload_untested(conn)
            if pending_untested:
                raise HTTPException(status_code=400, detail=f"存在 {pending_untested} 个未测试账号，请先完成协议测试后再上传")
    if not rows:
        raise HTTPException(status_code=400, detail="没有需要上传的账号")
    rows = [dict(r) for r in rows]
    workers = clamp_concurrency(payload.concurrency, 4)

    def runner(progress, is_cancelled):
        session, base, csrf_token, csrf_disabled, remote = _remote_session(pool=workers + 2, thread_safe=True)
        try:
            remote_items = list_remote_accounts(session, base)
            session._email_index = index_accounts_by_email(remote_items)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log_event("BATCH", f"预拉远程账号列表失败，回退逐号搜索：{exc}", "WARN")
            session._email_index = None  # type: ignore[attr-defined]
        log_event("BATCH", f"一键同步未上传：开始同步 {len(rows)} 个账号到远程，并发 {workers}")

        def do_one(r):
            _remote_upsert_safe(session, base, csrf_token, csrf_disabled, remote, r, progress, "sync-never-synced")

        run_cancellable(rows, workers, do_one, is_cancelled)
        log_event("BATCH", f"一键同步未上传：{'已终止' if is_cancelled() else '完成'}", "WARN" if is_cancelled() else "OK")

    job_id = jobs.submit_custom("remote-import", len(rows), runner)
    return {"success": True, "job_id": job_id, "total": len(rows), "concurrency": workers}


@app.post("/api/remote/import")
def remote_import(payload: BatchPayload):
    with get_conn(DB_PATH) as conn:
        if payload.ids:
            pending_untested = count_pending_upload_untested(conn, payload.ids)
            if pending_untested:
                raise HTTPException(status_code=400, detail=f"所选账号中有 {pending_untested} 个未测试，请先完成协议测试后再上传")
            marks = ",".join("?" for _ in payload.ids)
            rows = conn.execute(
                f"""
                SELECT * FROM accounts
                WHERE id IN ({marks})
                  AND (graph_status='ok' OR imap_status='ok' OR pop_status='ok')
                ORDER BY id
                """,
                payload.ids,
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM accounts
                WHERE (graph_status='ok' OR imap_status='ok' OR pop_status='ok')
                  AND COALESCE(remote_sync_status, '') NOT IN ('synced','imported','exists')
                ORDER BY id
                """
            ).fetchall()
            if not rows:
                pending_untested = count_pending_upload_untested(conn)
                if pending_untested:
                    raise HTTPException(status_code=400, detail=f"存在 {pending_untested} 个未测试账号，请先完成协议测试后再上传")
    if not rows:
        raise HTTPException(status_code=400, detail="没有需要上传的账号")
    rows = [dict(r) for r in rows]
    workers = clamp_concurrency(payload.concurrency, 4)

    def runner(progress, is_cancelled):
        session, base, csrf_token, csrf_disabled, remote = _remote_session(pool=workers + 2, thread_safe=True)
        try:
            remote_items = list_remote_accounts(session, base)
            session._email_index = index_accounts_by_email(remote_items)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log_event("REMOTE", f"预拉远程账号列表失败，回退逐号搜索：{exc}", "WARN")
            session._email_index = None  # type: ignore[attr-defined]

        def do_one(r):
            _remote_upsert_safe(session, base, csrf_token, csrf_disabled, remote, r, progress, "remote-import")

        run_cancellable(rows, workers, do_one, is_cancelled)
        log_event("REMOTE", f"远程导入(本地为准 upsert){'已终止' if is_cancelled() else '完成'} | 并发={workers}")

    job_id = jobs.submit_custom("remote-import", len(rows), runner)
    return {"success": True, "job_id": job_id, "total": len(rows), "concurrency": workers}


def remote_refresh_time(item: dict[str, Any]) -> str:
    status = str(item.get("last_refresh_status") or "").lower()
    if status not in ("success", "ok"):
        return ""
    return str(item.get("last_refresh_at") or "").strip()


def compare_token_times(local_value: str, remote_value: str) -> str:
    local_ts = parse_time_value(local_value)
    remote_ts = parse_time_value(remote_value)
    if local_ts is not None and remote_ts is not None:
        if remote_ts > local_ts:
            return "remote_newer"
        if local_ts > remote_ts:
            return "local_newer"
        return "same_time"
    if remote_ts is not None:
        return "remote_newer"
    if local_ts is not None:
        return "local_newer"
    return "unknown"


def mark_remote_conflict(conn, r, item, ts: str, reason: str) -> None:
    conn.execute(
        """
        UPDATE accounts
        SET remote_sync_status='conflict',
            remote_id=?,
            remote_sync_at=?,
            remote_sync_error=?,
            remote_last_refresh_at=?,
            remote_last_refresh_status=?,
            token_sync_status='conflict',
            updated_at=?
        WHERE id=?
        """,
        (
            str(item.get("id") or ""),
            ts,
            reason[:500],
            str(item.get("last_refresh_at") or ""),
            str(item.get("last_refresh_status") or ""),
            ts,
            r["id"],
        ),
    )


def pull_remote_token_to_local(conn, r, item, detail, ts: str) -> None:
    conn.execute(
        """
        UPDATE accounts
        SET refresh_token=?,
            client_id=?,
            last_refresh_at=?,
            last_refresh_status=?,
            last_refresh_error=?,
            refresh_token_updated_at=?,
            remote_id=?,
            remote_sync_status='synced',
            remote_sync_at=?,
            remote_sync_error='',
            remote_last_refresh_at=?,
            remote_last_refresh_status=?,
            token_sync_status='remote_newer',
            updated_at=?
        WHERE id=?
        """,
        (
            str(detail.get("refresh_token") or ""),
            str(detail.get("client_id") or item.get("client_id") or r["client_id"]),
            str(item.get("last_refresh_at") or ""),
            str(item.get("last_refresh_status") or ""),
            str(item.get("last_refresh_error") or "")[:1000],
            remote_refresh_time(item) or ts,
            str(item.get("id") or ""),
            ts,
            str(item.get("last_refresh_at") or ""),
            str(item.get("last_refresh_status") or ""),
            ts,
            r["id"],
        ),
    )


def _remote_upsert_one(session, base, csrf_token, csrf_disabled, remote, r, progress, action):
    """单账号同步到远程：远程已存在 → 用本地 token 覆盖(PUT)并纠正分组；不存在 → 按域名分组新增。本地为准。
    滥用封禁账号一律跳过，不推送到远程。"""
    ts = now_local()
    if is_banned_row(r):
        with get_conn(DB_PATH) as conn:
            add_history(conn, r["id"], r["email"], action, "skip", "滥用封禁，跳过同步", ts)
            conn.commit()
        progress(status="skip", account_id=r["id"], email=r["email"], reason="滥用封禁，跳过同步")
        return
    # 优先用预拉的 email 索引，减少每号 search
    email_index = getattr(session, "_email_index", None)
    if isinstance(email_index, dict):
        item = email_index.get(str(r.get("email") or "").lower())
    else:
        item = find_account(session, base, r["email"])
    with get_conn(DB_PATH) as conn:
        if not item:
            gid = group_for_email(r["email"])
            if gid is None:
                domain = r["email"].rsplit("@", 1)[-1]
                conn.execute("UPDATE accounts SET remote_sync_status='skipped', remote_sync_at=?, remote_sync_error=?, updated_at=? WHERE id=?",
                             (ts, f"域名 {domain} 不在同步范围", ts, r["id"]))
                add_history(conn, r["id"], r["email"], action, "skip", f"域名 {domain} 不在同步范围", ts)
                progress(status="skip", account_id=r["id"], email=r["email"], reason="域名不在同步范围")
                conn.commit()
                return
            result = import_accounts(session, base, csrf_token, csrf_disabled, [account_line(r)],
                                     gid, remote["provider"], remote["account_format"])
            added = int(result.get("added_count", 0) or 0)
            skipped = int(result.get("skipped_count", 0) or 0)
            if added > 0:
                conn.execute("UPDATE accounts SET remote_sync_status='synced', remote_sync_at=?, remote_sync_error='', updated_at=? WHERE id=?",
                             (ts, ts, r["id"]))
                add_history(conn, r["id"], r["email"], action, "ok", f"远程不存在，新增导入(分组{gid})", ts)
                progress(status="ok", account_id=r["id"], email=r["email"], reason=f"新增导入(分组{gid})")
            elif skipped > 0:
                existing = None
                if isinstance(email_index, dict):
                    existing = email_index.get(str(r.get("email") or "").lower())
                if existing is None:
                    existing = find_account(session, base, r["email"])
                if existing:
                    conn.execute(
                        """
                        UPDATE accounts
                        SET remote_sync_status='synced', remote_id=?, remote_sync_at=?,
                            remote_sync_error='', updated_at=?
                        WHERE id=?
                        """,
                        (str(existing.get("id") or ""), ts, ts, r["id"]),
                    )
                    add_history(conn, r["id"], r["email"], action, "ok", "远程已存在，状态已校准", ts)
                    progress(status="ok", account_id=r["id"], email=r["email"], reason="远程已存在，状态已校准")
                else:
                    err = result.get("error") or result.get("message") or "远程报告重复，但搜索未命中"
                    conn.execute("UPDATE accounts SET remote_sync_status='fail', remote_sync_at=?, remote_sync_error=?, updated_at=? WHERE id=?",
                                 (ts, str(err)[:500], ts, r["id"]))
                    add_history(conn, r["id"], r["email"], action, "fail", str(err), ts)
                    progress(status="fail", account_id=r["id"], email=r["email"], reason=str(err))
            else:
                err = result.get("error") or result.get("message") or f"导入失败 HTTP {result.get('http_status', '')}".strip()
                conn.execute("UPDATE accounts SET remote_sync_status='fail', remote_sync_at=?, remote_sync_error=?, updated_at=? WHERE id=?",
                             (ts, str(err)[:500], ts, r["id"]))
                add_history(conn, r["id"], r["email"], action, "fail", str(err), ts)
                progress(status="fail", account_id=r["id"], email=r["email"], reason=str(err))
            conn.commit()
            return
        # 远程已存在：按 refresh_token 更新时间决定同步方向，避免用旧 token 覆盖新 token
        detail = get_account_detail(session, base, item.get("id"))
        remote_token = str(detail.get("refresh_token") or "")
        remote_client_id = str(detail.get("client_id") or item.get("client_id") or "")
        remote_time = remote_refresh_time(item)
        local_time = token_time(r)
        if remote_token and remote_token == str(r["refresh_token"] or "") and (not remote_client_id or remote_client_id == str(r["client_id"] or "")):
            conn.execute(
                """
                UPDATE accounts
                SET remote_sync_status='synced', remote_id=?, remote_sync_at=?, remote_sync_error='',
                    last_refresh_at=?, last_refresh_status=?, last_refresh_error=?,
                    refresh_token_updated_at=CASE WHEN ? != '' THEN ? ELSE refresh_token_updated_at END,
                    remote_last_refresh_at=?, remote_last_refresh_status=?, token_sync_status='synced',
                    updated_at=?
                WHERE id=?
                """,
                (
                    str(item.get("id")),
                    ts,
                    str(item.get("last_refresh_at") or ""),
                    str(item.get("last_refresh_status") or ""),
                    str(item.get("last_refresh_error") or "")[:1000],
                    remote_time,
                    remote_time,
                    str(item.get("last_refresh_at") or ""),
                    str(item.get("last_refresh_status") or ""),
                    ts,
                    r["id"],
                ),
            )
            add_history(conn, r["id"], r["email"], action, "ok", "本地与远程 token 一致，状态已校准", ts)
            progress(status="ok", account_id=r["id"], email=r["email"], reason="token 已同步")
            conn.commit()
            return
        direction = compare_token_times(local_time, remote_time)
        if direction == "remote_newer":
            if not remote_token:
                reason = "远程较新但详情未返回 refresh_token"
                mark_remote_conflict(conn, r, item, ts, reason)
                add_history(conn, r["id"], r["email"], action, "fail", reason, ts)
                progress(status="fail", account_id=r["id"], email=r["email"], reason=reason)
                conn.commit()
                return
            moved = resync_target_group(r["email"], item.get("group_id"))
            if moved is not None:
                update_remote_token(session, base, csrf_token, csrf_disabled,
                                    item, remote_client_id or r["client_id"], remote_token, group_id=moved, password=r.get("password"))
            pull_remote_token_to_local(conn, r, item, detail, ts)
            add_history(conn, r["id"], r["email"], action, "ok", "远程 token 更新较晚，已拉回本地", ts)
            progress(status="ok", account_id=r["id"], email=r["email"], reason="远程 token 较新，已拉回本地")
            conn.commit()
            return
        if direction in ("unknown", "same_time"):
            reason = "本地与远程 token 不一致，且无法可靠判断更新时间"
            mark_remote_conflict(conn, r, item, ts, reason)
            add_history(conn, r["id"], r["email"], action, "fail", reason, ts)
            progress(status="fail", account_id=r["id"], email=r["email"], reason=reason)
            conn.commit()
            return
        # 本地较新 → 推送本地 token，并纠正放错的分组
        moved = resync_target_group(r["email"], item.get("group_id"))
        result = update_remote_token(session, base, csrf_token, csrf_disabled,
                                     item, r["client_id"], r["refresh_token"], group_id=moved, password=r.get("password"))
        if result.get("success") and int(result.get("http_status", 200) or 200) < 400:
            conn.execute(
                """
                UPDATE accounts
                SET remote_sync_status='synced', remote_id=?, remote_sync_at=?, remote_sync_error='',
                    remote_last_refresh_at=?, remote_last_refresh_status=?, token_sync_status='local_newer',
                    updated_at=?
                WHERE id=?
                """,
                (str(item.get("id")), ts, str(item.get("last_refresh_at") or ""), str(item.get("last_refresh_status") or ""), ts, r["id"]),
            )
            add_history(conn, r["id"], r["email"], action, "ok",
                        "本地 token 更新较晚，已推送远程" + (f"，分组纠正→{moved}" if moved is not None else ""), ts)
            progress(status="ok", account_id=r["id"], email=r["email"], reason="本地 token 较新，已推送远程")
        else:
            err = result.get("error") or result.get("message") or "更新失败"
            conn.execute("UPDATE accounts SET remote_sync_status='fail', remote_sync_at=?, remote_sync_error=?, updated_at=? WHERE id=?",
                         (ts, str(err)[:500], ts, r["id"]))
            add_history(conn, r["id"], r["email"], action, "fail", str(err), ts)
            progress(status="fail", account_id=r["id"], email=r["email"], reason=str(err))
        conn.commit()


def _remote_upsert_safe(session, base, csrf_token, csrf_disabled, remote, row, progress, action):
    try:
        _remote_upsert_one(session, base, csrf_token, csrf_disabled, remote, row, progress, action)
    except Exception as exc:  # noqa: BLE001
        ts = now_local()
        error = f"远程同步异常：{exc}"[:500]
        with get_conn(DB_PATH) as conn:
            conn.execute(
                """
                UPDATE accounts
                SET remote_sync_status='fail', remote_sync_at=?, remote_sync_error=?, updated_at=?
                WHERE id=?
                """,
                (ts, error, ts, row["id"]),
            )
            add_history(conn, row["id"], row["email"], action, "fail", error, ts)
            conn.commit()
        progress(status="fail", account_id=row["id"], email=row["email"], reason=error)


@app.post("/api/remote/resync")
def remote_resync(payload: BatchPayload):
    """把本地刷新后(dirty/指定)账号的 token 推送到远程（本地为准 upsert）。"""
    with get_conn(DB_PATH) as conn:
        if payload.ids:
            marks = ",".join("?" for _ in payload.ids)
            rows = conn.execute(
                f"""
                SELECT * FROM accounts
                WHERE id IN ({marks})
                  AND (graph_status='ok' OR imap_status='ok' OR pop_status='ok')
                ORDER BY id
                """,
                payload.ids,
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM accounts
                WHERE remote_sync_status='dirty'
                  AND (graph_status='ok' OR imap_status='ok' OR pop_status='ok')
                ORDER BY id
                """
            ).fetchall()
    if not rows:
        raise HTTPException(status_code=400, detail="没有待同步账号")
    rows = [dict(r) for r in rows]
    workers = clamp_concurrency(payload.concurrency, 4)

    def runner(progress, is_cancelled):
        session, base, csrf_token, csrf_disabled, remote = _remote_session(pool=workers + 2, thread_safe=True)
        try:
            remote_items = list_remote_accounts(session, base)
            session._email_index = index_accounts_by_email(remote_items)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log_event("REMOTE", f"预拉远程账号列表失败，回退逐号搜索：{exc}", "WARN")
            session._email_index = None  # type: ignore[attr-defined]

        def do_one(r):
            _remote_upsert_safe(session, base, csrf_token, csrf_disabled, remote, r, progress, "remote-resync")

        run_cancellable(rows, workers, do_one, is_cancelled)
        log_event("REMOTE", f"远程 token 同步{'已终止' if is_cancelled() else '完成'} | 并发={workers}")

    job_id = jobs.submit_custom("remote-resync", len(rows), runner)
    return {"success": True, "job_id": job_id, "total": len(rows), "concurrency": workers}


@app.post("/api/remote/reconcile")
def remote_reconcile(payload: BatchPayload):
    with get_conn(DB_PATH) as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()]
    normal_rows = [r for r in rows if is_normal_account(r)]
    banned_rows = [r for r in rows if is_banned_row(r)]
    workers = clamp_concurrency(payload.concurrency, 4)

    def runner(progress, is_cancelled):
        session, base, csrf_token, csrf_disabled, remote = _remote_session(pool=workers + 2)
        remote_items = list_remote_accounts(session, base)
        remote_by_email = {str(item.get("email", "")).lower(): item for item in remote_items}
        local_by_email = {row["email"].lower(): row for row in rows}
        bulk_group_ids = {int(value) for value in (remote.get("group_map") or {}).values()}
        stale_remote = [
            item for item in remote_items
            if int(item.get("group_id") or 0) in bulk_group_ids
            and str(item.get("email", "")).lower() not in local_by_email
        ]
        progress.set_total(len(normal_rows) + len(banned_rows) + len(stale_remote))
        sync_rows = []
        ts = now_local()

        with get_conn(DB_PATH) as conn:
            for row in normal_rows:
                item = remote_by_email.get(row["email"].lower())
                if item and row.get("remote_sync_status") != "dirty":
                    conn.execute(
                        """
                        UPDATE accounts
                        SET remote_sync_status='synced', remote_id=?, remote_sync_at=?,
                            remote_sync_error='', updated_at=?
                        WHERE id=?
                        """,
                        (str(item.get("id") or ""), ts, ts, row["id"]),
                    )
                    progress(status="ok", account_id=row["id"], email=row["email"], reason="远程已存在，状态已校准")
                else:
                    sync_rows.append(row)
            for row in banned_rows:
                if row["email"].lower() not in remote_by_email:
                    conn.execute(
                        """
                        UPDATE accounts
                        SET remote_sync_status='removed', remote_sync_at=?,
                            remote_sync_error='', updated_at=?
                        WHERE id=?
                        """,
                        (ts, ts, row["id"]),
                    )
                    progress(status="ok", account_id=row["id"], email=row["email"], reason="封禁账号远程已不存在")
            conn.commit()

        def sync_one(row):
            _remote_upsert_safe(session, base, csrf_token, csrf_disabled, remote, row, progress, "remote-reconcile")

        run_cancellable(sync_rows, workers, sync_one, is_cancelled)
        if is_cancelled():
            log_event("REMOTE", "远程校准已终止：停止上传后续账号", "WARN")
            return

        banned_remote = [row for row in banned_rows if row["email"].lower() in remote_by_email]

        def remove_banned(row):
            try:
                result = delete_account_remote(session, base, csrf_token, csrf_disabled, row["email"])
                ok = bool(result.get("success", False)) or result.get("http_status") in (200, 204, 404)
                error = "" if ok else str(result.get("error") or result.get("message") or result.get("http_status") or "远程删除失败")[:500]
            except Exception as exc:  # noqa: BLE001
                ok = False
                error = f"远程删除异常：{exc}"[:500]
            now = now_local()
            with get_conn(DB_PATH) as conn:
                conn.execute(
                    """
                    UPDATE accounts
                    SET remote_sync_status=?, remote_sync_at=?, remote_sync_error=?, updated_at=?
                    WHERE id=?
                    """,
                    ("removed" if ok else "fail", now, error, now, row["id"]),
                )
                add_history(
                    conn,
                    row["id"],
                    row["email"],
                    "remote-reconcile",
                    "ok" if ok else "fail",
                    "封禁账号已从远程移除" if ok else error,
                    now,
                )
                conn.commit()
            progress(
                status="ok" if ok else "fail",
                account_id=row["id"],
                email=row["email"],
                reason="封禁账号已从远程移除" if ok else error,
            )

        run_cancellable(banned_remote, workers, remove_banned, is_cancelled)
        if is_cancelled():
            log_event("REMOTE", "远程校准已终止：停止清理远程孤立账号", "WARN")
            return

        def remove_stale(item):
            email = str(item.get("email") or "")
            try:
                result = delete_account_remote(session, base, csrf_token, csrf_disabled, email)
                ok = bool(result.get("success", False)) or result.get("http_status") in (200, 204, 404)
                error = "" if ok else str(result.get("error") or result.get("message") or result.get("http_status") or "远程删除失败")[:500]
            except Exception as exc:  # noqa: BLE001
                ok = False
                error = f"远程删除异常：{exc}"[:500]
            progress(
                status="ok" if ok else "fail",
                email=email,
                reason="已清理远程批量分组孤立账号" if ok else error,
            )

        run_cancellable(stale_remote, workers, remove_stale, is_cancelled)
        log_event("REMOTE", f"远程校准{'已终止' if is_cancelled() else '完成'}", "WARN" if is_cancelled() else "OK")

    total = len(normal_rows) + len(banned_rows)
    job_id = jobs.submit_custom("remote-reconcile", total, runner)
    return {
        "success": True,
        "job_id": job_id,
        "total": total,
        "normal": len(normal_rows),
        "banned": len(banned_rows),
        "concurrency": workers,
    }


# ---------------- 配置 ----------------
@app.get("/api/config")
def api_get_config():
    cfg = get_config()
    remote = cfg["remote"]
    ui = cfg.get("ui") or {}
    return {
        "success": True,
        "config": {
            "proxy_url": (cfg.get("proxy") or {}).get("url", ""),
            "remote_base_url": remote["base_url"],
            "remote_password": remote["password"],
            "group_map": remote.get("group_map") or {},
            "skip_unmapped": remote.get("skip_unmapped", True),
            "external_recipient": (cfg.get("protocol_test") or {}).get("external_recipient", ""),
            "default_concurrency": ui.get("default_concurrency", 100),
        },
    }


@app.put("/api/config")
def put_config(payload: ConfigPayload):
    global CONFIG
    with _CONFIG_LOCK:
        cfg = load_config()
        if payload.proxy_url is not None:
            cfg.setdefault("proxy", {})["url"] = payload.proxy_url.strip()
        if payload.remote_base_url is not None:
            cfg["remote"]["base_url"] = payload.remote_base_url.strip()
        if payload.remote_password is not None:
            cfg["remote"]["password"] = payload.remote_password
        if payload.group_map is not None:
            cfg["remote"]["group_map"] = {
                str(k).strip().lower(): int(v)
                for k, v in payload.group_map.items()
                if str(k).strip()
            }
        if payload.skip_unmapped is not None:
            cfg["remote"]["skip_unmapped"] = payload.skip_unmapped
        if payload.external_recipient is not None:
            cfg.setdefault("protocol_test", {})["external_recipient"] = payload.external_recipient.strip()
        if payload.default_concurrency is not None:
            cfg.setdefault("ui", {})["default_concurrency"] = max(1, min(100, int(payload.default_concurrency)))
        save_config(cfg)
        CONFIG = cfg
        invalidate_remote_cache()
    log_event("CONFIG", "配置已更新")
    return {"success": True}
