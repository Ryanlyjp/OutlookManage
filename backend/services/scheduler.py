from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from backend.db import get_conn

_stop = threading.Event()
_thread: threading.Thread | None = None
_lock = threading.Lock()


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def next_run_iso(interval_hours: float, start: datetime | None = None) -> str:
    base = start or datetime.now().astimezone()
    return (base + timedelta(hours=interval_hours)).isoformat(timespec="seconds")


def run_due_once(db_path: Path, worker: Callable[[int], dict[str, Any]], current_time: datetime | None = None, notifier: Callable[[dict[str, Any], str], None] | None = None) -> int:
    current = current_time or datetime.now().astimezone()
    current_iso = current.isoformat(timespec="seconds")
    with get_conn(db_path) as conn:
        tasks = conn.execute("SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at,id", (current_iso,)).fetchall()
        for task in tasks:
            conn.execute("UPDATE scheduled_tasks SET next_run_at=?,updated_at=? WHERE id=? AND next_run_at=?", (next_run_iso(float(task["interval_hours"]), current), current_iso, task["id"], task["next_run_at"]))
        conn.commit()
    for task in tasks:
        try:
            result = worker(int(task["account_id"]))
        except Exception as exc:
            result = {"status": "fail", "reason": str(exc)}
        status = "ok" if result.get("status") == "ok" else "fail"
        message = str(result.get("reason") or ("测试正常" if status == "ok" else "测试失败"))[:160]
        finished_at = now_iso()
        banned = result.get("health_status") == "banned"
        if banned and task["notify_telegram"] and notifier:
            try:
                notifier(result, finished_at)
            except Exception as exc:
                message = f"{message}；TG通知失败：{exc}"[:160]
        with get_conn(db_path) as conn:
            exists = conn.execute("SELECT id FROM scheduled_tasks WHERE id=?", (task["id"],)).fetchone()
            if not exists:
                continue
            conn.execute("UPDATE scheduled_tasks SET last_run_at=?,last_status=?,last_message=?,enabled=?,updated_at=? WHERE id=?", (finished_at, status, message, 0 if banned else task["enabled"], finished_at, task["id"]))
            conn.execute("INSERT INTO scheduled_task_runs(task_id,status,message,created_at) VALUES(?,?,?,?)", (task["id"], status, message, finished_at))
            old_ids = [row["id"] for row in conn.execute("SELECT id FROM scheduled_task_runs WHERE task_id=? ORDER BY id DESC LIMIT -1 OFFSET 10", (task["id"],)).fetchall()]
            if old_ids:
                marks = ",".join("?" for _ in old_ids)
                conn.execute(f"DELETE FROM scheduled_task_runs WHERE id IN ({marks})", old_ids)
            conn.commit()
    return len(tasks)


def start(db_path: Path, worker: Callable[[int], dict[str, Any]], notifier: Callable[[dict[str, Any], str], None] | None = None) -> None:
    global _thread
    with _lock:
        if _thread and _thread.is_alive():
            return
        _stop.clear()

        def loop() -> None:
            while not _stop.is_set():
                try:
                    run_due_once(db_path, worker, notifier=notifier)
                except Exception:
                    pass
                _stop.wait(30)

        _thread = threading.Thread(target=loop, daemon=True, name="scheduled-graph-checks")
        _thread.start()


def stop() -> None:
    global _thread
    _stop.set()
    thread = _thread
    if thread and thread.is_alive():
        thread.join(timeout=2)
    _thread = None
