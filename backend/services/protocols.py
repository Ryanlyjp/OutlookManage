"""协议测试服务：批量任务默认走可杀的子进程；单条可同进程。"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from backend.services import diagnostics

# job_id -> set of Popen
_active_procs: dict[str, set[subprocess.Popen]] = {}
_procs_lock = threading.Lock()


def _register_proc(job_id: str | None, proc: subprocess.Popen) -> None:
    if not job_id:
        return
    with _procs_lock:
        _active_procs.setdefault(job_id, set()).add(proc)


def _unregister_proc(job_id: str | None, proc: subprocess.Popen) -> None:
    if not job_id:
        return
    with _procs_lock:
        s = _active_procs.get(job_id)
        if not s:
            return
        s.discard(proc)
        if not s:
            _active_procs.pop(job_id, None)


def kill_job_procs(job_id: str) -> int:
    """Terminate subprocesses for a cancelled job. Returns killed count."""
    with _procs_lock:
        procs = list(_active_procs.get(job_id) or [])
        _active_procs.pop(job_id, None)
    killed = 0
    for proc in procs:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                killed += 1
        except Exception:
            pass
    return killed


def run_protocol_test(
    python_exe: str,
    test_script: Path,
    cwd: Path,
    account_line: str,
    timeout: int = 180,
    *,
    proxy_url: str = "",
    external_recipient: str = "",
    skip_send: bool = False,
    protocol_cfg: dict | None = None,
    use_subprocess: bool | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """运行单账号协议测试。

    - 有 job_id 时默认用子进程（可被 cancel 立刻 kill）
    - 无 job_id 时默认同进程（单条点测更快）
    """
    if use_subprocess is None:
        use_subprocess = bool(job_id)
    if not use_subprocess:
        return _run_inprocess(
            account_line,
            proxy_url=proxy_url,
            external_recipient=external_recipient,
            skip_send=skip_send,
            protocol_cfg=protocol_cfg,
            cwd=cwd,
        )
    return _run_subprocess(
        python_exe,
        test_script,
        cwd,
        account_line,
        timeout,
        job_id=job_id,
        proxy_url=proxy_url,
        external_recipient=external_recipient,
        skip_send=skip_send,
    )


def _run_inprocess(
    account_line: str,
    *,
    proxy_url: str = "",
    external_recipient: str = "",
    skip_send: bool = False,
    protocol_cfg: dict | None = None,
    cwd: Path | None = None,
) -> dict[str, Any]:
    root = str(cwd or Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        import test_protocols as tp  # noqa: WPS433

        result = tp.run_account_test(
            account_line,
            proxy_url=proxy_url,
            external_recipient=external_recipient,
            skip_send=skip_send,
            protocol_cfg=protocol_cfg,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": f"协议测试异常：{exc}",
            "stdout": "",
            "stderr": str(exc)[:2000],
        }

    if not isinstance(result, dict):
        return {"success": False, "error": "协议测试未返回字典结果", "stdout": "", "stderr": ""}

    if result.get("fatal_error"):
        return {
            "success": False,
            "error": f"协议测试脚本异常：{result['fatal_error']}",
            "result": result,
            "stdout": "",
            "stderr": str(result.get("traceback") or "")[:2000],
        }

    health = diagnostics.build_health(result)
    return {
        "success": True,
        "result": result,
        "health": health,
        "stdout": "",
        "stderr": "",
        "mode": "inprocess",
    }


def _run_subprocess(
    python_exe: str,
    test_script: Path,
    cwd: Path,
    account_line: str,
    timeout: int,
    job_id: str | None = None,
    proxy_url: str = "",
    external_recipient: str = "",
    skip_send: bool = False,
) -> dict[str, Any]:
    cmd = [python_exe, str(test_script), "--account", account_line]
    if proxy_url:
        cmd.extend(["--proxy", proxy_url])
    if external_recipient:
        cmd.extend(["--external-recipient", external_recipient])
    if skip_send:
        cmd.append("--skip-send")

    try:
        # Windows: new process group so we can kill tree if needed
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": f"启动子进程失败：{exc}", "stdout": "", "stderr": ""}

    _register_proc(job_id, proc)
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return {
                "success": False,
                "error": f"协议测试超时（{timeout}s）",
                "stdout": (stdout or "")[-2000:],
                "stderr": (stderr or "")[-2000:],
            }
    finally:
        _unregister_proc(job_id, proc)

    # 若任务已取消且进程被杀，returncode 非 0
    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()
    if not stdout:
        # 被 kill 时常见无 stdout
        err = "协议测试被中止" if (job_id and proc.returncode not in (0, None)) else "协议测试脚本未返回结果"
        return {
            "success": False,
            "error": err,
            "stdout": "",
            "stderr": stderr[-2000:],
            "aborted": True,
        }

    try:
        result = json.loads(stdout)
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": f"协议测试结果解析失败：{exc}",
            "stdout": stdout[-2000:],
            "stderr": stderr[-2000:],
        }

    if result.get("fatal_error"):
        return {
            "success": False,
            "error": f"协议测试脚本异常：{result['fatal_error']}",
            "result": result,
            "stdout": stdout[-2000:],
            "stderr": stderr[-2000:],
        }

    health = diagnostics.build_health(result)
    return {
        "success": proc.returncode == 0,
        "result": result,
        "health": health,
        "stdout": stdout[-2000:],
        "stderr": stderr[-2000:],
        "mode": "subprocess",
    }
