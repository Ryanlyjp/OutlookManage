"""进程内按账号锁，防止同一账号同时跑刷新/协议测试/远程同步。"""
import threading
from contextlib import contextmanager

_global_lock = threading.Lock()
_locked: set[int] = set()


def is_locked(account_id: int) -> bool:
    with _global_lock:
        return account_id in _locked


def try_acquire(account_id: int) -> bool:
    with _global_lock:
        if account_id in _locked:
            return False
        _locked.add(account_id)
        return True


def release(account_id: int) -> None:
    with _global_lock:
        _locked.discard(account_id)


@contextmanager
def account_lock(account_id: int):
    """获取账号锁；若已被占用抛 RuntimeError。"""
    if not try_acquire(account_id):
        raise RuntimeError("账号正在执行其他任务，请稍后重试")
    try:
        yield
    finally:
        release(account_id)
