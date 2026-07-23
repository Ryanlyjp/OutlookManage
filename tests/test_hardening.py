"""Unit tests for manage-webui hardening (no live network required)."""
from __future__ import annotations

import gc
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.db import get_conn, init_db
from backend.services import jobs, locks, protocols, remote_pool


def _tmp_dir():
    # Windows: sqlite WAL may briefly keep handles; ignore cleanup errors
    return tempfile.TemporaryDirectory(ignore_cleanup_errors=True)


class TestBannedAndIdsFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp_dir()
        self.db = Path(self.tmp.name) / "t.db"
        init_db(self.db)
        ts = "2026-07-24T00:00:00+08:00"
        with get_conn(self.db) as conn:
            for email, hs, sev in [
                ("ok@test.com", "graph_only", "ok"),
                ("ban-status@test.com", "banned", "fail"),
                ("ban-sev@test.com", "token_invalid", "banned"),
                ("normal@test.com", "", ""),
            ]:
                conn.execute(
                    """INSERT INTO accounts
                    (email,password,client_id,refresh_token,health_status,health_severity,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (email, "p", "cid", "rt", hs, sev, ts, ts),
                )
            conn.commit()

        import backend.main as main

        self.main = main
        self._old_db = main.DB_PATH
        main.DB_PATH = self.db

    def tearDown(self):
        self.main.DB_PATH = self._old_db
        gc.collect()
        self.tmp.cleanup()

    def test_is_banned_row_unifies_fields(self):
        with get_conn(self.db) as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM accounts").fetchall()]
        by_email = {r["email"]: r for r in rows}
        self.assertFalse(self.main.is_banned_row(by_email["ok@test.com"]))
        self.assertTrue(self.main.is_banned_row(by_email["ban-status@test.com"]))
        self.assertTrue(self.main.is_banned_row(by_email["ban-sev@test.com"]))
        self.assertTrue(self.main.is_abuse_candidate(by_email["ban-status@test.com"]))
        self.assertTrue(self.main.is_abuse_candidate(by_email["ban-sev@test.com"]))

    def test_ids_or_all_filters_banned_even_when_ids_passed(self):
        payload = self.main.BatchPayload(ids=[1, 2, 3, 4], concurrency=2)
        ids = self.main._ids_or_all(payload, self.main.SQL_NOT_BANNED)
        # 1=ok, 4=normal; 2 and 3 banned
        self.assertEqual(ids, [1, 4])

    def test_ids_or_all_all_mode(self):
        payload = self.main.BatchPayload(ids=None)
        ids = self.main._ids_or_all(payload, self.main.SQL_NOT_BANNED)
        self.assertEqual(ids, [1, 4])


class TestLocks(unittest.TestCase):
    def test_try_acquire_release(self):
        self.assertTrue(locks.try_acquire(99901))
        self.assertFalse(locks.try_acquire(99901))
        locks.release(99901)
        self.assertTrue(locks.try_acquire(99901))
        locks.release(99901)

    def test_concurrent_single_holder(self):
        held = []
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            if locks.try_acquire(99902):
                held.append(1)
                time.sleep(0.05)
                locks.release(99902)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(held), 1)
        self.assertFalse(locks.is_locked(99902))


class TestJobs(unittest.TestCase):
    def test_submit_and_progress(self):
        def worker(x):
            return {"status": "ok", "account_id": x, "reason": "done"}

        job_id = jobs.submit("t", [1, 2, 3], worker, max_workers=2)
        deadline = time.time() + 5
        while time.time() < deadline:
            j = jobs.get_job(job_id)
            if j and j["state"] == "done":
                break
            time.sleep(0.05)
        j = jobs.get_job(job_id)
        self.assertIsNotNone(j)
        self.assertEqual(j["state"], "done")
        self.assertEqual(j["succeeded"], 3)
        self.assertEqual(j["processed"], 3)

    def test_cancel_sets_flag(self):
        started = threading.Event()
        release = threading.Event()

        def worker(x):
            started.set()
            release.wait(timeout=2)
            return {"status": "ok", "account_id": x, "reason": "x"}

        job_id = jobs.submit("t", [1], worker, max_workers=1)
        self.assertTrue(started.wait(2))
        self.assertTrue(jobs.cancel(job_id))
        # 硬取消：立即标 cancelled，不依赖 worker 返回
        j = jobs.get_job(job_id)
        self.assertTrue(j["cancelled"])
        self.assertEqual(j["state"], "cancelled")
        self.assertTrue(jobs.is_cancelled(job_id))
        release.set()
        time.sleep(0.3)
        j = jobs.get_job(job_id)
        self.assertEqual(j["state"], "cancelled")
        # 在途结果应记为 skip，不计入成功
        self.assertEqual(j["succeeded"], 0)

    def test_hard_cancel_stops_queue(self):
        gate = threading.Event()
        started = []

        def worker(x):
            started.append(x)
            gate.wait(timeout=3)
            return {"status": "ok", "account_id": x, "reason": "x"}

        job_id = jobs.submit("t", list(range(20)), worker, max_workers=2)
        deadline = time.time() + 2
        while time.time() < deadline and len(started) < 1:
            time.sleep(0.02)
        self.assertTrue(jobs.cancel(job_id))
        j = jobs.get_job(job_id)
        self.assertEqual(j["state"], "cancelled")
        gate.set()
        time.sleep(0.4)
        j = jobs.get_job(job_id)
        self.assertEqual(j["state"], "cancelled")
        self.assertEqual(j["processed"], j["total"])
        self.assertEqual(j["succeeded"], 0)
        self.assertGreaterEqual(j["skipped"], 1)
        # 不应把整队都跑完
        self.assertLess(len(started), 20)


class TestRemotePool(unittest.TestCase):
    def test_thread_safe_session_serializes(self):
        raw = remote_pool.build_session(None, pool_maxsize=5, thread_safe=False)
        safe = remote_pool.ThreadSafeSession(raw)
        order = []

        def call(i):
            def _req(method, url, **kwargs):
                order.append(f"start{i}")
                time.sleep(0.02)
                order.append(f"end{i}")
                class R:
                    status_code = 200
                    def json(self_inner):
                        return {}
                return R()
            safe._session.request = _req
            safe.get("http://example")

        # sequential via lock: no interleaving start/end of different threads if lock works
        ts = [threading.Thread(target=call, args=(i,)) for i in range(3)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        # with lock, each startN should be followed by endN before another start
        for i in range(0, len(order), 2):
            self.assertTrue(order[i].startswith("start"))
            self.assertEqual(order[i].replace("start", "end"), order[i + 1])

    def test_index_accounts_by_email(self):
        items = [{"email": "A@X.com", "id": 1}, {"email": "b@x.com", "id": 2}]
        idx = remote_pool.index_accounts_by_email(items)
        self.assertEqual(idx["a@x.com"]["id"], 1)
        self.assertEqual(idx["b@x.com"]["id"], 2)


class TestProtocolsInprocess(unittest.TestCase):
    def test_run_account_test_exists(self):
        import test_protocols as tp
        self.assertTrue(callable(tp.run_account_test))

    def test_inprocess_wrapper_handles_bad_account(self):
        res = protocols.run_protocol_test(
            sys.executable,
            ROOT / "test_protocols.py",
            ROOT,
            "bad-line",
            use_subprocess=False,
        )
        self.assertFalse(res["success"])
        self.assertIn("error", res)


class TestListAccountsNoSecrets(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp_dir()
        self.db = Path(self.tmp.name) / "t.db"
        init_db(self.db)
        ts = "2026-07-24T00:00:00+08:00"
        with get_conn(self.db) as conn:
            conn.execute(
                """INSERT INTO accounts
                (email,password,client_id,refresh_token,created_at,updated_at)
                VALUES (?,?,?,?,?,?)""",
                ("s@t.com", "secret-pass", "cid", "secret-rt", ts, ts),
            )
            conn.commit()
        import backend.main as main
        self.main = main
        self._old = main.DB_PATH
        main.DB_PATH = self.db

    def tearDown(self):
        self.main.DB_PATH = self._old
        gc.collect()
        self.tmp.cleanup()

    def test_list_strips_secrets_by_default(self):
        data = self.main.list_accounts()
        self.assertTrue(data["success"])
        item = data["items"][0]
        self.assertEqual(item["email"], "s@t.com")
        self.assertNotIn("password", item)
        self.assertNotIn("refresh_token", item)

    def test_list_include_secrets(self):
        data = self.main.list_accounts(include_secrets=True)
        item = data["items"][0]
        self.assertEqual(item["password"], "secret-pass")
        self.assertEqual(item["refresh_token"], "secret-rt")


class TestRefreshLockShorten(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmp_dir()
        self.db = Path(self.tmp.name) / "t.db"
        init_db(self.db)
        ts = "2026-07-24T00:00:00+08:00"
        with get_conn(self.db) as conn:
            conn.execute(
                """INSERT INTO accounts
                (email,password,client_id,refresh_token,created_at,updated_at)
                VALUES (?,?,?,?,?,?)""",
                ("r@t.com", "p", "cid", "rt", ts, ts),
            )
            conn.commit()
        import backend.main as main
        self.main = main
        self._old = main.DB_PATH
        main.DB_PATH = self.db
        self.sync_calls = []

    def tearDown(self):
        self.main.DB_PATH = self._old
        locks.release(1)
        gc.collect()
        self.tmp.cleanup()

    def test_auto_remote_after_release(self):
        order = []

        def fake_refresh(*a, **k):
            order.append("graph")
            return {
                "success": True,
                "access_token": "a",
                "refresh_token": "newrt",
                "scope": "x",
                "attempts": [],
            }

        def fake_sync(aid):
            # lock should already be released
            order.append("sync")
            order.append("locked" if locks.is_locked(aid) else "unlocked")

        with mock.patch.object(self.main, "refresh_with_graph", side_effect=fake_refresh), mock.patch.object(
            self.main, "auto_remote_sync", side_effect=fake_sync
        ):
            res = self.main.refresh_one(1)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(order, ["graph", "sync", "unlocked"])


class TestLogLock(unittest.TestCase):
    def test_log_event_concurrent(self):
        import backend.main as main
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "app.log"
        old = main.LOG_PATH
        main.LOG_PATH = path
        try:
            def w(i):
                for _ in range(20):
                    main.log_event("T", f"line-{i}")

            ts = [threading.Thread(target=w, args=(i,)) for i in range(4)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("\n"), 80)
        finally:
            main.LOG_PATH = old
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
