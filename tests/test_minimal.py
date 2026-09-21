from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from backend import main
from backend import mail_service
from backend.db import get_conn, init_db
from backend.services import scheduler


class TestImportParsing(unittest.TestCase):
    def test_two_part_format(self):
        account = main.parse_account_line("client-id----refresh-token")
        self.assertEqual(account["client_id"], "client-id")
        self.assertEqual(account["refresh_token"], "refresh-token")
        self.assertTrue(account["email"].endswith("@local.invalid"))

    def test_legacy_four_part_format(self):
        account = main.parse_account_line("a@outlook.com----pass----cid----rt")
        self.assertEqual(account["email"], "a@outlook.com")
        self.assertEqual(account["client_id"], "cid")

    def test_invalid_format(self):
        with self.assertRaises(ValueError):
            main.parse_account_line("invalid")


class TestClassification(unittest.TestCase):
    def test_abuse(self):
        self.assertEqual(main.classify_failure("User account is found to be in service abuse mode")[0], "banned")

    def test_invalid_token(self):
        self.assertEqual(main.classify_failure("AADSTS70000 invalid_grant")[0], "token_invalid")

    def test_other_error(self):
        self.assertEqual(main.classify_failure("proxy connection reset")[0], "other_error")


class TestGraphCheck(unittest.TestCase):
    @mock.patch("backend.main.requests.Session")
    def test_success_reads_message(self, session_class):
        session = session_class.return_value
        token = mock.Mock()
        token.json.return_value = {"access_token": "at", "refresh_token": "new-rt"}
        me = mock.Mock(ok=True)
        me.json.return_value = {"mail": "a@outlook.com"}
        messages = mock.Mock(ok=True)
        messages.json.return_value = {"value": [{"id": "1"}]}
        session.post.return_value = token
        session.get.side_effect = [me, messages]

        result = main.graph_check("cid", "rt", "http://127.0.0.1:2323")

        self.assertTrue(result["success"])
        self.assertEqual(result["health_status"], "normal")
        self.assertEqual(result["email"], "a@outlook.com")
        self.assertEqual(session.proxies["https"], "http://127.0.0.1:2323")
        self.assertIn("/consumers/", session.post.call_args.args[0])
        self.assertIn("/me/messages", session.get.call_args_list[1].args[0])

    @mock.patch("backend.main.requests.Session")
    def test_abuse_token_response(self, session_class):
        response = mock.Mock(text="")
        response.json.return_value = {"error": "invalid_grant", "error_description": "service abuse mode"}
        session_class.return_value.post.return_value = response
        result = main.graph_check("cid", "rt")
        self.assertFalse(result["success"])
        self.assertEqual(result["health_status"], "banned")


class TestDatabaseCompatibility(unittest.TestCase):
    def test_existing_schema_can_store_minimal_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            with get_conn(path) as conn:
                conn.execute(
                    """INSERT INTO accounts (email,password,client_id,refresh_token,status,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    ("a@outlook.com", "", "cid", "rt", "new", "now", "now"),
                )
                conn.execute("UPDATE accounts SET health_status='normal',graph_status='ok' WHERE email=?", ("a@outlook.com",))
                row = conn.execute("SELECT health_status,graph_status FROM accounts").fetchone()
            self.assertEqual(tuple(row), ("normal", "ok"))

    @mock.patch("backend.main.jobs.submit", return_value="job-1")
    def test_selected_batch_uses_existing_ids(self, submit):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            with get_conn(path) as conn:
                for email in ("a@outlook.com", "b@outlook.com"):
                    conn.execute(
                        """INSERT INTO accounts (email,password,client_id,refresh_token,status,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (email, "", "cid", "rt", "new", "now", "now"),
                    )
                conn.commit()
            old_path = main.DB_PATH
            main.DB_PATH = path
            try:
                result = main.test_selected(main.BatchPayload(ids=[2, 999, 1, 2], concurrency=3))
            finally:
                main.DB_PATH = old_path
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["concurrency"], 3)
        self.assertEqual(submit.call_args.args[1], [1, 2])

    def test_delete_selected_removes_accounts_and_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            with get_conn(path) as conn:
                for email in ("a@outlook.com", "b@outlook.com", "c@outlook.com"):
                    cursor = conn.execute(
                        """INSERT INTO accounts (email,password,client_id,refresh_token,status,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (email, "", "cid", "rt", "new", "now", "now"),
                    )
                    conn.execute(
                        "INSERT INTO history (account_id,email,action,status,detail,created_at) VALUES (?,?,?,?,?,?)",
                        (cursor.lastrowid, email, "graph_check", "ok", "done", "now"),
                    )
                conn.commit()
            old_path = main.DB_PATH
            main.DB_PATH = path
            try:
                result = main.delete_selected(main.BatchPayload(ids=[1, 2, 2, 999]))
            finally:
                main.DB_PATH = old_path
            with get_conn(path) as conn:
                accounts = conn.execute("SELECT id FROM accounts ORDER BY id").fetchall()
                history = conn.execute("SELECT account_id FROM history ORDER BY account_id").fetchall()
        self.assertEqual(result["deleted"], 2)
        self.assertEqual([row["id"] for row in accounts], [3])
        self.assertEqual([row["account_id"] for row in history], [3])


class TestPassword(unittest.TestCase):
    def test_hash_round_trip(self):
        encoded = main.hash_admin_password("StrongPassword-123!")
        self.assertTrue(main.verify_admin_password("StrongPassword-123!", encoded))
        self.assertFalse(main.verify_admin_password("wrong", encoded))

    def test_empty_proxy_means_direct_connection(self):
        old_config = main.CONFIG
        main.CONFIG = {**old_config, "proxy": {"url": ""}}
        try:
            self.assertEqual(main.proxy_url(), "")
        finally:
            main.CONFIG = old_config

    def test_plain_api_key_is_used_for_authentication_hash(self):
        old_config = main.CONFIG
        main.CONFIG = {**old_config, "api": {"key": "A" * 24, "key_hash": "legacy"}}
        try:
            self.assertEqual(main.global_api_key_hash(), main.secret_hash("A" * 24))
        finally:
            main.CONFIG = old_config


class TestOtpExtraction(unittest.TestCase):
    def test_code_crossing_keyword_window_remains_complete(self):
        for code in ('123456', '012345'):
            for text in ('code' + ' ' * 55 + code, code + ' ' * 35 + 'code'):
                with self.subTest(text=text):
                    self.assertEqual(mail_service.extract_otp({'body_text': text}), code)

    def test_window_does_not_turn_long_number_into_otp(self):
        self.assertEqual(mail_service.extract_otp({'body_text': 'code' + ' ' * 55 + '123456789012'}), '')

    def test_extracts_latest_message_code(self):
        message = {"subject": "Your verification code", "body_text": "Use 482913 to continue.", "body_html": ""}
        self.assertEqual(mail_service.extract_otp(message), "482913")

    def test_ignores_unrelated_words_near_keyword(self):
        message = {"subject": "", "body_text": "OTP for your account is A7B92C", "body_html": ""}
        self.assertEqual(mail_service.extract_otp(message), "A7B92C")

    def test_reads_html_visible_text(self):
        message = {"subject": "", "body_text": "", "body_html": "<p>验证码：<b>778899</b></p>"}
        self.assertEqual(mail_service.extract_otp(message), "778899")

    def test_does_not_scan_another_message(self):
        message = {"subject": "Newsletter", "body_text": "No one-time code here", "body_html": ""}
        self.assertEqual(mail_service.extract_otp(message), "")

    @mock.patch("backend.mail_service.graph_get")
    def test_inbox_and_junk_are_merged_by_received_time(self, graph_get):
        graph_get.side_effect = [
            {"value": [{"id": "inbox", "subject": "Inbox", "receivedDateTime": "2026-01-01T10:00:00Z"}]},
            {"value": [{"id": "junk", "subject": "Junk", "receivedDateTime": "2026-01-01T11:00:00Z"}]},
        ]
        messages = mail_service.list_messages(mock.Mock(), 5)
        self.assertEqual([item["id"] for item in messages], ["junk", "inbox"])
        self.assertIn("/inbox/messages", graph_get.call_args_list[0].args[1])
        self.assertIn("/junkemail/messages", graph_get.call_args_list[1].args[1])


class TestShareSchema(unittest.TestCase):
    def test_one_share_per_account(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            with get_conn(path) as conn:
                cursor = conn.execute("INSERT INTO accounts(email,password,client_id,refresh_token,created_at,updated_at) VALUES(?,?,?,?,?,?)", ("a@outlook.com", "", "cid", "rt", "now", "now"))
                values = (cursor.lastrowid, "page-1", "hash", 1, "", "now", "now")
                conn.execute("INSERT INTO otp_shares(account_id,page_token,api_key_hash,enabled,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", values)
                with self.assertRaises(Exception):
                    conn.execute("INSERT INTO otp_shares(account_id,page_token,api_key_hash,enabled,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (cursor.lastrowid, "page-2", "hash2", 1, "", "now", "now"))


class TestScheduledTasks(unittest.TestCase):
    def test_task_list_includes_account_created_at(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            with get_conn(path) as conn:
                account_id = conn.execute("INSERT INTO accounts(email,password,client_id,refresh_token,created_at,updated_at) VALUES(?,?,?,?,?,?)", ("created@outlook.com", "", "cid", "rt", "2026-09-11T07:52:00+00:00", "now")).lastrowid
                conn.execute("INSERT INTO scheduled_tasks(account_id,interval_hours,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?)", (account_id, 1, "2099-01-01T00:00:00+00:00", "now", "now"))
                conn.commit()
            old_path = main.DB_PATH
            main.DB_PATH = path
            try:
                task = main.list_scheduled_tasks()["tasks"][0]
            finally:
                main.DB_PATH = old_path
            self.assertEqual(task["account_created_at"], "2026-09-11T07:52:00+00:00")

    def test_interval_has_one_minute_minimum(self):
        self.assertEqual(main.scheduled_interval_minutes(main.ScheduledTaskPayload(account_id=1, interval_minutes=1)), 1)
        with self.assertRaises(main.HTTPException):
            main.scheduled_interval_minutes(main.ScheduledTaskPayload(account_id=1, interval_minutes=0.99))

    def test_legacy_hour_interval_converts_to_minutes(self):
        payload = main.ScheduledTaskPayload(account_id=1, interval_hours=0.5)
        self.assertEqual(main.scheduled_interval_minutes(payload), 30)

    def test_due_task_runs_and_records_short_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            current = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
            with get_conn(path) as conn:
                account_id = conn.execute("INSERT INTO accounts(email,password,client_id,refresh_token,created_at,updated_at) VALUES(?,?,?,?,?,?)", ("timer@outlook.com", "", "cid", "rt", "now", "now")).lastrowid
                task_id = conn.execute("INSERT INTO scheduled_tasks(account_id,interval_hours,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?)", (account_id, 0.5, (current - timedelta(minutes=1)).isoformat(timespec="seconds"), "now", "now")).lastrowid
                conn.commit()
            calls = []

            def worker(value):
                calls.append(value)
                return {"status": "fail", "reason": "Graph timeout"}

            self.assertEqual(scheduler.run_due_once(path, worker, current), 1)
            with get_conn(path) as conn:
                task = conn.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
                runs = conn.execute("SELECT * FROM scheduled_task_runs WHERE task_id=?", (task_id,)).fetchall()
            self.assertEqual(calls, [account_id])
            self.assertEqual(task["last_status"], "fail")
            self.assertEqual(task["last_message"], "Graph timeout")
            self.assertEqual(len(runs), 1)
            self.assertEqual(datetime.fromisoformat(task["next_run_at"]), current + timedelta(minutes=30))

    def test_banned_stops_task_and_sends_notification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            current = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
            with get_conn(path) as conn:
                account_id = conn.execute("INSERT INTO accounts(email,password,client_id,refresh_token,created_at,updated_at) VALUES(?,?,?,?,?,?)", ("banned@outlook.com", "", "cid", "rt", "now", "now")).lastrowid
                task_id = conn.execute("INSERT INTO scheduled_tasks(account_id,interval_hours,next_run_at,notify_telegram,created_at,updated_at) VALUES(?,?,?,?,?,?)", (account_id, 1, (current - timedelta(minutes=1)).isoformat(timespec="seconds"), 1, "now", "now")).lastrowid
                conn.commit()
            notifications = []
            scheduler.run_due_once(path, lambda _: {"status": "fail", "health_status": "banned", "email": "banned@outlook.com", "reason": "账号已封禁"}, current, lambda result, timestamp: notifications.append((result, timestamp)))
            with get_conn(path) as conn:
                task = conn.execute("SELECT enabled,last_status FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
            self.assertEqual(task["enabled"], 0)
            self.assertEqual(task["last_status"], "fail")
            self.assertEqual(notifications[0][0]["email"], "banned@outlook.com")

    def test_non_banned_failure_does_not_stop_task(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "accounts.db"
            init_db(path)
            current = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
            with get_conn(path) as conn:
                account_id = conn.execute("INSERT INTO accounts(email,password,client_id,refresh_token,created_at,updated_at) VALUES(?,?,?,?,?,?)", ("error@outlook.com", "", "cid", "rt", "now", "now")).lastrowid
                task_id = conn.execute("INSERT INTO scheduled_tasks(account_id,interval_hours,next_run_at,created_at,updated_at) VALUES(?,?,?,?,?)", (account_id, 1, (current - timedelta(minutes=1)).isoformat(timespec="seconds"), "now", "now")).lastrowid
                conn.commit()
            scheduler.run_due_once(path, lambda _: {"status": "fail", "health_status": "token_invalid", "reason": "Token 无效"}, current)
            with get_conn(path) as conn:
                enabled = conn.execute("SELECT enabled FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()[0]
            self.assertEqual(enabled, 1)

    @mock.patch("backend.main.requests.post")
    def test_telegram_message_format(self, post):
        post.return_value.ok = True
        old_config = main.CONFIG
        main.CONFIG = {**old_config, "proxy": {"url": ""}, "telegram": {"bot_token": "bot-token", "chat_id": "chat-id"}}
        try:
            main.telegram_notify_banned({"email": "user@outlook.com"}, "2026-08-15T12:00:00+00:00")
        finally:
            main.CONFIG = old_config
        self.assertEqual(post.call_args.kwargs["json"], {"chat_id": "chat-id", "text": "user@outlook.com-banned-2026-08-15T12:00:00+00:00"})
        self.assertIsNone(post.call_args.kwargs["proxies"])


if __name__ == "__main__":
    unittest.main()
