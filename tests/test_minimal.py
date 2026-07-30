from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import main
from backend.db import get_conn, init_db


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


class TestPassword(unittest.TestCase):
    def test_hash_round_trip(self):
        encoded = main.hash_admin_password("StrongPassword-123!")
        self.assertTrue(main.verify_admin_password("StrongPassword-123!", encoded))
        self.assertFalse(main.verify_admin_password("wrong", encoded))


if __name__ == "__main__":
    unittest.main()
