import datetime
import json
import sqlite3
import unittest

from util import generate_jwt_pair, AuthRequest


class TestUtil(unittest.TestCase):
    def test_generate_jwk_pair(self):
        jwk_key, token = generate_jwt_pair(AuthRequest(username="example_user", password="example_password"), False)
        self.assertIsNotNone(jwk_key)
        self.assertIsNotNone(token)
        print("generated jwk_key and token successfully")

    def test_key_table(self):
        db = sqlite3.connect('totally_not_my_privateKeys.db')
        db.row_factory = sqlite3.Row
        resp = db.execute("PRAGMA TABLE_INFO(keys)").fetchall()
        db.close()
        self.assertTrue(len(resp), 3)
        print("keys table has 3 columns")
        correct = {
            "kid": "INTEGER",
            "key": "BLOB",
            "exp": "INTEGER"
        }
        for i in resp:
            self.assertIn(i['name'], correct)
            self.assertEqual(i['type'], correct[i['name']])
        print("keys table has correct columns")

    def test_user_table(self):
        db = sqlite3.connect('totally_not_my_privateKeys.db')
        db.row_factory = sqlite3.Row
        resp = db.execute("PRAGMA TABLE_INFO(users)").fetchall()
        db.close()
        self.assertTrue(len(resp), 6)
        print("users table has 6 columns")
        correct = {
            "id": "INTEGER",
            "username": "TEXT",
            "password_hash": "TEXT",
            "email": "TEXT",
            "date_registered": "TIMESTAMP",
            "last_login": "TIMESTAMP"
        }
        for i in resp:
            self.assertIn(i['name'], correct)
            self.assertEqual(i['type'], correct[i['name']])
        print("users table has correct columns")

    def test_auth_logs_table(self):
        db = sqlite3.connect('totally_not_my_privateKeys.db')
        db.row_factory = sqlite3.Row
        resp = db.execute("PRAGMA TABLE_INFO(auth_logs)").fetchall()
        db.close()
        self.assertTrue(len(resp), 3)
        print("auth_logs table has 4 columns")
        correct = {
            "id": "INTEGER",
            "request_ip": "TEXT",
            "request_timestamp": "TIMESTAMP",
            "user_id": "INTEGER"
        }
        for i in resp:
            self.assertIn(i['name'], correct)
            self.assertEqual(i['type'], correct[i['name']])
        print("auth_logs table has correct columns")

    def test_expired_key_is_None(self):
        print("generating expired jwt")
        jwk_key, token = generate_jwt_pair(AuthRequest(username="expired_user", password="expired_password"), True)
        self.assertIsNone(jwk_key)
        print("jwk_key is None")

    def test_expired_key_is_expired(self):
        print("ensuring expired jwt is expired")
        jwk_key, token = generate_jwt_pair(AuthRequest(username="expired_user", password="expired_password"), True)
        self.assertTrue(json.loads(token.claims)["exp"] < datetime.datetime.now().timestamp())
        print("jwt is expired")

    def test_valid_key_is_not_expired(self):
        print("ensuring valid jwt is not expired")
        jwk_key, token = generate_jwt_pair(AuthRequest(username="example_user", password="example_password"), False)
        self.assertTrue(json.loads(token.claims)["exp"] > datetime.datetime.now().timestamp())
        print("jwt is not expired")

    def test_valid_key_is_not_None(self):
        print("ensuring valid jwt is not None")
        jwk_key, token = generate_jwt_pair(AuthRequest(username="example_user", password="example_password"), False)
        self.assertTrue(json.loads(token.claims)["exp"] > datetime.datetime.now().timestamp())
        self.assertIsNotNone(jwk_key)
        print("jwk_key is not None")


if __name__ == '__main__':
    unittest.main()
