import datetime
import json
import unittest

from jwcrypto import jwk, jwt

from util import init_keys, create_keys, generate_rsa_key, generate_jwt


class TestUtil(unittest.TestCase):
    def test_init_keys(self):
        public, private = init_keys()
        self.assertIsNotNone(public)
        self.assertIsNotNone(private)

    def test_create_keys(self):
        public, private = create_keys()
        self.assertIsNotNone(public)
        self.assertIsNotNone(private)

    def test_generate_rsa_key(self):
        public, private = init_keys()
        jwk_key = generate_rsa_key(public, 'test_kid')
        self.assertEqual(jwk_key.kid, 'test_kid')

    def test_generate_jwt(self):
        public, private = init_keys()
        jwk_key, token = generate_jwt(public, private, False)
        self.assertEqual(jwk_key.kid, json.loads(token.header)['kid'])
        self.assertEqual(json.loads(token.claims)['sub'], 'example_user')

    def test_generate_rsa_key_different_inputs(self):
        public, private = init_keys()
        jwk_key = generate_rsa_key(public, 'different_kid')
        self.assertEqual(jwk_key.kid, 'different_kid')

    def test_expired_key_is_None(self):
        public, private = init_keys()
        jwk_key, token = generate_jwt(public, private, True)
        self.assertIsNone(jwk_key)

    def test_expired_key_is_expired(self):
        public, private = init_keys()
        jwk_key: jwk.JWK
        token: jwt.JWT
        jwk_key, token = generate_jwt(public, private, True)
        self.assertTrue(json.loads(token.claims)["exp"] < datetime.datetime.now().timestamp())

    def test_valid_key_is_not_expired(self):
        public, private = init_keys()
        jwk_key: jwk.JWK
        token: jwt.JWT
        jwk_key, token = generate_jwt(public, private, False)
        self.assertTrue(json.loads(token.claims)["exp"] > datetime.datetime.now().timestamp())

    def test_valid_key_is_not_None(self):
        public, private = init_keys()
        jwk_key, token = generate_jwt(public, private, False)
        self.assertIsNotNone(jwk_key)


if __name__ == '__main__':
    unittest.main()