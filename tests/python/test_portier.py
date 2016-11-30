from base64 import b64encode
import binascii
from uuid import uuid4
from unittest.mock import Mock, patch

from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey

from tornado.escape import json_encode
from tornado.testing import gen_test

from tests.python.util import Test, HTTPTest, CoroMock

from minigrid.error import LoginError
from minigrid import portier


class TestUtil(Test):
    def test_b64dec_incorrect_padding(self):
        self.assertRaises(binascii.Error, portier.b64dec, 'a')

    def test_b64dec_success(self):
        result = portier.b64dec('aaaa')
        self.assertEqual(result, b'i\xa6\x9a')

    def test_jwk_to_rsa(self):
        result = portier.jwk_to_rsa({
            'e': b64encode('3'.encode()).decode(),
            'n': b64encode('4'.encode()).decode(),
        })
        self.assertIsInstance(result, _RSAPublicKey)


class TestGetVerifiedEmail(HTTPTest):
    @patch('minigrid.portier.discover_keys', new_callable=CoroMock)
    @patch('minigrid.portier.jwt.decode')
    @gen_test
    async def test_get_verified_email_success(self, jwt_decode, discover_keys):
        discover_keys.coro.return_value = {'a': 'key'}
        nonce = uuid4().hex
        portier.redis_kv.setex(nonce, 1, '')
        jwt_decode.return_value = {
            'sub': 'a@a.com',
            'nonce': nonce,
        }
        token = b64encode(json_encode({
            'kid': 'a',
        }).encode())
        result = await portier.get_verified_email(token.decode())
        self.assertEqual(result, 'a@a.com')

    @patch('minigrid.portier.discover_keys', new_callable=CoroMock)
    @gen_test
    async def test_get_verified_email_missing_key(self, discover_keys):
        discover_keys.coro.return_value = {'a': 'key'}
        token = b64encode(json_encode({
            'kid': 'b',
        }).encode())
        with self.assertRaises(LoginError) as missing_key:
            await portier.get_verified_email(token.decode())
        self.assertEqual(
            missing_key.exception.reason, 'Cannot find public key with ID b')

    @patch('minigrid.portier.discover_keys', new_callable=CoroMock)
    @gen_test
    async def test_get_verified_invalid_jwt(self, discover_keys):
        discover_keys.coro.return_value = {'a': 'key'}
        token = b64encode(json_encode({
            'kid': 'a',
        }).encode())
        with self.assertRaises(LoginError) as invalid_jwt:
            await portier.get_verified_email(token.decode())
        self.assertEqual(
            invalid_jwt.exception.reason, 'Invalid JWT: Not enough segments')

    @patch('minigrid.portier.discover_keys', new_callable=CoroMock)
    @patch('minigrid.portier.jwt.decode')
    @gen_test
    async def test_get_verified_email_invalid_email(
            self, jwt_decode, discover_keys):
        discover_keys.coro.return_value = {'a': 'key'}
        nonce = uuid4().hex
        portier.redis_kv.setex(nonce, 1, '')
        jwt_decode.return_value = {
            'sub': 'a#a.com',
            'nonce': nonce,
        }
        token = b64encode(json_encode({
            'kid': 'a',
        }).encode())
        with self.assertRaises(LoginError) as invalid_email:
            await portier.get_verified_email(token.decode())
        self.assertEqual(
            invalid_email.exception.reason, 'Invalid e-mail address: a#a.com')

    @patch('minigrid.portier.discover_keys', new_callable=CoroMock)
    @patch('minigrid.portier.jwt.decode')
    @gen_test
    async def test_get_verified_email_invalid_nonce(
            self, jwt_decode, discover_keys):
        discover_keys.coro.return_value = {'a': 'key'}
        jwt_decode.return_value = {
            'sub': 'a@a.com',
            'nonce': 'invalid nonce',
        }
        token = b64encode(json_encode({
            'kid': 'a',
        }).encode())
        with self.assertRaises(LoginError) as invalid_nonce:
            await portier.get_verified_email(token.decode())
        self.assertEqual(
            invalid_nonce.exception.reason,
            'Invalid, expired, or re-used nonce'
        )


class TestDiscoverKeys(HTTPTest):
    @patch('minigrid.portier.AsyncHTTPClient.fetch', new_callable=CoroMock)
    @gen_test
    async def test_discover_keys_no_cache_hit_success(self, fetch):
        response = Mock()
        rsa_numbers = {
            'e': b64encode('3'.encode()).decode(),
            'n': b64encode('4'.encode()).decode(),
        }
        response.body = json_encode({'jwks_uri': 'a', 'keys': [
            {
                'alg': 'RS256',
                'kid': 'included',
                **rsa_numbers,
            },
            {'alg': 'notRS256', 'kid': 'excluded'},
        ]})
        fetch.coro.return_value = response
        result = await portier.discover_keys('a')
        self.assertListEqual(list(result.keys()), ['included'])
        self.assertIsInstance(result['included'], _RSAPublicKey)

    @gen_test
    async def test_discover_keys_cache_hit_success(self):
        rsa_numbers = {
            'e': b64encode('3'.encode()).decode(),
            'n': b64encode('4'.encode()).decode(),
        }
        raw_jwks = json_encode({'jwks_uri': 'a', 'keys': [
            {
                'alg': 'RS256',
                'kid': 'included',
                **rsa_numbers,
            },
            {'alg': 'notRS256', 'kid': 'excluded'},
        ]})
        portier.redis_kv.setex('jwks:a', 1, raw_jwks)
        result = await portier.discover_keys('a')
        self.assertListEqual(list(result.keys()), ['included'])
        self.assertIsInstance(result['included'], _RSAPublicKey)

    @patch('minigrid.portier.AsyncHTTPClient.fetch', new_callable=CoroMock)
    @gen_test
    async def test_discover_keys_missing_jwks_uri(self, fetch):
        response = Mock()
        rsa_numbers = {
            'e': b64encode('3'.encode()).decode(),
            'n': b64encode('4'.encode()).decode(),
        }
        response.body = json_encode({'not_jwks_uri': 'a', 'keys': [
            {
                'alg': 'RS256',
                'kid': 'included',
                **rsa_numbers,
            },
            {'alg': 'notRS256', 'kid': 'excluded'},
        ]})
        fetch.coro.return_value = response
        with self.assertRaises(LoginError) as jwks_uri_missing:
            await portier.discover_keys('a')
        self.assertEqual(
            jwks_uri_missing.exception.reason,
            'No jwks_uri in discovery document'
        )

    @patch('minigrid.portier.AsyncHTTPClient.fetch', new_callable=CoroMock)
    @gen_test
    async def test_discover_keys_missing_keys(self, fetch):
        response = Mock()
        rsa_numbers = {
            'e': b64encode('3'.encode()).decode(),
            'n': b64encode('4'.encode()).decode(),
        }
        response.body = json_encode({'jwks_uri': 'a', 'not_keys': [
            {
                'alg': 'RS256',
                'kid': 'included',
                **rsa_numbers,
            },
            {'alg': 'notRS256', 'kid': 'excluded'},
        ]})
        fetch.coro.return_value = response
        with self.assertRaises(LoginError) as jwks_uri_missing:
            await portier.discover_keys('a')
        self.assertEqual(
            jwks_uri_missing.exception.reason,
            'No keys found in JWK Set'
        )
