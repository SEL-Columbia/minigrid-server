"""Utility functions for portier login."""
from base64 import urlsafe_b64decode
from datetime import timedelta
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import jwt

import redis

from tornado.escape import json_decode
from tornado.httpclient import AsyncHTTPClient

import minigrid.error
from minigrid.options import options


redis_kv = redis.StrictRedis.from_url(options.redis_url)


def b64dec(string):
    padding = '=' * ((4 - len(string) % 4) % 4)
    return urlsafe_b64decode(string + padding)


async def get_verified_email(token):
    keys = await discover_keys('https://broker.portier.io')
    raw_header, _, _ = token.partition('.')
    header = json_decode(b64dec(raw_header))
    try:
        pub_key = keys[header['kid']]
    except KeyError:
        raise minigrid.error.LoginError(
            reason='Cannot find public key with ID {}'.format(header['kid']))
    try:
        payload = jwt.decode(
            token, pub_key,
            algorithms=['RS256'],
            audience=options.minigrid_website_url,
            issuer='https://broker.portier.io',
            leeway=3*60,
        )
    except Exception as exc:
        raise minigrid.error.LoginError(reason='Invalid JWT: {}'.format(exc))
    if not re.match('.+@.+', payload['sub']):
        raise minigrid.error.LoginError(
            reason='Invalid e-mail address: {}'.format(payload['sub']))
    if not redis_kv.delete(payload['nonce']):
        raise minigrid.error.LoginError(
            reason='Invalid, expired, or re-used nonce')
    return payload['sub']


def jwk_to_rsa(key):
    e = int.from_bytes(b64dec(key['e']), 'big')
    n = int.from_bytes(b64dec(key['n']), 'big')
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


async def discover_keys(broker):
    cache_key = 'jwks:' + broker
    raw_jwks = redis_kv.get(cache_key)
    if not raw_jwks:
        http_client = AsyncHTTPClient()
        url = broker + '/.well-known/openid-configuration'
        response = await http_client.fetch(url)
        discovery = json_decode(response.body)
        if 'jwks_uri' not in discovery:
            raise minigrid.error.LoginError(
                reason='No jwks_uri in discovery document')
        raw_jwks = (await http_client.fetch(discovery['jwks_uri'])).body
        redis_kv.setex(cache_key, timedelta(minutes=5), raw_jwks)
    jwks = json_decode(raw_jwks)
    if 'keys' not in jwks:
        raise minigrid.error.LoginError(reason='No keys found in JWK Set')
    return {
        key['kid']: jwk_to_rsa(key)
        for key in jwks['keys']
        if key['alg'] == 'RS256'
    }
