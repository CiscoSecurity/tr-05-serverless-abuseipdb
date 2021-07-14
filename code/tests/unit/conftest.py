from datetime import datetime

import jwt
from pytest import fixture

from app import app
from tests.unit.mock_for_tests import PRIVATE_KEY


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='test_api_key',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            limit=100,
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_jwks_host=False,
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': limit
        }

        if wrong_jwks_host:
            payload.pop('jwks_host')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )
    return _make_jwt


@fixture(scope='session')
def valid_jwt_with_wrong_payload(client):
    payload = {
        'name': 'test',
        'jwks_host': 'visibility.amp.cisco.com',
        'aud': 'http://localhost'
    }
    return jwt.encode(
        payload, client.application.rsa_private_key, algorithm='RS256',
        headers={
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7'
        }
    )
