from datetime import datetime

from authlib.jose import jwt
from pytest import fixture

from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'key': 'test_api_key'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def valid_jwt_with_wrong_payload(client):
    header = {'alg': 'HS256'}

    payload = {'name': 'test'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')
