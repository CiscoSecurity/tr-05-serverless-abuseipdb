import json
from typing import Optional
from http import HTTPStatus

import jwt
import requests
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError
from flask import request, current_app, jsonify, g
from requests.exceptions import SSLError, ConnectionError, InvalidURL
from bs4 import BeautifulSoup

from api.errors import (
    BadRequestError,
    AbuseNotFoundError,
    AbuseInternalServerError,
    AbuseUnexpectedResponseError,
    AbuseTooManyRequestsError,
    AbuseServerDownError,
    AbuseUnavailableError,
    AbuseSSLError,
    AuthorizationError
)


def url_for(endpoint) -> Optional[str]:
    return current_app.config['ABUSE_IPDB_API_URL'].format(
        endpoint=endpoint,
    )


def set_ctr_entities_limit(payload):
    try:
        ctr_entities_limit = int(payload['CTR_ENTITIES_LIMIT'])
        assert ctr_entities_limit > 0
    except (KeyError, ValueError, AssertionError):
        ctr_entities_limit = current_app.config['CTR_DEFAULT_ENTITIES_LIMIT']
    current_app.config['CTR_ENTITIES_LIMIT'] = ctr_entities_limit


def get_auth_token():
    """
    Parse the incoming request's Authorization header and Validate it.
    """

    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_pub_key(jwks_host, token):
    expected_errors = {
        ConnectionError: 'Wrong jwks_host in JWT payload. '
                         'Make sure domain follows the '
                         'visibility.<region>.cisco.com structure',
        InvalidURL: 'Wrong jwks_host in JWT payload. '
                    'Make sure domain follows the '
                    'visibility.<region>.cisco.com structure',
    }
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_jwt():
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint
    """
    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        AssertionError: 'jwk_host is missing in JWT payload. Make sure '
                        'custom_jwks_host field is present in module_type',
        InvalidSignatureError: 'Failed to decode JWT with provided key. '
                               'Make suer domain in custom_jwks_host '
                               'corresponds to your SekureX instance region.',
        DecodeError: 'Wrong JWT structure',
        InvalidAudienceError: 'Wrong configuration-token-audience',
        TypeError: 'kid from JWT header not found in API response'
    }

    token = get_auth_token()
    try:
        jwks_host = jwt.decode(
            token, options={'verify_signature': False}).get('jwks_host')
        assert jwks_host
        key = get_pub_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        set_ctr_entities_limit(payload)
        return payload['key']
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data) or None
    if error:
        raise BadRequestError(
            f'Invalid JSON payload received. {json.dumps(error)}.'
        )

    return data


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    data = {
        'errors': [error],
        'data': {}
    }

    if g.get('sightings'):
        data['data'].update({'sightings': format_docs(g.sightings)})

    if g.get('indicators'):
        data['data'].update({'indicators': format_docs(g.indicators)})

    if g.get('verdicts'):
        data['data'].update({'verdicts': format_docs(g.verdicts)})

    if g.get('judgements'):
        data['data'].update({'judgements': format_docs(g.judgements)})

    if g.get('relationships'):
        data['data'].update({'relationships': format_docs(g.relationships)})

    if not data['data']:
        data.pop('data')

    return jsonify(data)


def get_response_data(response):

    expected_response_errors = {
        HTTPStatus.NOT_FOUND: AbuseNotFoundError,
        HTTPStatus.INTERNAL_SERVER_ERROR: AbuseInternalServerError,
        HTTPStatus.BAD_GATEWAY: AbuseUnavailableError,
        HTTPStatus.SERVICE_UNAVAILABLE: AbuseUnavailableError,
        HTTPStatus.GATEWAY_TIMEOUT: AbuseUnavailableError,
        521: AbuseServerDownError
    }

    if response.ok:
        return response.text if 'DOCTYPE html' in response.text \
            else response.json()

    else:
        if response.status_code in expected_response_errors:
            raise expected_response_errors[response.status_code]

        if response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY:
            return {}

        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise AbuseTooManyRequestsError(response)

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            raise AuthorizationError(
                message=response.json()['errors'][0]['detail']
            )

        else:
            raise AbuseUnexpectedResponseError(response)


def get_categories_objects(categories_output):
    """
    Return categories id, title and description from a table from response HTML
    document as the dict object:
    {
    'category_id': {
            'title': 'some_title',
            'description': 'some_description'
        }
    }
    """
    categories = {}

    document = BeautifulSoup(categories_output, 'html.parser')
    table = document.find_all('table')[0]

    for row in table.find_all('tr'):
        columns = row.find_all('td')
        if columns:
            categories[columns[0].get_text().strip()] = {
                'title': columns[1].get_text().strip(),
                'description': columns[2].get_text().strip()
            }
    return categories


def catch_ssl_errors(func):
    def wraps(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise AbuseSSLError(error)
    return wraps
