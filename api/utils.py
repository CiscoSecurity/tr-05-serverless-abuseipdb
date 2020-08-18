from typing import Optional
from http import HTTPStatus
import json

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify, g
from requests.exceptions import SSLError
from bs4 import BeautifulSoup

from api.errors import (
    BadRequestError,
    AbuseInvalidCredentialsError,
    AbuseNotFoundError,
    AbuseInternalServerError,
    AbuseUnexpectedResponseError,
    AbuseTooManyRequestsError,
    AbuseServerDownError,
    AbuseUnavailableError,
    AbuseSSLError
)


def url_for(endpoint) -> Optional[str]:

    return current_app.config['ABUSE_IPDB_API_URL'].format(
        endpoint=endpoint,
    )


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


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
        HTTPStatus.UNAUTHORIZED: AbuseInvalidCredentialsError,
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
