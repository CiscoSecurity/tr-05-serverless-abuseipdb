from typing import Optional
from http import HTTPStatus
import json

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from bs4 import BeautifulSoup

from api.errors import (
    BadRequestError,
    AbuseInvalidCredentialsError,
    AbuseNotFoundError,
    AbuseInternalServerError,
    AbuseUnexpectedResponseError,
    AbuseTooManyRequestsError
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


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    return jsonify({'errors': [error]})


def get_response_data(response):

    if response.ok:
        return response.text if 'DOCTYPE html' in response.text \
            else response.json()

    else:
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            raise AbuseInvalidCredentialsError()

        if response.status_code == HTTPStatus.NOT_FOUND:
            raise AbuseNotFoundError()

        if response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY:
            return {}

        if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            raise AbuseInternalServerError()

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
