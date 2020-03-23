from typing import Optional
import json

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify

from api.errors import (
    BadRequestError,
    AbuseInvalidCredentialsError,
    AbuseNotFoundError,
    AbuseInternalServerError,
    AbuseUnexpectedResponseError
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
        return response.json()

    else:
        if response.status_code == 401:
            raise AbuseInvalidCredentialsError()

        if response.status_code == 404:
            raise AbuseNotFoundError()

        if response.status_code == 500:
            raise AbuseInternalServerError()

        else:
            raise AbuseUnexpectedResponseError(response)
