from typing import Optional
import json

from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify


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
        data = None
        # Mimic the Abuse IPDB API error response payload.
        error = {
            'status': 'INVALID_ARGUMENT',
            'message': f'Invalid JSON payload received. {json.dumps(error)}.'
        }

    return data, error


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(errors):

    for error in errors:
        error['code'] = error.pop('status', 'internal_error').lower()
        if not error.get('message'):
            error['message'] = error.pop('detail', 'unexpected error')

        error.pop('details', None)

        error['type'] = 'fatal'

    return jsonify({'errors': errors})


def get_response_data(response):

    if response.ok:
        return response.json(), None

    else:
        if response.status_code == 401:
            error = {
                'message': 'The request is missing a valid API key.',
                'status': 'PERMISSION_DENIED',
            }
            return None, [error]
        if response.status_code == 404:
            error = {
                'message': 'The Abuse IPDB not found.',
                'status': 'NOT_FOUND',
            }
            return None, [error]
        if response.status_code == 500:
            error = {
                'message': 'The Abuse IPDB internal error.',
                'status': '3RD_PARTY_API_INTERNAL_ERROR',
            }
            return None, [error]
        else:
            return None, response.json()['errors']
