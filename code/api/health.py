import requests
from flask import Blueprint, current_app

from api.utils import (
    jsonify_data,
    url_for,
    get_jwt,
    get_response_data,
    catch_ssl_errors,
    catch_auth_errors,
)

health_api = Blueprint('health', __name__)


@catch_ssl_errors
@catch_auth_errors
def check_health_abuse_ipdb_api():
    url = url_for('check')

    headers = {
        'Accept': 'application/json',
        'Key': get_jwt()
    }

    params = {
        'ipAddress': current_app.config.get('ABUSE_IPDB_HEALTH_CHECK_IP')
    }

    response = requests.get(url, headers=headers, params=params)

    return get_response_data(response)


@health_api.route('/health', methods=['POST'])
def health():
    check_health_abuse_ipdb_api()
    return jsonify_data({'status': 'ok'})
