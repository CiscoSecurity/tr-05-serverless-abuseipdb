from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    EXPECTED_RESPONSE_AUTH_ERROR
)


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='function')
def abuse_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def abuse_api_response(*, ok, status_error=None):
    mock_response = mock.MagicMock()

    mock_response.ok = ok

    if ok:
        payload = {
            "data": {
                "ipAddress": "118.25.6.39",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 30,
                "countryCode": "CN",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
                "domain": "tencent.com",
                "totalReports": 4,
                "numDistinctUsers": 4,
                "lastReportedAt": "2020-03-04T15:57:03+00:00"
            }
        }

    else:
        if status_error == 404:
            mock_response.status_code = 404
        elif status_error == 500:
            mock_response.status_code = 500
        else:
            mock_response.status_code = 401

    mock_response.json = lambda: payload

    return mock_response


def test_health_call_success(route, client, valid_jwt, abuse_api_request):
    abuse_api_request.return_value = abuse_api_response(ok=True)
    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK


def test_health_call_auth_error(route, client, valid_jwt, abuse_api_request):
    abuse_api_request.return_value = abuse_api_response(ok=False)
    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_AUTH_ERROR


def test_health_call_404(route, client, valid_jwt, abuse_api_request):
    abuse_api_request.return_value = abuse_api_response(ok=False, status_error=404)
    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


def test_health_call_500(route, client, valid_jwt, abuse_api_request):
    abuse_api_request.return_value = abuse_api_response(ok=False, status_error=500)
    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR
