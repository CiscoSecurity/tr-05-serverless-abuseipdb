from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_DELIBERATE,
    EXPECTED_RESPONSE_AUTH_ERROR,
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    ABUSE_RESPONSE_MOCK,
    EXPECTED_RESPONSE_OBSERVE
)


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='function')
def gsb_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def gsb_api_response(*, ok, status_error=None):
    mock_response = mock.MagicMock()

    mock_response.ok = ok

    if ok:
        payload = ABUSE_RESPONSE_MOCK

    else:

        if status_error == 404:
            mock_response.status_code = 404

        elif status_error == 500:
            mock_response.status_code = 500

        else:
            mock_response.status_code = 401

    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': 'https://google.com'}]


def test_enrich_call_with_invalid_json_failure(route, client, valid_jwt,
                                               invalid_json):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json
                           )

    expected_payload = {
        'errors': [
            {
                'code': 'invalid_argument',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '118.25.6.39'}]


@fixture(scope='module')
def expected_payload(route, client):

    payload = None

    if route.startswith('/deliberate'):

        payload = EXPECTED_RESPONSE_DELIBERATE

    if route.startswith('/observe'):

        payload = EXPECTED_RESPONSE_OBSERVE

    return payload


def test_enrich_call_success(route, client, valid_jwt, valid_json,
                             gsb_api_request, expected_payload):

    gsb_api_request.return_value = gsb_api_response(ok=True)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data['data']['verdicts']['docs'][0].pop('valid_time')
    if data['data'].get('judgements'):
        assert data['data']['judgements']['docs'][0].pop('id')
        assert data['data']['judgements']['docs'][1].pop('id')
    assert data == expected_payload


def test_enrich_call_auth_error(route, client, valid_jwt, valid_json,
                                gsb_api_request):

    gsb_api_request.return_value = gsb_api_response(ok=False)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_AUTH_ERROR


def test_enrich_call_404_error(route, client, valid_jwt, valid_json,
                               gsb_api_request):

    gsb_api_request.return_value = gsb_api_response(ok=False, status_error=404)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_404_ERROR


def test_enrich_call_500_error(route, client, valid_jwt, valid_json,
                               gsb_api_request):

    gsb_api_request.return_value = gsb_api_response(ok=False, status_error=500)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_500_ERROR
