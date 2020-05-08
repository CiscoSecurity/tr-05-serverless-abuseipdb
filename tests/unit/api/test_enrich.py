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
    EXPECTED_RESPONSE_OBSERVE,
    ABUSE_CATEGORIES,
    EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1,
    ABUSE_429_RESPONSE,
    EXPECTED_RESPONSE_429_ERROR
)


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='function')
def abuse_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def abuse_api_response(*, ok, status_error=None, payload=None):
    mock_response = mock.MagicMock()

    if payload:
        payload = payload

    mock_response.ok = ok

    if ok:
        if not payload:
            payload = ABUSE_RESPONSE_MOCK

    else:
        mock_response.status_code = status_error
        mock_response.text = str(payload)

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
                'code': 'invalid argument',
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


@mock.patch('api.enrich.get_categories_objects')
def test_enrich_call_success(categories_mock, route, client, valid_jwt,
                             valid_json, abuse_api_request, expected_payload):

    categories_mock.return_value = ABUSE_CATEGORIES
    abuse_api_request.return_value = abuse_api_response(ok=True)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()

    assert data['data']['verdicts']['docs'][0].pop('valid_time')

    if route == '/observe/observables':

        judgements = data['data']['judgements']
        assert judgements['count'] == 2
        assert judgements['docs'][0].pop('id')
        assert judgements['docs'][1].pop('id')

        sightings = data['data']['sightings']
        assert sightings['count'] == 2
        sighting_id_1 = sightings['docs'][0].pop('id')
        sighting_id_2 = sightings['docs'][1].pop('id')

        indicators = data['data']['indicators']
        assert indicators['count'] == 4
        indicator_id_1 = indicators['docs'][0].pop('id')
        indicator_id_2 = indicators['docs'][1].pop('id')
        indicator_id_3 = indicators['docs'][2].pop('id')
        indicator_id_4 = indicators['docs'][3].pop('id')

        relationships = data['data']['relationships']
        assert relationships['count'] == 4
        assert relationships['docs'][0].pop('id')
        assert relationships['docs'][1].pop('id')
        assert relationships['docs'][2].pop('id')
        assert relationships['docs'][3].pop('id')
        assert relationships['docs'][0].pop('source_ref') == sighting_id_1
        assert relationships['docs'][1].pop('source_ref') == sighting_id_1
        assert relationships['docs'][2].pop('source_ref') == sighting_id_2
        assert relationships['docs'][3].pop('source_ref') == sighting_id_2
        assert relationships['docs'][0].pop('target_ref') == indicator_id_1
        assert relationships['docs'][1].pop('target_ref') == indicator_id_2
        assert relationships['docs'][2].pop('target_ref') == indicator_id_3
        assert relationships['docs'][3].pop('target_ref') == indicator_id_4

    assert data == expected_payload


@mock.patch('api.enrich.get_categories_objects')
def test_enrich_call_success_limit_1(categories_mock, route, client, valid_jwt,
                                     valid_json, abuse_api_request):

    categories_mock.return_value = ABUSE_CATEGORIES
    abuse_api_request.return_value = abuse_api_response(ok=True)

    if route == '/observe/observables':
        client.application.config['CTR_ENTITIES_LIMIT'] = 1

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK

        data = response.get_json()

        assert data['data']['verdicts']['docs'][0].pop('valid_time')

        judgements = data['data']['judgements']
        assert judgements['count'] == 1
        assert judgements['docs'][0].pop('id')

        sightings = data['data']['sightings']
        assert sightings['count'] == 1
        sighting_id_1 = sightings['docs'][0].pop('id')

        indicators = data['data']['indicators']
        assert indicators['count'] == 2
        indicator_id_1 = indicators['docs'][0].pop('id')
        indicator_id_2 = indicators['docs'][1].pop('id')

        relationships = data['data']['relationships']
        assert relationships['count'] == 2
        assert relationships['docs'][0].pop('id')
        assert relationships['docs'][1].pop('id')
        assert relationships['docs'][0].pop('source_ref') == sighting_id_1
        assert relationships['docs'][1].pop('source_ref') == sighting_id_1
        assert relationships['docs'][0].pop('target_ref') == indicator_id_1
        assert relationships['docs'][1].pop('target_ref') == indicator_id_2

        assert data == EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1


def test_enrich_call_auth_error(route, client, valid_jwt, valid_json,
                                abuse_api_request):

    abuse_api_request.return_value = abuse_api_response(
        ok=False, status_error=HTTPStatus.UNAUTHORIZED)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_AUTH_ERROR


def test_enrich_call_404_error(route, client, valid_jwt, valid_json,
                               abuse_api_request):

    abuse_api_request.return_value = abuse_api_response(
        ok=False, status_error=HTTPStatus.NOT_FOUND)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_404_ERROR


def test_enrich_call_500_error(route, client, valid_jwt, valid_json,
                               abuse_api_request):

    abuse_api_request.return_value = abuse_api_response(
        ok=False, status_error=HTTPStatus.INTERNAL_SERVER_ERROR)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_500_ERROR


def test_enrich_call_422_error(route, client, valid_jwt, valid_json,
                               abuse_api_request):

    abuse_api_request.return_value = abuse_api_response(
        ok=False, status_error=HTTPStatus.UNPROCESSABLE_ENTITY)

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == {'data': {}}


def test_enrich_call_429_error(route, client, valid_jwt, valid_json,
                               abuse_api_request):

    abuse_api_request.return_value = abuse_api_response(
        ok=False,
        status_error=HTTPStatus.TOO_MANY_REQUESTS,
        payload=ABUSE_429_RESPONSE
    )

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_429_ERROR
