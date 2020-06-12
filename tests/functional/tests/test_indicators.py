from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_indicators_ip_observable(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable from Abuse IPDB module

    ID: CCTRI-840-10da94e0-4b1b-4fa2-bd4f-3e9885426918

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
        observable from Abuse IPDB module

    Importance: Critical
    """
    payload = {'type': 'ip', 'value': '1.1.1.1'}
    response_from_all_modules = enrich_observe_observables(
        payload=[payload],
        **{'headers': module_headers}
    )['data']
    response_from_abuse_module = get_observables(
        response_from_all_modules, 'Abuse IPDB')
    assert response_from_abuse_module['module'] == 'Abuse IPDB'
    assert response_from_abuse_module['module_instance_id']
    assert response_from_abuse_module['module_type_id']

    indicators = response_from_abuse_module['data']['indicators']
    assert len(indicators['docs']) > 0
    for indicator in indicators['docs']:
        assert indicator['type'] == 'indicator'
        assert indicator['id']
        assert indicator['schema_version']
        assert indicator['producer'] == 'AbuseIPDB'
        assert indicator['valid_time'] == {}
        assert indicator['confidence'] == 'Medium'
        assert indicator['title']
        assert indicator['description']
        assert indicator['external_ids']
        assert indicator['external_references'] == [{
            'source_name': 'AbuseIPDB',
            'description': 'AbuseIPDB attack categories',
            'url': 'https://www.abuseipdb.com/categories',
            'external_id': indicator["external_ids"][0]
        }]

    assert indicators['count'] == len(indicators['docs'])
