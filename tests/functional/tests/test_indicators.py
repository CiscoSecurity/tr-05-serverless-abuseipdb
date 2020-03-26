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
    response = enrich_observe_observables(
        payload=[payload],
        **{'headers': module_headers}
    )['data']
    indicators = get_observables(response, 'Abuse IPDB')['data']['indicators']
    assert indicators['count'] == 10
    for indicator in indicators['docs']:
        assert indicator['type'] == 'indicator'
        assert indicator['schema_version']
        assert indicator['producer'] == 'AbuseIPDB'
        assert indicator['valid_time'] == {}
        assert indicator['confidence'] == 'Medium'
        assert indicator['title']
        assert indicator['description']
        assert indicator['external_ids']
        assert indicator['external_references'] == [{
            'source_name': 'AbuseIPDB',
            'url': 'https://www.abuseipdb.com/categories'
        }]
