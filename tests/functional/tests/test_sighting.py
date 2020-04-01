from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_sighting_ip_observable(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sighting for observable from Abuse IPDB module

    ID: CCTRI-841-f58e47e4-f00e-423c-9a53-e3d03e337018

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sighting for
        observable from Abuse IPDB module

    Importance: Critical
    """
    payload = {'type': 'ip', 'value': '1.1.1.1'}
    response = enrich_observe_observables(
        payload=[payload],
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(response, 'Abuse IPDB')['data']['sightings']
    relations = {
        'origin': 'AbuseIPDB Enrichment Module',
        'origin_uri': 'https://www.abuseipdb.com/check/1.1.1.1',
        'relation': 'Resolved_To',
        'source': {'value': 'cloudflare.com', 'type': 'domain'},
        'related': payload
    }
    for sighting in sightings['docs']:
        assert sighting['type'] == 'sighting'
        assert sighting['schema_version']
        assert sighting['source'] == 'AbuseIPDB'
        assert sighting['source_uri'] == (
            'https://www.abuseipdb.com/check/1.1.1.1')
        assert sighting['confidence'] == 'Medium'
        assert sighting['title'] == 'Reported to AbuseIPDB'
        assert sighting['description']
        assert sighting['count'] == 4
        assert sighting['internal'] is False
        assert sighting['external_references'][0]['source_name'] == 'AbuseIPDB'
        assert sighting['external_references'][0]['url'] == (
            'https://www.abuseipdb.com/check/1.1.1.1')
        assert sighting['observed_time']['start_time']
        assert sighting['observables'][0] == payload
        assert sighting['relations'][0] == relations
