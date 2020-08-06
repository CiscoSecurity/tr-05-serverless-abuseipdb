from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    ABUSE_IPDB_URL,
    CTR_ENTITIES_LIMIT,
    MODULE_NAME, SOURCE
)


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
    observables = [{'type': 'ip', 'value': '1.1.1.1'}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_abuse = get_observables(response_from_all_modules,
                                          MODULE_NAME)

    assert response_from_abuse['module'] == MODULE_NAME
    assert response_from_abuse['module_instance_id']
    assert response_from_abuse['module_type_id']

    sightings = response_from_abuse['data']['sightings']

    relations = {
        'origin': f'{SOURCE} Enrichment Module',
        'origin_uri': f'{ABUSE_IPDB_URL}/check/{observables[0]["value"]}',
        'relation': 'Resolved_To',
        'source': {'value': 'cloudflare.com', 'type': 'domain'},
        'related': observables[0]
    }

    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert sighting['type'] == 'sighting'
        assert sighting['id'].startswith('transient:sighting-')
        assert sighting['schema_version']
        assert sighting['source'] == SOURCE
        assert sighting['source_uri'] == (
            f'{ABUSE_IPDB_URL}/check/{observables[0]["value"]}')
        assert sighting['confidence'] == 'Medium'
        assert sighting['title'] == f'Reported to {SOURCE}'
        assert 'description' in sighting
        assert sighting['count'] == 1
        assert sighting['internal'] is False
        assert sighting['external_references'][0]['source_name'] == SOURCE
        assert sighting['external_references'][0]['url'] == (
            f'{ABUSE_IPDB_URL}/check/{observables[0]["value"]}')
        assert sighting['observed_time']['start_time'] == (
            sighting['observed_time']['end_time']
        )
        assert sighting['observables'] == observables
        assert sighting['relations'][0] == relations

    assert sightings['count'] == len(sightings['docs']) <= CTR_ENTITIES_LIMIT
