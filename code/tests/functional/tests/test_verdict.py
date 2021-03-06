from pytest import mark
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_deliberate_observables
from tests.functional.tests.constants import MODULE_NAME


@mark.skip(reason='Deprecated')
def test_positive_clean_verdict_ip_observable(module_headers):
    """Perform testing for enrich deliberate observables endpoint to get
    verdict for observable with clean disposition from Abuse IPDB module

    ID: CCTRI-811-eb6d1371-5d0c-42df-8437-8863f3bac4d0

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected verdict for
            observable from Abuse IPDB module

    Importance: Critical
    """
    observables = [{'type': 'ip', 'value': '118.232.96.6'}]
    response_from_all_modules = enrich_deliberate_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_abuse = get_observables(response_from_all_modules,
                                          MODULE_NAME)

    assert response_from_abuse['module'] == MODULE_NAME
    assert response_from_abuse['module_instance_id']
    assert response_from_abuse['module_type_id']

    verdicts = response_from_abuse['data']['verdicts']
    assert verdicts['count'] == 1
    assert verdicts['docs'][0]['type'] == 'verdict'
    assert verdicts['docs'][0]['disposition'] == 1
    assert verdicts['docs'][0]['disposition_name'] == 'Clean'
    assert verdicts['docs'][0]['observable'] == observables[0]
    assert verdicts['docs'][0]['valid_time']['start_time']


def test_positive_suspicious_verdict_ip_observable(module_headers):
    """Perform testing for enrich deliberate observables endpoint to get
    verdict for observable with suspicious disposition from Abuse IPDB module

    ID: CCTRI-811-93e7fe20-bf8f-42ce-9966-17961ce5dfa8

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected verdict for
            observable from Abuse IPDB module

    Importance: Critical
    """
    observables = [{'type': 'ip', 'value': '118.232.96.6'}]
    response_from_all_modules = enrich_deliberate_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_abuse = get_observables(response_from_all_modules,
                                          MODULE_NAME)

    assert response_from_abuse['module'] == MODULE_NAME
    assert response_from_abuse['module_instance_id']
    assert response_from_abuse['module_type_id']

    verdicts = response_from_abuse['data']['verdicts']
    assert verdicts['count'] == 1
    assert verdicts['docs'][0]['type'] == 'verdict'
    assert verdicts['docs'][0]['disposition'] == 3
    assert verdicts['docs'][0]['disposition_name'] == 'Suspicious'
    assert verdicts['docs'][0]['observable'] == observables[0]
    assert verdicts['docs'][0]['valid_time']['start_time']


@mark.skip(reason='Deprecated')
def test_positive_unknown_verdict_ip_observable(module_headers):
    """Perform testing for enrich deliberate observables endpoint to get
    verdict for observable with unknown disposition from Abuse IPDB module

    ID: CCTRI-811-e0b57f1d-bfca-4d4c-a163-02fdcebe9131

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected verdict for
            observable from Abuse IPDB module

    Importance: Critical
    """
    observables = [{'type': 'ip', 'value': '1.1.1.1'}]
    response_from_all_modules = enrich_deliberate_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_abuse = get_observables(response_from_all_modules,
                                          MODULE_NAME)

    assert response_from_abuse['module'] == MODULE_NAME
    assert response_from_abuse['module_instance_id']
    assert response_from_abuse['module_type_id']

    verdicts = response_from_abuse['data']['verdicts']
    assert verdicts['count'] == 1
    assert verdicts['docs'][0]['type'] == 'verdict'
    assert verdicts['docs'][0]['disposition'] == 5
    assert verdicts['docs'][0]['disposition_name'] == 'Unknown'
    assert verdicts['docs'][0]['observable'] == observables[0]
    assert verdicts['docs'][0]['valid_time']['start_time']
