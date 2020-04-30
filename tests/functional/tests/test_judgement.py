from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_judgement_ip_observable(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    judgement for observable from Abuse IPDB module

    ID: CCTRI-811-4917ba85-fa06-4f9f-b213-2f3a40861766

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected verdict for
            observable from Abuse IPDB module

    Importance: Critical
    """
    payload = {'type': 'ip', 'value': '192.168.1.1'}
    response = enrich_observe_observables(
        payload=[payload],
        **{'headers': module_headers}
    )['data']
    judgements = get_observables(response, 'Abuse IPDB')['data']['judgements']
    assert judgements['count'] == 26
    for judgement in judgements['docs']:
        assert judgement['type'] == 'judgement'
        assert judgement['id']
        assert judgement['disposition'] == 2
        assert judgement['disposition_name'] == 'Malicious'
        assert judgement['source'] == 'AbuseIPDB'
        assert judgement['severity'] == 'Medium'
        assert judgement['confidence'] == 'Medium'
        assert judgement['priority'] == 85
