from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_post_health
from tests.functional.tests.constants import MODULE_NAME


def test_positive_smoke_enrich_health(module_headers):
    """Perform testing for enrich health endpoint to check status of Abuse IPDB
    module

    ID: CCTRI-811-bc1b575c-495e-49f4-a5db-2867941c3303

    Steps:
        1. Send request to enrich health endpoint

    Expectedresults:
        1. Check that data in response body contains status Ok from Abuse IPDB
            module

    Importance: Critical
    """
    response_from_all_modules = enrich_post_health(
        **{'headers': module_headers}
    )
    response_from_abuse_ipdb = get_observables(response_from_all_modules,
                                               MODULE_NAME)
    assert response_from_abuse_ipdb['data'] == {'status': 'ok'}
