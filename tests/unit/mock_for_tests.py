EXPECTED_RESPONSE_DELIBERATE = {
    "data": {
        "verdicts": {
            "count": 1,
            "docs": [
                {
                    "disposition": 3,
                    "disposition_name": "Suspicious",
                    "observable": {
                        "type": "ip",
                        "value": "118.25.6.39"
                    },
                    "type": "verdict"
                }
            ]
        }
    }
}

EXPECTED_RESPONSE_AUTH_ERROR = {
    'errors': [
        {
            'code': 'permission_denied',
            'message': 'The request is missing a valid API key.',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_404_ERROR = {
    'errors': [
        {
            'code': 'not_found',
            'message': 'The Abuse IPDB not found.',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_500_ERROR = {
    'errors': [
        {
            'code': '3rd_party_api_internal_error',
            'message': 'The Abuse IPDB internal error.',
            'type': 'fatal'
        }
    ]
}
