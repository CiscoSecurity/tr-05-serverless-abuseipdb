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
