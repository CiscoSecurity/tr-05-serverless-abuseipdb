ABUSE_RESPONSE_MOCK = {
    "data": {
        "ipAddress": "180.126.219.126",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 21,
        "countryCode": "CN",
        "usageType": None,
        "isp": "ChinaNet Jiangsu Province Network",
        "domain": "chinatelecom.com.cn",
        "countryName": "China",
        "totalReports": 2,
        "numDistinctUsers": 2,
        "lastReportedAt": "2020-03-10T23:11:57+00:00",
        "reports": [
            {
                "reportedAt": "2020-03-10T23:11:57+00:00",
                "comment": "ssh",
                "categories": [
                    15,
                    21
                ],
                "reporterId": 38609,
                "reporterCountryCode": "US",
                "reporterCountryName": "United States of America"
            },
            {
                "reportedAt": "2020-02-26T14:34:59+00:00",
                "comment": "SSH login attempts with user root.",
                "categories": [
                    18,
                    20
                ],
                "reporterId": 39401,
                "reporterCountryCode": "UA",
                "reporterCountryName": "Ukraine"
            }
        ]
    }
}

EXPECTED_RESPONSE_DELIBERATE = {
    'data': {
        'verdicts': {
            'count': 1,
            'docs': [
                {
                    'disposition': 1,
                    'disposition_name': 'Clean',
                    'observable': {
                        'type': 'ip',
                        'value': '118.25.6.39'
                    },
                    'type': 'verdict'
                }
            ]
        }
    }
}


EXPECTED_RESPONSE_OBSERVE = {
    "data": {
        "judgements": {
            "count": 2,
            "docs": [
                {
                    "confidence": "Medium",
                    "disposition": 2,
                    "disposition_name": "Malicious",
                    "observable": {
                        "type": "ip",
                        "value": "118.25.6.39"
                    },
                    "priority": 85,
                    "schema_version": "1.0.16",
                    "severity": "Medium",
                    "source": "AbuseIPDB",
                    "source_uri":
                        "https://www.abuseipdb.com/check/118.25.6.39",
                    "type": "judgement",
                    "valid_time": {
                        "end_time": "2020-03-17T23:11:57.000000Z",
                        "start_time": "2020-03-10T23:11:57.000000Z"
                    }
                },
                {
                    "confidence": "Medium",
                    "disposition": 2,
                    "disposition_name": "Malicious",
                    "observable": {
                        "type": "ip",
                        "value": "118.25.6.39"
                    },
                    "priority": 85,
                    "schema_version": "1.0.16",
                    "severity": "Medium",
                    "source": "AbuseIPDB",
                    "source_uri":
                        "https://www.abuseipdb.com/check/118.25.6.39",
                    "type": "judgement",
                    "valid_time": {
                        "end_time": "2020-03-04T14:34:59.000000Z",
                        "start_time": "2020-02-26T14:34:59.000000Z"
                    }
                }
            ]
        },
        "verdicts": {
            "count": 1,
            "docs": [
                {
                    "disposition": 1,
                    "disposition_name": "Clean",
                    "observable": {
                        "type": "ip",
                        "value": "118.25.6.39"
                    },
                    "type": "verdict",
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
