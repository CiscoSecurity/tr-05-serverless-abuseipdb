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

ABUSE_CATEGORIES = {
    '15': {
        'title': 'title for id 15',
        'description': 'description for id 15'
    },
    '18': {
        'title': 'title for id 16',
        'description': 'description for id 16'
    },
    '20': {
        'title': 'title for id 20',
        'description': 'description for id 20'
    },
    '21': {
        'title': 'title for id 21',
        'description': 'description for id 21'
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
        'indicators': {
            'count': 4,
            'docs': [
                {
                    'confidence': 'Medium',
                    'description': 'description for id 15',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.16',
                    'short_description': 'description for id 15',
                    'title': 'title for id 15',
                    'type': 'indicator',
                    'valid_time': {},
                    'external_ids': ['15']
                },
                {
                    'confidence': 'Medium',
                    'description': 'description for id 21',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.16',
                    'short_description': 'description for id 21',
                    'title': 'title for id 21',
                    'type': 'indicator',
                    'valid_time': {},
                    'external_ids': ['21']
                },
                {
                    'confidence': 'Medium',
                    'description': 'description for id 16',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.16',
                    'short_description': 'description for id 16',
                    'title': 'title for id 16',
                    'type': 'indicator',
                    'valid_time': {},
                    'external_ids': ['18']
                },
                {
                    'confidence': 'Medium',
                    'description': 'description for id 20',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.16',
                    'short_description': 'description for id 20',
                    'title': 'title for id 20',
                    'type': 'indicator',
                    'valid_time': {},
                    'external_ids': ['20']
                }
            ]
        },
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
        'relationships': {
            'count': 4,
            'docs': [
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.16',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.16',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.16',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.16',
                    'type': 'relationship'
                }
            ]
        },
        'sightings': {
            'count': 2,
            'docs': [
                {
                    'confidence': 'Medium',
                    'count': 2,
                    'description': 'ssh',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url':
                                'https://www.abuseipdb.com/check/118.25.6.39'
                        }
                    ],
                    'internal': False,
                    'observables': [
                        {
                            'type': 'ip',
                            'value': '118.25.6.39'
                        }
                    ],
                    'observed_time': {
                        'start_time': '2020-03-10T23:11:57.000000Z'
                    },
                    'relations': [
                        {
                            'origin': 'AbuseIPDB Enrichment Module',
                            'origin_uri':
                                'https://www.abuseipdb.com/check/118.25.6.39',
                            'related': {
                                'type': 'ip',
                                'value': '118.25.6.39'
                            },
                            'relation': 'Resolved_To',
                            'source': {
                                'type': 'domain',
                                'value': 'chinatelecom.com.cn'
                            }
                        }
                    ],
                    'schema_version': '1.0.16',
                    'source': 'AbuseIPDB',
                    'source_uri':
                        'https://www.abuseipdb.com/check/118.25.6.39',
                    'title': 'Reported to AbuseIPDB',
                    'type': 'sighting'
                },
                {
                    'confidence': 'Medium',
                    'count': 2,
                    'description': 'SSH login attempts with user root.',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url':
                                'https://www.abuseipdb.com/check/118.25.6.39'
                        }
                    ],
                    'internal': False,
                    'observables': [
                        {
                            'type': 'ip',
                            'value': '118.25.6.39'
                        }
                    ],
                    'observed_time': {
                        'start_time': '2020-02-26T14:34:59.000000Z'
                    },
                    'relations': [
                        {
                            'origin': 'AbuseIPDB Enrichment Module',
                            'origin_uri':
                                'https://www.abuseipdb.com/check/118.25.6.39',
                            'related': {
                                'type': 'ip',
                                'value': '118.25.6.39'
                            },
                            'relation': 'Resolved_To',
                            'source': {
                                'type': 'domain',
                                'value': 'chinatelecom.com.cn'
                            }
                        }
                    ],
                    'schema_version': '1.0.16',
                    'source': 'AbuseIPDB',
                    'source_uri':
                        'https://www.abuseipdb.com/check/118.25.6.39',
                    'title': 'Reported to AbuseIPDB',
                    'type': 'sighting'
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
            'code': 'permission denied',
            'message': 'The request is missing a valid API key.',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_404_ERROR = {
    'errors': [
        {
            'code': 'not found',
            'message': 'The Abuse IPDB not found.',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_500_ERROR = {
    'errors': [
        {
            'code': 'internal error',
            'message': 'The Abuse IPDB internal error.',
            'type': 'fatal'
        }
    ]
}
