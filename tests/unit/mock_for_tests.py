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
        'title': 'title for id 18',
        'description': 'description for id 18'
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

ABUSE_429_RESPONSE = {
    "errors": [
        {
            "detail": "Daily rate limit of 1000 requests exceeded for this"
                      " endpoint. See headers for additional details.",
            "status": 429
        }
    ]
}

ABUSE_401_RESPONSE = {
    "errors": [
        {
            "detail": "Authentication failed. You are either missing your "
                      "API key or it is incorrect. Note: The APIv2 key "
                      "differs from the APIv1 key.",
            "status": 401
        }
    ]
}

ABUSE_503_RESPONSE = {
    "errors": [
        {
            "code": "service unavailable",
            "message": "The AbuseIPDB is unavailable."
                       " Please, try again later.",
            "type": "fatal"
        }
    ]
}

EXPECTED_RESPONSE_DELIBERATE = {
    'data': {
        'verdicts': {
            'count': 1,
            'docs': [
                {
                    'disposition': 3,
                    'disposition_name': 'Suspicious',
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
                            'url': 'https://www.abuseipdb.com/categories',
                            'description': 'AbuseIPDB attack categories',
                            'external_id': '15'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.17',
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
                            'url': 'https://www.abuseipdb.com/categories',
                            'description': 'AbuseIPDB attack categories',
                            'external_id': '21'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.17',
                    'short_description': 'description for id 21',
                    'title': 'title for id 21',
                    'type': 'indicator',
                    'valid_time': {},
                    'external_ids': ['21']
                },
                {
                    'confidence': 'Medium',
                    'description': 'description for id 18',
                    'external_references': [
                        {
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories',
                            'description': 'AbuseIPDB attack categories',
                            'external_id': '18'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.17',
                    'short_description': 'description for id 18',
                    'title': 'title for id 18',
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
                            'url': 'https://www.abuseipdb.com/categories',
                            'description': 'AbuseIPDB attack categories',
                            'external_id': '20'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.17',
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
                    "reason": "title for id 15, title for id 21",
                    "schema_version": "1.0.17",
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
                    "reason": "title for id 18, title for id 20",
                    "schema_version": "1.0.17",
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
                    'schema_version': '1.0.17',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.17',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.17',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.17',
                    'type': 'relationship'
                }
            ]
        },
        'sightings': {
            'count': 2,
            'docs': [
                {
                    'confidence': 'Medium',
                    'count': 1,
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
                        'start_time': '2020-03-10T23:11:57.000000Z',
                        'end_time': '2020-03-10T23:11:57.000000Z'
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
                    'schema_version': '1.0.17',
                    'source': 'AbuseIPDB',
                    'source_uri':
                        'https://www.abuseipdb.com/check/118.25.6.39',
                    'title': 'Reported to AbuseIPDB',
                    'type': 'sighting'
                },
                {
                    'confidence': 'Medium',
                    'count': 1,
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
                        'start_time': '2020-02-26T14:34:59.000000Z',
                        'end_time': '2020-02-26T14:34:59.000000Z'
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
                    'schema_version': '1.0.17',
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
                    "disposition": 3,
                    "disposition_name": "Suspicious",
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

EXPECTED_RESPONSE_OBSERVE_WITH_LIMIT_1 = {
    'data': {
        'indicators': {
            'count': 2,
            'docs': [
                {
                    'confidence': 'Medium',
                    'description': 'description for id 15',
                    'external_ids': ['15'],
                    'external_references': [
                        {
                            'description': 'AbuseIPDB attack categories',
                            'external_id': '15',
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.17',
                    'short_description': 'description for id 15',
                    'title': 'title for id 15',
                    'type': 'indicator',
                    'valid_time': {}
                },
                {
                    'confidence': 'Medium',
                    'description': 'description for id 21',
                    'external_ids': ['21'],
                    'external_references': [
                        {
                            'description': 'AbuseIPDB attack categories',
                            'external_id': '21',
                            'source_name': 'AbuseIPDB',
                            'url': 'https://www.abuseipdb.com/categories'
                        }
                    ],
                    'producer': 'AbuseIPDB',
                    'schema_version': '1.0.17',
                    'short_description': 'description for id 21',
                    'title': 'title for id 21',
                    'type': 'indicator',
                    'valid_time': {}
                }
            ]
        },
        'judgements': {
            'count': 1,
            'docs': [
                {
                    'confidence': 'Medium',
                    'disposition': 2,
                    'disposition_name': 'Malicious',
                    'observable': {
                        'type': 'ip',
                        'value': '118.25.6.39'
                    },
                    'priority': 85,
                    "reason": "title for id 15, title for id 21",
                    'schema_version': '1.0.17',
                    'severity': 'Medium',
                    'source': 'AbuseIPDB',
                    'source_uri':
                        'https://www.abuseipdb.com/check/118.25.6.39',
                    'type': 'judgement',
                    'valid_time': {
                        'end_time': '2020-03-17T23:11:57.000000Z',
                        'start_time': '2020-03-10T23:11:57.000000Z'
                    }
                }
            ]
        },
        'relationships': {
            'count': 2,
            'docs': [
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.17',
                    'type': 'relationship'
                },
                {
                    'relationship_type': 'sighting-of',
                    'schema_version': '1.0.17',
                    'type': 'relationship'
                }
            ]
        },
        'sightings': {
            'count': 1,
            'docs': [
                {
                    'confidence': 'Medium',
                    'count': 1,
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
                        'start_time': '2020-03-10T23:11:57.000000Z',
                        'end_time': '2020-03-10T23:11:57.000000Z'
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
                    'schema_version': '1.0.17',
                    'source': 'AbuseIPDB',
                    'source_uri':
                        'https://www.abuseipdb.com/check/118.25.6.39',
                    'title': 'Reported to AbuseIPDB',
                    'type': 'sighting'
                }
            ]
        },
        'verdicts': {
            'count': 1,
            'docs': [
                {
                    'disposition': 3,
                    'disposition_name': 'Suspicious',
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

EXPECTED_RESPONSE_AUTH_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Authentication failed. You are '
                       'either missing your API key or it is incorrect. Note: '
                       'The APIv2 key differs from the APIv1 key.',
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

EXPECTED_RESPONSE_429_ERROR = {
    'errors': [
        {
            'code': 'too many requests',
            'message': 'Daily rate limit of 1000 requests exceeded for this '
                       'endpoint. See headers for additional details.',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_SSL_ERROR = {
    'errors': [
        {
            'code': 'unknown',
            'message': 'Unable to verify SSL certificate: self signed '
                       'certificate',
            'type': 'fatal'
        }
    ]
}

EXPECTED_AUTHORIZATION_HEADER_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Authorization header is missing',
            'type': 'fatal'
        }
    ]
}

EXPECTED_AUTHORIZATION_TYPE_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Wrong authorization type',
            'type': 'fatal'
        }
    ]
}

EXPECTED_JWT_STRUCTURE_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Wrong JWT structure',
            'type': 'fatal'
        }
    ]
}

EXPECTED_JWT_PAYLOAD_STRUCTURE_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Wrong JWT payload structure',
            'type': 'fatal'
        }
    ]
}

EXPECTED_WRONG_JWKS_HOST_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Wrong jwks_host in JWT payload. '
                       'Make sure domain follows the '
                       'visibility.<region>.cisco.com structure',
            'type': 'fatal'
        }
    ]
}

EXPECTED_JWKS_HOST_MISSING_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: jwk_host is missing in JWT '
                       'payload. Make sure custom_jwks_host field is present '
                       'in module_type',
            'type': 'fatal'
        }
    ]
}

EXPECTED_INVALID_SIGNATURE_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Failed to decode JWT with '
                       'provided key. Make suer domain in custom_jwks_host '
                       'corresponds to your SekureX instance region.',
            'type': 'fatal'
        }
    ]
}

EXPECTED_WRONG_AUDIENCE_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: Wrong '
                       'configuration-token-audience',
            'type': 'fatal'
        }
    ]
}

EXPECTED_KID_NOT_IN_API_ERROR = {
    'errors': [
        {
            'code': 'authorization error',
            'message': 'Authorization failed: kid from JWT header not found '
                       'in API response',
            'type': 'fatal'
        }
    ]
}

EXPECTED_RESPONSE_OF_JWKS_ENDPOINT = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'tSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
                 'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
                 'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
                 '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
                 'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
                 '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
                 'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
                 'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
                 'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
                 'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
                 'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
                 '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
                 'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
                 'k3jNdVM',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
