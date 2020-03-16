import os

from version import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    ABUSE_IPDB_API_CLIENT_VERSION = VERSION

    ABUSE_IPDB_API_URL = 'https://api.abuseipdb.com/api/v2/{endpoint}'
    ABUSE_IPDB_UI_URL = 'https://www.abuseipdb.com/check/{ip}'

    ABUSE_IPDB_HEALTH_CHECK_IP = '192.168.1.100'

    ABUSE_IPDB_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPV6',
    }

    ABUSE_IPDB_SEARCH_PERIOD = 30

    ABUSE_SCORE_RELATIONS = {
        'Unknown': (0, 0),
        'Clean': (1, 25),
        'Suspicious': (26, 85),
        'Malicious': (86, 100)
    }

    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }
    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'schema_version': '1.0.16',
        'source': 'AbuseIPDB',
        'confidence': 'Medium',
        'priority': 85,
        'severity': 'Medium',
    }

    CTIM_DISPOSITIONS = {
        'Clean': 1,
        'Suspicious': 3,
        'Malicious': 2,
        'Unknown': 5
    }
