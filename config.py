from uuid import NAMESPACE_X500

from __version__ import VERSION


class Config(object):
    VERSION = VERSION

    NAMESPACE_BASE = NAMESPACE_X500

    ABUSE_IPDB_API_CLIENT_VERSION = VERSION
    ABUSE_IPDB_SOURCE_NAME = 'AbuseIPDB'
    ABUSE_IPDB_CATEGORY_DESCRIPTION = 'AbuseIPDB attack categories'

    ABUSE_IPDB_API_URL = 'https://api.abuseipdb.com/api/v2/{endpoint}'
    ABUSE_IPDB_UI_URL = 'https://www.abuseipdb.com/check/{ip}'
    ABUSE_IPDB_CATEGORIES_URL = 'https://www.abuseipdb.com/categories'

    ABUSE_IPDB_HEALTH_CHECK_IP = '192.168.1.100'

    ABUSE_IPDB_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPV6',
    }

    ABUSE_IPDB_SEARCH_PERIOD = 30

    ABUSE_SCORE_RELATIONS = {
        'Suspicious': (0, 85),
        'Malicious': (86, 100)
    }

    CTIM_SCHEMA_VERSION = '1.0.17'
    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }
    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'schema_version': CTIM_SCHEMA_VERSION,
        'source': ABUSE_IPDB_SOURCE_NAME,
        'confidence': 'Medium',
        'priority': 85,
        'severity': 'Medium',
    }
    CTIM_SIGHTING_DEFAULT = {
        'type': 'sighting',
        'schema_version': CTIM_SCHEMA_VERSION,
        'source': ABUSE_IPDB_SOURCE_NAME,
        'confidence': 'Medium',
        'title': 'Reported to AbuseIPDB',
        'internal': False
    }
    CTIM_INDICATOR_DEFAULT = {
        'type': 'indicator',
        'schema_version': CTIM_SCHEMA_VERSION,
        'producer': ABUSE_IPDB_SOURCE_NAME,
        'valid_time': {},
        'confidence': 'Medium'
    }
    CTIM_RELATIONSHIPS_DEFAULT = {
        'type': 'relationship',
        'relationship_type': 'sighting-of',
        'schema_version': CTIM_SCHEMA_VERSION
    }

    CTR_DEFAULT_ENTITIES_LIMIT = 100
    CTR_ENTITIES_LIMIT = CTR_DEFAULT_ENTITIES_LIMIT

    CTIM_VALID_DAYS_PERIOD = 7

    CTIM_DISPOSITIONS = {
        'Suspicious': 3,
        'Malicious': 2
    }
