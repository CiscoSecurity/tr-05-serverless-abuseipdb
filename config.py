import os


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    ABUSE_IPDB_API_URL = 'https://api.abuseipdb.com/api/v2/{endpoint}'

    ABUSE_IPDB_OBSERVABLE_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPV6',
    }

    ABUSE_IPDB_SEARCH_PERIOD = 30

    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }