INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
NOT_FOUND = 'not found'
INTERNAL = 'internal error'
TOO_MANY_REQUESTS = 'too many requests'
SERVER_DOWN = 'web server is down'
SERVER_UNAVAILABLE = 'service unavailable'
AUTH_ERROR = 'authorization error'
HEALTH_CHECK_ERROR = 'health check failed'


class TRError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class AbuseInternalServerError(TRError):
    def __init__(self):
        super().__init__(
            INTERNAL,
            'The Abuse IPDB internal error.'
        )


class AbuseNotFoundError(TRError):
    def __init__(self):
        super().__init__(
            NOT_FOUND,
            'The Abuse IPDB not found.'
        )


class AbuseUnexpectedResponseError(TRError):
    def __init__(self, payload):
        error_payload = payload.json()

        super().__init__(
            UNKNOWN,
            str(error_payload)
        )


class AbuseServerDownError(TRError):
    def __init__(self):
        super().__init__(
            SERVER_DOWN,
            'The AbuseIPDB server is down.'
        )


class AbuseUnavailableError(TRError):
    def __init__(self):

        super().__init__(
            SERVER_UNAVAILABLE,
            'The AbuseIPDB is unavailable. Please, try again later.'
        )


class AbuseTooManyRequestsError(TRError):
    def __init__(self, payload):
        error_payload = payload.json()['errors'][0]['detail']

        super().__init__(
            TOO_MANY_REQUESTS,
            str(error_payload)
        )


class AbuseSSLError(TRError):
    def __init__(self, error):
        message = getattr(
            error.args[0].reason.args[0], 'verify_message', ''
        ) or error.args[0].reason.args[0].args[0]

        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class AuthorizationError(TRError):
    def __init__(self, message):

        super().__init__(
            AUTH_ERROR,
            f"Authorization failed: {message}"
        )


class BadRequestError(TRError):
    def __init__(self, error_message):
        super().__init__(
            INVALID_ARGUMENT,
            error_message
        )


class AbuseWatchdogError(TRError):
    def __init__(self):
        super().__init__(
            HEALTH_CHECK_ERROR,
            'Invalid Health Check'
        )
