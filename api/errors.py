import json

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
NOT_FOUND = 'not found'
INTERNAL = 'internal error'


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


class AbuseInvalidCredentialsError(TRError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'The request is missing a valid API key.'
        )


class AbuseUnexpectedResponseError(TRError):
    def __init__(self, payload):
        error_payload = json.loads(payload).get('error', {})

        super().__init__(
            error_payload.get('status', '').lower().replace('_', ' '),
            error_payload.get('message', None)
            or error_payload.get('details', None)
        )


class BadRequestError(TRError):
    def __init__(self, error_message):
        super().__init__(
            INVALID_ARGUMENT,
            error_message
        )
