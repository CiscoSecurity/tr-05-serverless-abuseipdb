from functools import partial

from marshmallow import ValidationError, Schema, fields, INCLUDE


def validate_string(value, *, choices=None):
    if value == '':
        raise ValidationError('Field may not be blank.')

    if choices is not None:
        if value not in choices:
            raise ValidationError(
                f'Must be one of: {", ".join(map(repr, choices))}.'
            )


OBSERVABLE_TYPE_CHOICES = (
    'ip',
    'ipv6',
)


class ObservableSchema(Schema):
    type = fields.String(
        validate=partial(validate_string, choices=OBSERVABLE_TYPE_CHOICES),
        required=True,
    )
    value = fields.String(
        validate=validate_string,
        required=True,
    )


class ActionFormParamsSchema(Schema):
    action_id = fields.String(
        data_key='action-id',
        validate=validate_string,
        required=True,
    )
    observable_type = fields.String(
        validate=partial(validate_string, choices=OBSERVABLE_TYPE_CHOICES),
        required=True,
    )
    observable_value = fields.String(
        validate=validate_string,
        required=True,
    )

    class Meta:
        unknown = INCLUDE
