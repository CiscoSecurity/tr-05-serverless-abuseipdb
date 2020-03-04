from functools import partial
from collections import defaultdict
from datetime import datetime, timedelta

from flask import Blueprint, current_app
import requests

from api.schemas import ObservableSchema
from api.utils import (
    get_json,
    get_jwt,
    jsonify_data,
    url_for,
    jsonify_errors
)


enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


def validate_abuse_ipdb_output(abuse_input):
    url = url_for('check')

    headers = {
        'Accept': 'application/json',
        'Key': get_jwt().get('key')
    }

    params = {
        'ipAddress': abuse_input,
        'maxAgeInDays': current_app.config['ABUSE_IPDB_SEARCH_PERIOD'],
        'verbose': 'true'
    }

    response = requests.get(url, headers=headers, params=params)

    if response.ok:
        return response.json(), None
    else:
        if response.status_code == 401:
            error = {
                'code': 403,
                'message': 'The request is missing a valid API key.',
                'status': 'PERMISSION_DENIED',
            }
            return None, error
        else:
            return None, response.json()['error']


def group_observables(relay_input):
    # Leave only unique (value, type) pairs grouped by value.

    observables = defaultdict(set)

    for observable in relay_input:
        value = observable['value']
        type = observable['type'].lower()

        # Discard any unsupported type.
        if type in current_app.config['ABUSE_IPDB_OBSERVABLE_TYPES']:
            observables[value].add(type)

    observables = {
        value: sorted(types)
        for value, types in observables.items()
    }

    return observables


def extract_verdicts(observables, start_time):
    docs = []

    for items in observables:
        for value, types in items.items():

            disposition = None
            disposition_name = None
            cache_duration = 100

            end_time = start_time + timedelta(seconds=cache_duration)

            valid_time = {
                'start_time': start_time.isoformat() + 'Z',
                'end_time': end_time.isoformat() + 'Z',
            }

            for type in types:
                observable = {'value': value, 'type': type}

                doc = {
                    'observable': observable,
                    'disposition': disposition,
                    'disposition_name': disposition_name,
                    'valid_time': valid_time,
                    **current_app.config['CTIM_VERDICT_DEFAULTS']
                }

                docs.append(doc)

    return docs


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    relay_input, error = get_json(ObservableSchema(many=True))

    if error:
        return jsonify_errors(error)

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    abuse_abuse_ipdb_outputs = []

    for value in observables.keys():
        abuse_abuse_ipdb_output, error = validate_abuse_ipdb_output(value)

        if error:
            return jsonify_errors(error)

        abuse_abuse_ipdb_outputs.append(abuse_abuse_ipdb_output)

    start_time = datetime.utcnow()

    verdicts = extract_verdicts(abuse_abuse_ipdb_outputs, start_time)

    relay_output = {}

    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
