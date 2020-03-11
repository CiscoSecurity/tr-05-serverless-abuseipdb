from functools import partial
from datetime import datetime

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
        'Key': get_jwt().get('key', '')
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
            return None, [error]
        else:
            return None, response.json()['errors']


def group_observables(relay_input):
    # Leave only unique pairs.

    result = []
    for obj in relay_input:

        obj['type'] = obj['type'].lower()

        # Get only supported types.
        if obj['type'] in current_app.config['ABUSE_IPDB_OBSERVABLE_TYPES']:
            if obj in result:
                continue
            result.append(obj)

    return result


def get_disposition(output):

    score = output['abuseConfidenceScore']

    disposition = None
    disposition_name = None

    for d_name, borders in current_app.config['ABUSE_SCORE_RELATIONS'].items():
        if borders[0] <= score <= borders[1]:
            disposition = current_app.config['CTIM_DISPOSITIONS'][d_name]
            disposition_name = d_name

    return disposition, disposition_name


def extract_verdicts(outputs, start_time):
    docs = []

    for output in outputs:

        disposition, disposition_name = get_disposition(output['data'])

        valid_time = {
            'start_time': start_time.isoformat() + 'Z'
        }

        observable = {
            'value': output['data']['observable']['value'],
            'type': output['data']['observable']['type']
        }

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
        return jsonify_errors([error])

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    abuse_abuse_ipdb_outputs = []

    for observable in observables:
        abuse_abuse_ipdb_output, errors = validate_abuse_ipdb_output(
            observable['value'])

        if errors:
            return jsonify_errors(errors)

        abuse_abuse_ipdb_output['data']['observable'] = observable
        abuse_abuse_ipdb_outputs.append(abuse_abuse_ipdb_output)

    start_time = datetime.utcnow()

    verdicts = extract_verdicts(abuse_abuse_ipdb_outputs, start_time)

    relay_output = {}

    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_observables()
    return jsonify_data([])
