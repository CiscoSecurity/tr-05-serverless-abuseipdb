from functools import partial
from datetime import datetime, timedelta
from uuid import uuid4

from flask import Blueprint, current_app
import requests

from api.schemas import ObservableSchema
from api.utils import (
    get_json,
    get_jwt,
    jsonify_data,
    url_for,
    jsonify_errors,
    get_response_data
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

    return get_response_data(response)


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


def extract_judgement(outputs):
    docs = []

    for output in outputs:

        reports = output['data']['reports']
        if len(reports) >= 100:
            reports = reports[:100]

        for report in reports:

            start_time = datetime.strptime(
                report['reportedAt'].split('+')[0],
                '%Y-%m-%dT%H:%M:%S'
            )
            end_time = start_time + timedelta(days=7)

            valid_time = {
                'start_time': start_time.isoformat(
                    timespec='microseconds') + 'Z',
                'end_time': end_time.isoformat(timespec='microseconds') + 'Z',
            }

            observable = {
                'value': output['data']['observable']['value'],
                'type': output['data']['observable']['type']
            }

            judgement_id = f'transient:{uuid4()}'

            doc = {
                'id': judgement_id,
                'observable': observable,
                'disposition': 2,
                'disposition_name': 'Malicious',
                'valid_time': valid_time,
                'source_uri': current_app.config['ABUSE_IPDB_UI_URL'].format(
                    ip=output['data']['observable']['value']),
                **current_app.config['CTIM_JUDGEMENT_DEFAULTS']
            }

            docs.append(doc)

    return docs, outputs


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

    time_now = datetime.utcnow()

    judgements, outputs = extract_judgement(abuse_abuse_ipdb_outputs)
    verdicts = extract_verdicts(outputs, time_now)

    relay_output = {}

    if judgements:
        relay_output['judgements'] = format_docs(judgements)
    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_observables()
    return jsonify_data([])
