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
    get_response_data,
    get_categories_objects
)


enrich_api = Blueprint('enrich', __name__)


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


def get_abuse_ipdb_outputs(observables):
    # Return list of responses from AbuseIPDB for all observables

    outputs = []
    for observable in observables:
        abuse_ipdb_output = validate_abuse_ipdb_output(
            observable['value'])

        abuse_ipdb_output['data']['observable'] = observable
        outputs.append(abuse_ipdb_output)

    return outputs


def get_categories():

    # get categories HTML page with categories table
    response = requests.get(
        url=current_app.config['ABUSE_IPDB_CATEGORIES_URL']
    )

    categories_output = get_response_data(response)

    return get_categories_objects(categories_output)


def get_disposition(output):

    score = output['abuseConfidenceScore']

    disposition = None
    disposition_name = None

    for d_name, borders in current_app.config['ABUSE_SCORE_RELATIONS'].items():
        if borders[0] <= score <= borders[1]:
            disposition = current_app.config['CTIM_DISPOSITIONS'][d_name]
            disposition_name = d_name

    return disposition, disposition_name


def extract_verdicts(output, start_time):
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

    return doc


def extract_judgement(report, output):

    start_time = datetime.strptime(
        report['reportedAt'].split('+')[0],
        '%Y-%m-%dT%H:%M:%S'
    )
    end_time = start_time + timedelta(
        days=current_app.config['CTIM_VALID_DAYS_PERIOD'])

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

    return doc


def extract_sightings(report, output):
    start_time = datetime.strptime(
        report['reportedAt'].split('+')[0],
        '%Y-%m-%dT%H:%M:%S'
    )

    observed_time = {
        'start_time': start_time.isoformat(
            timespec='microseconds') + 'Z',
    }

    observable = {
        'value': output['data']['observable']['value'],
        'type': output['data']['observable']['type']
    }

    sighting_id = f'transient:{uuid4()}'

    # fill the obj for make relationships
    for category in report['categories']:
        category_id = str(category)
        if category_id in output['relations'].keys():
            output['relations'][category_id]['sighting_ids'].append(
                sighting_id
            )

    external_reference = {
        'source_name': 'AbuseIPDB',
        'url': current_app.config['ABUSE_IPDB_UI_URL'].format(
            ip=output['data']['observable']['value'])
    }

    relation = {
        'origin': 'AbuseIPDB Enrichment Module',
        'source': {
            'type': 'domain',
            'value': output['data']['domain']
        },
        'related': observable,
        'relation': 'Resolved_To',
        'origin_uri': current_app.config['ABUSE_IPDB_UI_URL'].format(
            ip=output['data']['observable']['value'])
    }

    doc = {
        'id': sighting_id,
        'count': output['data']['totalReports'],
        'observables': [observable],
        'external_references': [external_reference],
        'observed_time': observed_time,
        'description': report['comment'],
        'source_uri': current_app.config['ABUSE_IPDB_UI_URL'].format(
            ip=output['data']['observable']['value']),
        'relations': [relation],
        **current_app.config['CTIM_SIGHTING_DEFAULT']
    }

    return doc


def extract_indicators(report, output, categories):
    docs = []
    for category in report['categories']:
        category_id = str(category)

        # one indicator for each uniq category id
        if category_id not in output['categories_ids']:
            output['categories_ids'].append(category_id)

            indicator_id = f'transient:{uuid4()}'

            # obj for make relationships
            output['relations'][category_id] = {
                'indicator_id': indicator_id,
                'sighting_ids': []
            }

            category = categories[category_id]

            external_reference = {
                'source_name': 'AbuseIPDB',
                'url': current_app.config['ABUSE_IPDB_CATEGORIES_URL'],
                'description':
                    current_app.config['ABUSE_IPDB_CATEGORY_DESCRIPTION'],
                'external_id': category_id
            }

            doc = {
                'id': indicator_id,
                'title': category['title'],
                'description': category['description'] or category['title'],
                'short_description':
                    category['description'] or category['title'],
                'external_ids': [category_id],
                'external_references': [external_reference],
                **current_app.config['CTIM_INDICATOR_DEFAULT']
            }

            docs.append(doc)

    return docs


def extract_relationships(output):
    docs = []

    for key in output['relations'].keys():
        relation = output['relations'][key]
        indicator_id = relation['indicator_id']

        for sighting_id in relation['sighting_ids']:

            relationship_id = f'transient:{uuid4()}'

            doc = {
                'id': relationship_id,
                'source_ref': sighting_id,
                'target_ref': indicator_id,
                **current_app.config['CTIM_RELATIONSHIPS_DEFAULT']
            }

            docs.append(doc)

    return docs


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    abuse_outputs = get_abuse_ipdb_outputs(observables)

    start_time = datetime.utcnow()

    verdicts = []
    for output in abuse_outputs:
        verdicts.append(extract_verdicts(output, start_time))

    relay_output = {}

    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    abuse_outputs = get_abuse_ipdb_outputs(observables)

    time_now = datetime.utcnow()

    # get dict with actual abuseipdb categories with titles and descriptions
    categories = get_categories()

    verdicts = []
    judgements = []
    indicators = []
    sightings = []
    relationships = []

    for output in abuse_outputs:

        verdicts.append(extract_verdicts(output, time_now))

        output['categories_ids'] = []
        output['relations'] = {}

        reports = output['data']['reports']
        reports.sort(key=lambda x: x['reportedAt'], reverse=True)

        if len(reports) >= current_app.config['CTIM_SIGHTINGS_NUMBER']:
            reports = reports[:current_app.config['CTIM_SIGHTINGS_NUMBER']]

        for report in reports:
            judgements.append(extract_judgement(report, output))
            indicators.extend(extract_indicators(report, output, categories))
            sightings.append(extract_sightings(report, output))

        relationships.extend(extract_relationships(output))

    relay_output = {}

    if judgements:
        relay_output['judgements'] = format_docs(judgements)
    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)
    if sightings:
        relay_output['sightings'] = format_docs(sightings)
    if indicators:
        relay_output['indicators'] = format_docs(indicators)
    if relationships:
        relay_output['relationships'] = format_docs(relationships)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented
    return jsonify_data([])
