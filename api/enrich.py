from datetime import datetime, timedelta
from uuid import uuid4, uuid5

import requests
from flask import Blueprint, current_app, g

from api.schemas import ObservableSchema
from api.utils import (
    get_json,
    get_jwt,
    jsonify_data,
    url_for,
    get_response_data,
    get_categories_objects,
    format_docs,
    catch_ssl_errors
)


enrich_api = Blueprint('enrich', __name__)


@catch_ssl_errors
def validate_abuse_ipdb_output(abuse_input, token):
    url = url_for('check')

    headers = {
        'Accept': 'application/json',
        'User-Agent': ('SecureX Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>'),
        'Key': token
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


def get_abuse_ipdb_outputs(observable, token):
    # Return list of responses from AbuseIPDB for all observables

    abuse_ipdb_output = validate_abuse_ipdb_output(observable['value'], token)

    if abuse_ipdb_output:
        abuse_ipdb_output['data']['observable'] = observable

    return abuse_ipdb_output


@catch_ssl_errors
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


def get_relation(output, observable):
    if output['data']['domain']:
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
    else:
        relation = {}

    return relation


def get_reason(categories, ids):
    categories_titles = [
        categories[str(id)]['title'] or categories[str(id)]['description']
        for id in ids if id
    ]

    return ', '.join(categories_titles)


def get_transient_id(entity_type, base_value=None):
    uuid = (uuid5(current_app.config['NAMESPACE_BASE'], base_value)
            if base_value else uuid4())
    return f'transient:{entity_type}-{uuid}'


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


def extract_judgement(report, output, categories):

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

    judgement_id = f'transient:judgement-{uuid4()}'

    doc = {
        'id': judgement_id,
        'observable': observable,
        'disposition': 2,
        'disposition_name': 'Malicious',
        'valid_time': valid_time,
        'source_uri': current_app.config['ABUSE_IPDB_UI_URL'].format(
            ip=output['data']['observable']['value']),
        'reason': get_reason(categories, report['categories']),
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
        'end_time': start_time.isoformat(
            timespec='microseconds') + 'Z'
    }

    observable = {
        'value': output['data']['observable']['value'],
        'type': output['data']['observable']['type']
    }

    sighting_id = f'transient:sighting-{uuid4()}'

    # fill the obj for make relationships
    for category in report['categories']:
        if category:
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

    relation = get_relation(output, observable)

    doc = {
        'id': sighting_id,
        'count': 1,
        'observables': [observable],
        'external_references': [external_reference],
        'observed_time': observed_time,
        'description': report['comment'],
        'source_uri': current_app.config['ABUSE_IPDB_UI_URL'].format(
            ip=output['data']['observable']['value']),
        'relations': [relation] if relation else [],
        **current_app.config['CTIM_SIGHTING_DEFAULT']
    }

    return doc


def extract_indicators(report, output, categories):
    docs = []
    for category in report['categories']:
        if category:
            category_id = str(category)

            # one indicator for each uniq category id
            if category_id not in output['categories_ids']:
                output['categories_ids'].append(category_id)

                indicator_id = get_transient_id('indicator', category_id)

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
                    'description':
                        category['description'] or category['title'],
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

            relationship_id = f'transient:relationship-{uuid4()}'

            doc = {
                'id': relationship_id,
                'source_ref': sighting_id,
                'target_ref': indicator_id,
                **current_app.config['CTIM_RELATIONSHIPS_DEFAULT']
            }

            docs.append(doc)

    return docs


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    start_time = datetime.utcnow()
    token = get_jwt()

    g.verdicts = []

    for observable in observables:
        output = get_abuse_ipdb_outputs(observable, token)

        if output:
            g.verdicts.append(extract_verdicts(output, start_time))

    relay_output = {}

    if g.verdicts:
        relay_output['verdicts'] = format_docs(g.verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input = get_json(ObservableSchema(many=True))

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    time_now = datetime.utcnow()

    token = get_jwt()

    # get dict with actual abuseipdb categories with titles and descriptions
    categories = get_categories()

    g.verdicts = []
    g.judgements = []
    g.indicators = []
    g.sightings = []
    g.relationships = []

    for observable in observables:
        output = get_abuse_ipdb_outputs(observable, token)

        if output:
            g.verdicts.append(extract_verdicts(output, time_now))

            output['categories_ids'] = []
            output['relations'] = {}

            reports = output['data']['reports']
            reports.sort(key=lambda x: x['reportedAt'], reverse=True)

            if len(reports) >= current_app.config['CTR_ENTITIES_LIMIT']:
                reports = reports[:current_app.config['CTR_ENTITIES_LIMIT']]

            for report in reports:
                g.judgements.append(
                    extract_judgement(report, output, categories))
                g.indicators.extend(
                    extract_indicators(report, output, categories))
                g.sightings.append(extract_sightings(report, output))

            g.relationships.extend(extract_relationships(output))

    relay_output = {}

    if g.judgements:
        relay_output['judgements'] = format_docs(g.judgements)
    if g.verdicts:
        relay_output['verdicts'] = format_docs(g.verdicts)
    if g.sightings:
        relay_output['sightings'] = format_docs(g.sightings)
    if g.indicators:
        relay_output['indicators'] = format_docs(g.indicators)
    if g.relationships:
        relay_output['relationships'] = format_docs(g.relationships)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented
    return jsonify_data([])
