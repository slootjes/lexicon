"""Module provider for Open Domain Registry"""
import hashlib
import json
import logging
import time

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

import requests

from lexicon.providers.base import Provider as BaseProvider

LOGGER = logging.getLogger(__name__)

NAMESERVER_DOMAINS = ['odrdns.eu']


def provider_parser(subparser):
    """Generate subparser for Open Domain Registry"""
    subparser.add_argument(
        "--auth-key", help="specify api key for authentication")
    subparser.add_argument(
        "--auth-secret", help="specify api secret for authentication")


class Provider(BaseProvider):
    def __init__(self, config):
        super(Provider, self).__init__(config)
        self.domain_id = None
        self.api_endpoint = 'https://api.opendomainregistry.net'
        self.access_token = None
        self.domain_id = None

    def _authenticate(self):
        timestamp = int(time.time())
        api_key = self._get_provider_option('auth_key')
        api_secret = self._get_provider_option('auth_secret')

        signature = self._create_signature(timestamp, api_key, api_secret)

        token_response = self._post('/user/login/',
                                    {'timestamp': timestamp, 'api_key': api_key, 'signature': signature}
                                    )

        self.access_token = token_response['response']['token']

    def _list_records(self, rtype=None, name=None, content=None):
        return self._get_current_records(None, rtype, name, content)

    def _create_record(self, rtype, name, content):
        if self._get_domain_identifier() is None:
            # domain does not yet exist, create new zone for it
            return True
        else:
            # domain zone exists, add current record to it
            return self._update_record(None, rtype=rtype, name=name, content=content)

    def _update_record(self, identifier, rtype=None, name=None, content=None):


        return True

    def delete_record(self, identifier=None, rtype=None, name=None, content=None, **kwargs):
        return True

    def _request(self, action='GET', url='/', data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if self.access_token is not None:
            headers['X-Access-Token'] = self.access_token

        response = requests.request(action, self.api_endpoint + url, params=query_params,
                                    data=json.dumps(data),
                                    headers=headers)
        # if the request fails for any reason, throw an error.
        response.raise_for_status()
        return response.json()

    # Helpers
    def _get_current_records(self, identifier=None, rtype=None, name=None, content=None):
        domain_id = self._get_domain_identifier()
        records_response = self._get('/dns/{0}'.format(domain_id))

        matches = []
        for record in records_response['response']['records']:

            LOGGER.debug('Record: %s', record)

            if (rtype is not None) and (record['type'] != rtype):
                LOGGER.debug('Type does not match - expected "%s", found "%s"', rtype, record['type'])
                continue

            if (name is not None) and (record['name'] != name):
                LOGGER.debug('Name does not match - expected "%s", found "%s"', name, record['name'])
                continue

            if (name is not None) and (record['content'] != content):
                LOGGER.debug('Content does not match - expected "%s", found "%s"', content, record['content'])
                continue

            record_id = self._create_record_identifier(record)
            if (identifier is not None) and (identifier != record_id):
                LOGGER.debug('Identifier does not match - expected "%s", found "%s"', identifier, record_id)
                continue

            matches.append({
                'id': record_id,
                'type': record['type'],
                'name': record['name'],
                'ttl': record['ttl'],
                'content': record['content'],
                'options': {
                    'disabled': record['disabled']
                }
            })

        LOGGER.debug('list_records: %s', matches)

        return matches

    def _get_domain_identifier(self):
        if self.domain_id is not None:
            return self.domain_id

        domains = self._get('/dns/', {'f[hostname]': self.domain})
        LOGGER.debug('domains: %s', domains)

        if len(domains['response']) == 1:
            self.domain_id = domains['response'][0]['id']
            return self.domain_id

        raise Exception('Domain identifier could not be found.')

    def _create_signature(self, timestamp, api_key, api_secret):
        return 'token$' + self._calculate_hash('%s %s %s' % (api_key, timestamp, self._calculate_hash(api_secret)))

    def _calculate_hash(self, value):
        return hashlib.sha1(value.encode('utf-8')).hexdigest()

    def _create_record_identifier(self, record):
        record_hash = hashlib.sha1()
        record_hash.update(('type=' + record['type'] + ',').encode('utf-8'))
        record_hash.update(('name=' + record['name'] + ',').encode('utf-8'))
        record_hash.update(('content=' + record['content'] + ',').encode('utf-8'))

        return record_hash.hexdigest()
