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

    # List all records. Return an empty list if no records found
    # type, name and content are used to filter records.
    # If possible filter during the query, otherwise filter after response is received.
    def _list_records(self, rtype=None, name=None, content=None):

        domain_id = self._get_domain_identifier()
        records_response = self._get('/dns/{0}'.format(domain_id))

        entries = []

        for record in records_response['response']['records']:

            LOGGER.debug("Record: %s", record)

            if (rtype is not None) and (record['type'] != rtype):
                LOGGER.debug(
                    "\tType doesn't match - expected: '%s', found: '%s'",
                    rtype, record['type'])
                continue

            entry = {
                'type': record['type'],
                'name': record['name'],
                'ttl': record['ttl'],
                'content': record['content'],
                'options': {
                    'disabled': record['disabled']
                }
            }

            entries.append(entry)

        LOGGER.debug('list_records: %s', entries)

        return entries

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
