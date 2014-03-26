import json
from leap.keymanager import KeyManager
from leap.soledad.client import Soledad
from leap.soledad.common.crypto import WrongMac, UnknownMacMethod, MacMethods
import requests

SOLEDAD_TIMEOUT = 120
SOLEDAD_CERT = '/tmp/ca.crt'


class SoledadDiscoverException(Exception):
    def __init__(self, *args, **kwargs):
        super(SoledadDiscoverException, self).__init__(*args, **kwargs)


class SoledadWrongPassphraseException(Exception):
    def __init__(self, *args, **kwargs):
        super(SoledadWrongPassphraseException, self).__init__(*args, **kwargs)


class LeapKeyManager(object):
    def __init__(self, soledad, leap_session, nicknym_url):
        self.keymanager = KeyManager('foobar@dev.dfi.local', nicknym_url, soledad,
                                     leap_session.session_id, SOLEDAD_CERT, 'https://api.dev.dfi.local:4430/', leap_session.api_version,
                                     leap_session.uuid, '/usr/local/MacGPG2/bin/gpg2')


class SoledadSession(object):
    def __init__(self, encryption_passphrase, leap_srp_session, verify_ssl=True, timeout_in_s=15):
        self.leap_srp_session = leap_srp_session
        self.verify_ssl = verify_ssl
        self.timeout_in_s = timeout_in_s

        self.soledad = self._init_soledad(encryption_passphrase)


    def _init_soledad(self, encryption_passphrase):
        try:
            server_url = self._discover_soledad_server()
            return Soledad(self.leap_srp_session.uuid, unicode(encryption_passphrase), '/tmp/foobar/secrets',
                               '/tmp/foobar/database', server_url, SOLEDAD_CERT, self.leap_srp_session.token)

        except (WrongMac, UnknownMacMethod, MacMethods), e:
            raise SoledadWrongPassphraseException(e)

    def sync(self):
        self.soledad.sync()

    def _discover_nicknym_server(self):
        return 'https://nicknym.%s:6425/' % self.leap_srp_session.api_server_name


    def _discover_soledad_server(self):
        try:
            http = requests.Session()
            service_url = "https://%s/%s/config/soledad-service.json" % (
                self.leap_srp_session.api_server_name, self.leap_srp_session.api_version)
            response = http.get(service_url, verify=self.verify_ssl, timeout=self.timeout_in_s)
            response.raise_for_status()
            json_data = json.loads(response.content)

            hosts = json_data['hosts']
            host = hosts.keys()[0]
            server_url = 'https://%s:%d/user-%s' % \
                         (hosts[host]['hostname'], hosts[host]['port'],
                          self.leap_srp_session.uuid)
            return server_url
        except Exception, e:
            raise SoledadDiscoverException(e)
