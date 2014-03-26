from leap.keymanager import KeyManager

SOLEDAD_CERT = '/tmp/ca.crt'


class NickNym(object):

    def __init__(self, config, soledad_session, srp_session):
        nicknym_url = _discover_nicknym_server(config)
        self.keymanager = KeyManager(config.email(), nicknym_url, soledad_session.soledad,
                                     srp_session.session_id, SOLEDAD_CERT, 'https://api.dev.dfi.local:4430/',
                                     srp_session.api_version,
                                     srp_session.uuid, config.gpg_binary)


def _discover_nicknym_server(config):
        return 'https://nicknym.%s:6425/' % config.server_name
