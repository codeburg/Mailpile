import atexit
from mailbox import Mailbox
import re
from threading import Thread
import traceback
from urllib import quote
import sys

from leap.mail.imap.fetch import LeapIncomingMail
from leap.mail.imap.server import SoledadBackedAccount
from twisted.internet import reactor

from mailpile.mailboxes import UnorderedPicklable
from plugins.soledad.leap_srp import LeapSecureRemotePassword
from plugins.soledad.nicknym import NickNym
from plugins.soledad.soledad import SoledadSession


REACTOR_THREAD = None
LEAP_SESSIONS = {}


class LeapClientConfig(object):
    """
    LEAP client configuration

    """

    def __init__(self, server_name, user_name, user_password, db_passphrase, verify_ssl=True, fetch_interval_in_s=30,
                 timeout_in_s=15, gpg_binaray='/usr/local/MacGPG2/bin/gpg2'):
        """
        Constructor.

        :param server_name: The LEAP server name, e.g. demo.leap.se
        :type server_name: str

        :param user_name: The LEAP account user name, normally the first part of your email, e.g. foobar for foobar@demo.leap.se
        :type user_name: str

        :param user_password: The LEAP account password
        :type user_password: str

        :param db_passphrase: The passphrase used to encrypt the local soledad database
        :type db_passphrase: str

        :param verify_ssl: Set to false to disable strict SSL certificate validation
        :type verify_ssl: bool

        :param fetch_interval_in_s: Polling interval for fetching incoming mail from LEAP server
        :type fetch_interval_in_s: int

        :param timeout_in_s: Timeout for network operations, e.g. HTTP calls
        :type timeout_in_s: int

        :param gpg_binaray: Path to the GPG binary (must not be a symlink)
        :type gpg_binaray: str

        """
        self.server_name = server_name
        self.user_name = user_name
        self.user_password = user_password
        self.db_passphrase = db_passphrase
        self.verify_ssl = verify_ssl
        self.timeout_in_s = timeout_in_s
        self.gpg_binary = gpg_binaray
        self.fetch_interval_in_s = fetch_interval_in_s

    def email(self):
        return '%s@%s' % (self.user_name, self.server_name)


class LeapSession(object):
    """
    A LEAP session.


    Properties:

    - ``leap_config`` the configuration for this session (LeapClientConfig).

    - ``srp_session`` the secure remote password session to authenticate with LEAP. See http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol (LeapSecureRemotePassword)

    - ``soledad_session`` the soledad session. See https://leap.se/soledad (LeapSecureRemotePassword)

    - ``nicknym`` the nicknym instance. See https://leap.se/nicknym (NickNym)

    - ``account`` the actual leap mail account. Implements Twisted imap4.IAccount and imap4.INamespacePresenter (SoledadBackedAccount)

    - ``incoming_mail_fetcher`` Background job for fetching incoming mails from LEAP server (LeapIncomingMail)
    """

    def __init__(self, leap_config, start_background_jobs=True):
        """
        Constructor.

        :param leap_config: The config for this LEAP session
        :type leap_config: LeapClientConfig

        """
        self.leap_config = leap_config
        self.srp_session = self._authenticate()
        self.soledad_session = self._create_soledad_session(self.srp_session)
        self.nicknym = self._create_nicknym(self.srp_session, self.soledad_session)
        self.account = self._create_account(self.srp_session, self.soledad_session)
        self.incoming_mail_fetcher = self._create_incoming_mail_fetcher(self.nicknym, self.soledad_session,
                                                                        self.account)

        if start_background_jobs:
            self.start_background_jobs()

    def __enter__(self):
        self.start_background_jobs()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.stop_background_jobs()

    def _authenticate(self):
        return LeapSecureRemotePassword(verify_ssl=self.leap_config.verify_ssl,
                                        timeout_in_s=self.leap_config.timeout_in_s).authenticate(
            'api.%s' % self.leap_config.server_name,
            self.leap_config.user_name,
            self.leap_config.db_passphrase)

    def _create_soledad_session(self, srp_session):
        return SoledadSession(self.leap_config.db_passphrase, srp_session, self.leap_config.verify_ssl,
                              self.leap_config.timeout_in_s)

    def _create_nicknym(self, srp_session, soledad_session):
        return NickNym(self.leap_config, soledad_session, srp_session)

    def _create_account(self, srp_session, soledad_session):
        return SoledadBackedAccount(srp_session.uuid, soledad_session.soledad)

    def _create_incoming_mail_fetcher(self, nicknym, soledad_session, account):
        return LeapIncomingMail(nicknym.keymanager, soledad_session.soledad, account,
                                self.leap_config.fetch_interval_in_s, self.leap_config.email())

    def start_background_jobs(self):
        reactor.callFromThread(self.incoming_mail_fetcher.start_loop)

    def stop_background_jobs(self):
        reactor.callFromThread(self.incoming_mail_fetcher.stop)


class LeapMailbox(Mailbox):
    def __init__(self, username, password, server_name, mailbox_name, verify_ssl=False):
        try:
            self.username = username
            self.password = password
            self.server_name = server_name
            self.mailbox_name = mailbox_name

            self.leap_config = LeapClientConfig(server_name, username, password, password, verify_ssl=verify_ssl)
            self.leap_session = LeapSessionFactory.get_session_for(self.leap_config)
            self.mbx = self.leap_session.account.getMailbox(mailbox_name)
        except:
            traceback.print_exc(file=sys.stdout)
            raise

    def add(self, message):
        """Add message and return assigned key."""
        raise NotImplementedError('Not yet supported')

    def remove(self, key):
        """Remove the keyed message; raise KeyError if it doesn't exist."""
        raise NotImplementedError('Not yet supported')

    def iterkeys(self):
        """Return an iterator over keys."""
        mbx = self.leap_session.account.getMailbox(self.mailbox_name)
        msgs = mbx.messages.get_all()
        return (str(msg.content['uid']) for msg in msgs)

    def get_file(self, key):
        """Return a file-like representation or raise a KeyError."""
        message = self.mbx.messages.get_msg_by_uid(key)
        return message.open()

    def get_message(self, key):
        """Return a Message representation or raise a KeyError."""
        return self.mbx.messages.get_msg_by_uid(key)

    def get_bytes(self, key):
        """Return a byte string representation or raise a KeyError."""
        raise NotImplementedError('Method must be implemented by subclass')

    def __contains__(self, key):
        """Return True if the keyed message exists, False otherwise."""
        return self.mbx.messages.get_by_uid(key) is not None

    def __len__(self):
        """Return a count of messages in the mailbox."""
        return self.mbx.getMessageCount()

    def close(self):
        """Flush and close the mailbox."""
        self.leap_session.close()

    def flush(self):
        """Write any pending changes to the disk."""
        raise NotImplementedError('Method must be implemented by subclass')

    def lock(self):
        """Lock the mailbox."""
        raise NotImplementedError('Method must be implemented by subclass')

    def unlock(self):
        """Unlock the mailbox if it is locked."""
        raise NotImplementedError('Method must be implemented by subclass')

    def get_bytes(self, key):
        """Return a byte string representation or raise a KeyError."""
        raise NotImplementedError('Method must be implemented by subclass')


class MailpileMailbox(UnorderedPicklable(LeapMailbox)):
    @classmethod
    def parse_path(cls, path, create=False):
        if path.startswith("leap://"):
            pattern = re.compile('^leap://(.+):(.+)@([A-Za-z.]+)/([A-Za-z]+)$')
            m = pattern.match(path)
            if m:
                username = m.group(1)
                password = m.group(2)
                server_name = m.group(3)
                mailbox_name = m.group(4)

                # WARNING: Order must match LeapMailbox.__init__(...)
                return username, password, server_name, mailbox_name
        raise ValueError('Not an LEAP url: %s' % path)

    def __getstate__(self):
        odict = self.__dict__.copy()
        # Pickle can't handle file and function objects.
        del odict['leap_config']
        del odict['leap_session']
        del odict['mbx']
        del odict['_save_to']
        del odict['_encryption_key_func']

        return odict

    def get_msg_ptr(self, mboxid, toc_id):
        return '%s%s' % (mboxid, quote(toc_id))


class LeapSessionFactory(object):


    @classmethod
    def get_session_for(cls, leap_config):
        """
        LeapClientConfig
        """
        global LEAP_SESSIONS
        session_name = "%s:%s" % (leap_config.server_name, leap_config.user_name)
        if session_name not in LEAP_SESSIONS:
            LEAP_SESSIONS[session_name] = LeapSession(leap_config)
        return LEAP_SESSIONS[session_name]

#mailpile.mailboxes.register(50, MailpileMailbox)


def start_reactor():
    global REACTOR_THREAD
    REACTOR_THREAD = Thread(target=reactor.run, args=(False,))
    REACTOR_THREAD.start()


def stop_reactor_on_exit():
    reactor.callFromThread(reactor.stop)
    global REACTOR_THREAD
    REACTOR_THREAD = None


def stop_sessions_on_exit():
    global LEAP_SESSIONS
    for session in LEAP_SESSIONS.values():
        session.close()


def cleanup_on_exit():
    stop_sessions_on_exit()
    stop_reactor_on_exit()

start_reactor()
atexit.register(cleanup_on_exit)

