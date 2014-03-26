import unittest
import time
from plugins.soledad import LeapClientConfig, LeapSession, MailpileMailbox


class LeapTest(unittest.TestCase):
    def test_foobar(self):
        config = LeapClientConfig('dev.dfi.local', 'foobar', 'foobarfoobar', 'foobarfoobar', verify_ssl=False,
                                  fetch_interval_in_s=2)
        with LeapSession(config) as leap:
            self.assertIsNotNone(leap)
            time.sleep(3)

    def test_parse_path(self):
        (username, password, servername, mailbox_name) = MailpileMailbox.parse_path('leap://foo:bar@foo.bar.local/INBOX')
        self.assertEqual('foo', username)
        self.assertEqual('bar', password)
        self.assertEqual('foo.bar.local', servername)
        self.assertEqual('INBOX', mailbox_name)

    def test_parse_path_returns_value_error(self):
        self.assertRaises(ValueError, MailpileMailbox.parse_path, 'leap://something invalid/')
        self.assertRaises(ValueError, MailpileMailbox.parse_path, 'foo://foo:bar@foo.bar.local/INBOX')
