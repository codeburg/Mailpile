import unittest
import sys
from plugins.soledad.leap_srp import LeapSecureRemotePassword
from plugins.soledad.soledad import SoledadSession


class SoledadSessionTest(unittest.TestCase):
    def test_foobar(self):
        leap_session = LeapSecureRemotePassword(verify_ssl=False).authenticate('api.dev.dfi.local', 'foobar', 'foobarfoobar')
        session = SoledadSession('foobarfoobar', leap_session, verify_ssl=False)
        session.sync()
        session.soledad.list_indexes()
