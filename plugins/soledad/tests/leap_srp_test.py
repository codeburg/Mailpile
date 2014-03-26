import unittest

from plugins.soledad.leap_srp import LeapSecureRemotePassword, LeapAuthException, LeapSRPSession


class LeapSRPTest(unittest.TestCase):
    USER_NAME = 'foobar'

    def test_login_is_possible(self):
        srp = LeapSecureRemotePassword(verify_ssl=False)
        leap_session = srp.authenticate('api.dev.dfi.local', LeapSRPTest.USER_NAME, 'foobarfoobar')

        self.assertIsNotNone(leap_session)
        self.assertTrue(isinstance(leap_session, LeapSRPSession))

    def test_invalid_password_raises_exception(self):
        srp = LeapSecureRemotePassword(verify_ssl=False)

        self.assertRaises(LeapAuthException, srp.authenticate, 'api.dev.dfi.local', LeapSRPTest.USER_NAME, 'invalid')

    def test_verify_ssl_flag(self):
        srp = LeapSecureRemotePassword(verify_ssl=True)

        self.assertRaises(LeapAuthException, srp.authenticate, 'api.dev.dfi.local', LeapSRPTest.USER_NAME, 'foobarfoobar')
