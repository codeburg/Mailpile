import binascii
import srp
from mailpile.commands import Action
from tests import MailPileUnittest


class TestCommands(MailPileUnittest):
    def test_foobar(self):
        self.assertEqual(0, srp.NG_1024)
        self.mp._session.config.plugins.available()
        res = Action(self.mp._session, "soledadlogin", None)

        self.assertIsNone(res)
