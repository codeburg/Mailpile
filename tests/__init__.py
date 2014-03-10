import contextlib
import os
import shutil
import sys
import unittest
from cStringIO import StringIO

# Mailpile core
from mailpile.crypto.gpgi import change_gnupg_home
from mailpile.ui import SilentInteraction

# Pull in all the standard plugins, plus the demos.
from mailpile.mailboxes import *
from mailpile.plugins import *
import mailpile.plugins.demos

MP = None


def get_mailpile_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def get_shared_mailpile():
    global MP
    if MP is not None:
        return MP

    workdir = get_mailpile_root()
    tmpdir = os.path.join(workdir, 'testing', 'tmp')
    test_data = os.path.join(workdir, 'testing', 'Maildir')

    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    if not os.path.exists(os.path.join(test_data, "new")):
        os.mkdir(os.path.join(test_data, "new"))

    sys.stderr.write('Preparing shared Mailpile test environment, '
                     'please wait. 8-)\n')

    config = mailpile.app.ConfigManager(workdir=tmpdir, rules=mailpile.defaults.CONFIG_RULES)
    session = mailpile.ui.Session(config)
    session.config.load(session)
    session.main = True
    ui = session.ui = SilentInteraction(config)

    mp = mailpile.Mailpile(session=session)
    mp.set('prefs.index_encrypted=true')

    # Add some mail, scan it.
    mp.add(test_data)
    mp.rescan()

    MP = mp, session, config, ui

    return MP


@contextlib.contextmanager
def capture():
    oldout, olderr = sys.stdout, sys.stderr
    try:
        out = [StringIO(), StringIO()]
        sys.stdout, sys.stderr = out
        yield out
    finally:
        sys.stdout, sys.stderr = oldout, olderr
        out[0] = out[0].getvalue()
        out[1] = out[1].getvalue()


class MailPileUnittest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)

    @classmethod
    def setUpClass(cls):
        change_gnupg_home(os.path.join(get_mailpile_root(), 'testing', 'gpg-keyring'), 'test')
        (cls.mp, cls.session, cls.config, cls.ui) = get_shared_mailpile()
