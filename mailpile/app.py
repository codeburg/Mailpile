import getopt
import gettext
import locale
import os
import sys
from gettext import gettext as _

import mailpile.util
import mailpile.defaults
from mailpile.commands import COMMANDS, Action, Help, HelpSplash, Load, Rescan
from mailpile.config import ConfigManager, getLocaleDirectory
from mailpile.ui import ANSIColors, Session, UserInteraction
from mailpile.util import *

# This makes sure mailbox "plugins" get loaded... has to go somewhere?
from mailpile.mailboxes import *

# This is also a bit silly, should be somewhere else?
Help.ABOUT = mailpile.defaults.ABOUT


##[ Main ]####################################################################

def Interact(session):
    import readline
    try:
        readline.read_history_file(session.config.history_file())
    except IOError:
        pass

    # Negative history means no saving state to disk.
    history_length = session.config.sys.history_length
    if history_length >= 0:
        readline.set_history_length(history_length)
    else:
        readline.set_history_length(-history_length)

    try:
        prompt = session.ui.palette.color('mailpile> ',
                                          color=session.ui.palette.BLACK,
                                          weight=session.ui.palette.BOLD)
        while True:
            session.ui.block()
            opt = raw_input(prompt).decode('utf-8').strip()
            session.ui.unblock()
            if opt:
                if ' ' in opt:
                    opt, arg = opt.split(' ', 1)
                else:
                    arg = ''
                try:
                    session.ui.display_result(Action(session, opt, arg))
                except UsageError, e:
                    session.error(unicode(e))
                except UrlRedirectException, e:
                    session.error('Tried to redirect to: %s' % e.url)
    except EOFError:
        print

    try:
        if session.config.sys.history_length > 0:
            readline.write_history_file(session.config.history_file())
        else:
            os.remove(session.config.history_file())
    except OSError:
        pass


def Main(args):
    re.UNICODE = 1
    re.LOCALE = 1

    # Bootstrap translations until we've loaded everything else
    translation = gettext.translation("mailpile", getLocaleDirectory(),
                                      fallback=True)
    translation.install(unicode=True)

    try:
        # Create our global config manager and the default (CLI) session
        config = ConfigManager(rules=mailpile.defaults.CONFIG_RULES)
        session = Session(config)
        session.config.load(session)
        session.main = True
        session.ui = UserInteraction(config)
        if sys.stdout.isatty():
            session.ui.palette = ANSIColors()
    except AccessError, e:
        sys.stderr.write('Access denied: %s\n' % e)
        sys.exit(1)

    try:
        # Create and start (most) worker threads
        config.prepare_workers(session)

        try:
            shorta, longa = '', []
            for cls in COMMANDS:
                shortn, longn, urlpath, arglist = cls.SYNOPSIS[:4]
                if arglist:
                    if shortn:
                        shortn += ':'
                    if longn:
                        longn += '='
                if shortn:
                    shorta += shortn
                if longn:
                    longa.append(longn.replace(' ', '_'))

            opts, args = getopt.getopt(args, shorta, longa)
            for opt, arg in opts:
                Action(session, opt.replace('-', ''), arg.decode('utf-8'))
            if args:
                Action(session, args[0], ' '.join(args[1:]).decode('utf-8'))

        except (getopt.GetoptError, UsageError), e:
            session.error(e)

        if not opts and not args:
            # Create and start the rest of the threads, load the index.
            session.interactive = session.ui.interactive = True
            config.prepare_workers(session, daemons=True)
            Load(session, '').run(quiet=True)
            session.ui.display_result(HelpSplash(session, 'help', []).run())
            Interact(session)

    except KeyboardInterrupt:
        pass

    finally:
        mailpile.util.QUITTING = True
        config.stop_workers()
        if config.index:
            config.index.save_changes()
        sys.exitfunc() #force shutdown of twisted reactor

if __name__ == "__main__":
    Main(sys.argv[1:])
