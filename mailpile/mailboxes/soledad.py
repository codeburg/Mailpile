import mailpile
from plugins.soledad import MailpileMailbox


# Hack currently necessary as
mailpile.mailboxes.register(5, MailpileMailbox)
