import mailpile.plugins
from mailpile.vcard import VCardLine
from mailpile.commands import Command
from mailpile.mailutils import Email

##[ Commands ]################################################################

VCARD_CRYPTO_POLICY = 'X-CRYPTO-POLICY'

class DiscoverCryptoAction(Command):
    def _get_keywords(self, e):
        idx = self._idx()
        mid = e.msg_mid()
        kws, snippet = idx.read_message(
            self.session,
            mid,
            e.get_msg_info(field=idx.MSG_ID),
            e.get_msg(),
            e.get_msg_size(),
            int(e.get_msg_info(field=idx.MSG_DATE), 36))
        return kws

    def _search(self, email):
        idx = self._idx()
        return idx.search(self.session, ['to:' + email, 'has:crypto', 'has:pgp'], order='date_fwd')

    def _find_policy_based_on_mails(self, mail_idxs):
        idx = self._idx()
        for mail_idx in mail_idxs.as_set():
            mail = Email(idx, mail_idx).get_msg()

            if mail.encryption_info.get('status') != 'none':
                return 'encrypt'
            if mail.signature_info.get('status') != 'none':
                return 'sign'

        return 'none'

    def _find_policy(self, email):
        mail_idxs = self._search(email)

        if mail_idxs:
            return self._find_policy_based_on_mails(mail_idxs)
        else:
            return 'none'

    def _update_vcard(self, vcard, policy):
        if 'default' == policy:
            for line in vcard.get_all(VCARD_CRYPTO_POLICY):
                vcard.remove(line.line_id)
        else:
            if len(vcard.get_all(VCARD_CRYPTO_POLICY)) > 0:
                vcard.get(VCARD_CRYPTO_POLICY).value = policy
            else:
                vcard.add(VCardLine(name=VCARD_CRYPTO_POLICY, value=policy))


class AutoDiscoverCryptoPolicy(DiscoverCryptoAction):
    SYNOPSIS = (None, 'discover_crypto_policy', None, None)
    ORDER = ('AutoDiscover', 0)

    def _set_crypto_policy(self, email, policy):
        if policy != 'none':
            vcard = self.session.config.vcards.get_vcard(email)
            if vcard:
                self._update_vcard(vcard, policy)
                self.session.ui.mark('policy for %s will be %s' % (email, policy))
            else:
                self.session.ui.mark('skipped setting policy for %s to policy,  no vcard entry found' % email)

    def _update_crypto_state(self, email):
        policy = self._find_policy(email)

        self._set_crypto_policy(email, policy)

    def command(self):
        idx = self._idx()

        for email in idx.EMAIL_IDS:
            self._update_crypto_state(email)

        return {}


class UpdateCryptoPolicyForUser(DiscoverCryptoAction):
    SYNOPSIS = (None, 'crypto_policy/set', 'crypto_policy/set', '<email addresses> none|sign|encrypt|default')
    ORDER = ('Internals', 9)
    HTTP_CALLABLE = ('POST',)

    def command(self):
        if len(self.args) != 2:
            return self._error('Please provide email address and policy!')

        email = self.args[0]
        policy = self.args[1]
        if policy not in {'none', 'sign', 'encrypt', 'default'}:
            return self._error('Policy has to be one of none|sign|encrypt|default')

        vcard = self.session.config.vcards.get_vcard(email)
        if vcard:
            self._update_vcard(vcard, policy)
            return {vcard}
        else:
            return self._error('No vcard for email %s!' % email)


class CryptoPolicyForUser(DiscoverCryptoAction):
    """ foobar """
    SYNOPSIS = (None, 'crypto_policy', 'crypto_policy', '[<emailaddresses>]')
    ORDER = ('Internals', 9)
    HTTP_CALLABLE = ('GET',)

    def command(self):
        try:
            if len(self.args) != 1:
                return self._error('Please provide a single email address!')

            email = self.args[0]

            policy_from_vcard = self._vcard_policy(email)
            if policy_from_vcard:
                return policy_from_vcard
            else:
                return self._find_policy(email)
        except:
            return {}

    def _vcard_policy(self, email):
        vcard = self.session.config.vcards.get_vcard(email)
        if vcard and len(vcard.get_all(VCARD_CRYPTO_POLICY)) > 0:
            return vcard.get(VCARD_CRYPTO_POLICY).value
        else:
            return None


mailpile.plugins.register_commands(AutoDiscoverCryptoPolicy, CryptoPolicyForUser, UpdateCryptoPolicyForUser)
