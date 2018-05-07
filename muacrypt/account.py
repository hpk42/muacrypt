# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""Account management and processing of incoming / outgoing mails on a
per-account basis. """

from __future__ import unicode_literals

import os
import logging
import re
import shutil
import six
from attr import attrs, attrib
import email
import uuid
import time
from .bingpg import cached_property, BinGPG
from . import mime
from .states import States
from .recommendation import Recommendation
from .myattr import attrib_text, attrib_float
import email.utils


def parse_date_to_float(date):
    try:
        return time.mktime(email.utils.parsedate(date))
    except TypeError:
        return 0.0


def effective_date(date):
    assert isinstance(date, float)
    return min(date, time.time())


class AccountException(Exception):
    """ an exception raised during method calls on an AccountManager instance. """


@attrs
class NotInitialized(AccountException):
    msg = attrib(type=six.text_type)

    def __str__(self):
        return "AccountManager not initialized: {}".format(self.msg)


@attrs
class AccountNotFound(AccountException):
    msg = attrib(type=six.text_type)

    def __str__(self):
        return "AccountNotFound: {}".format(self.msg)


class AccountManager(object):
    """ Manage multiple accounts and route in/out messages to the appropriate account. """
    def __init__(self, dir, plugin_manager):
        """ Initialize multi-account configuration.

        :type dir: unicode
        :param dir:
             directory in which muacrypt will states state.
        :type plugin_manager: pluggy.PluginManager
        :param plugin_manager:
             a plugin manager instance with hooks registered
        """
        self.dir = dir
        self._states = States(dir)
        self.accountmanager_state = self._states.get_accountmanager_state()
        self.plugin_manager = plugin_manager

    def init(self):
        assert self.accountmanager_state.version is None
        self.accountmanager_state.set_version("0.1")

    def _ensure_init(self):
        if not self.exists():
            self.init()

    def exists(self):
        return self.accountmanager_state.version is not None

    def get_account(self, account_name="default", check=True):
        self._ensure_init()
        account = Account(self._states, account_name, plugin_manager=self.plugin_manager)
        if check and not account.exists():
            raise AccountNotFound("account {!r} not known".format(account_name))
        self.plugin_manager.hook.instantiate_account(
            plugin_manager=self.plugin_manager,
            basedir=os.path.join(self.dir, account_name)
        )
        return account

    def list_account_names(self):
        return self._states.get_account_names()

    def add_account(self, account_name="default", email_regex=None,
                    keyhandle=None, gpgbin="gpg", gpgmode="own"):
        """ add a named account to this account.

        :param account_name: name of this account
        :param email_regex: regular expression which matches all email addresses
                            belonging to this account.
        :param keyhandle: key fingerprint or uid to use for this account.
        :param gpgbin: basename of or full path to gpg binary
        :param gpgmode: "own" (default) keeps all key state inside the account
                        directory under the account.  "system" will states keys
                        in the user's system gnupg keyring.
        """
        account = self.get_account(account_name, check=False)
        assert not account.exists()
        if email_regex is None:
            email_regex = '.*'
        account.create(account_name, email_regex=email_regex, keyhandle=keyhandle,
                       gpgbin=gpgbin, gpgmode=gpgmode)
        return account

    def mod_account(self, account_name="default", email_regex=None,
                    keyhandle=None, gpgbin=None, prefer_encrypt=None):
        """ modify a named account.

        All arguments are optional: if they are not specified the underlying
        account setting remains unchanged.

        :param account_name: name of this account
        :param email_regex: regular expression which matches all email addresses
                            belonging to this account.
        :param keyhandle: key fingerprint or uid to use for this account.
        :param gpgbin: basename of or full path to gpg binary
        :param prefer_encrypt: prefer_encrypt setting for this account.
        :returns: Account instance
        """
        account = self.get_account(account_name)
        changed = account.modify(
            email_regex=email_regex, keyhandle=keyhandle, gpgbin=gpgbin,
            prefer_encrypt=prefer_encrypt,
        )
        return changed, account

    def del_account(self, account_name):
        """ fully remove an account. """
        account = self.get_account(account_name)
        account.delete()

    def get_account_from_emailadr(self, emailadr, raising=False):
        """ get account for a given email address. """
        for name in self.list_account_names():
            account = self.get_account(name)
            if re.match(account.ownstate.email_regex, emailadr):
                return account
        if raising:
            raise AccountNotFound(emailadr)

    def remove(self):
        """ remove the account directory and reset this account configuration
        to empty.  You need to add accounts to reinitialize.
        """
        shutil.rmtree(self.dir, ignore_errors=True)
        self._states = States(self.dir)
        self.accountmanager_state = self._states.get_accountmanager_state()

    def make_header(self, emailadr, headername="Autocrypt: "):
        """ return an Autocrypt header line which uses our own
        key and the provided emailadr if one of our account matches it.

        :type emailadr: unicode
        :param emailadr:
            pure email address which we use as the "addr" attribute
            in the generated Autocrypt header.  An account may generate
            and send mail from multiple aliases and we advertise
            the same key across those aliases.

        :type headername: unicode
        :param headername:
            the prefix we use for the header, defaults to "Autocrypt".
            By specifying an empty string you just get the header value.

        :rtype: unicode
        :returns: Autocrypt header with prefix and value (or empty string)
        """
        if not self.list_account_names():
            raise NotInitialized("no accounts configured")
        account = self.get_account_from_emailadr(emailadr, raising=True)
        if account is None:
            return ""
        else:
            assert account.ownstate.keyhandle
            return headername + account.make_ac_header(emailadr)


class Account:
    """ An Account manages all Autocrypt settings (both own keys and
    settings as well as per-peer ones derived from Autocrypt headers).
    """

    def __init__(self, states, name, plugin_manager):
        """ shallow initializer. Call create() for initializing this
        account. exists() tells whether that has happened already. """
        assert name.isalnum(), name
        self.name = name
        self._states = states
        self.plugin_manager = plugin_manager
        self.ownstate = self._states.get_ownstate(name)

    def __repr__(self):
        return "Account(name={})".format(self.name)

    def get_peerstate(self, addr):
        routable_addr = mime.parse_email_addr(addr)
        return self._states.get_peerstate(self.name, routable_addr)

    def get_recommendation(self, addrs, reply_to_enc=False):
        assert isinstance(addrs, (list, set, tuple)), addrs
        addrs = map(mime.parse_email_addr, addrs)
        peerstates = {addr: self.get_peerstate(addr) for addr in addrs}
        return Recommendation(peerstates, self.ownstate.prefer_encrypt,
                              reply_to_enc=reply_to_enc)

    def get_peername_list(self):
        return self._states.get_peername_list(self.name)

    def create(self, name, email_regex, keyhandle, gpgbin, gpgmode):
        """ create all settings, keyrings etc for this account.

        :param name: name of this account
        :param email_regex: regular expression which matches all email addresses
                            belonging to this account.
        :param keyhandle: key fingerprint or uid to use for this account. If it is
                          None we generate a fresh Autocrypt compliant key.
        :param gpgbin: basename of or full path to gpg binary
        :param gpgmode: "own" keeps all key state inside the account
                        directory under the account.  "system" will states keys
                        in the user's system GnuPG keyring.
        """
        assert gpgmode in ("own", "system")
        self.ownstate.new_config(
            name=name,
            email_regex=email_regex,
            gpgbin=gpgbin,
            gpgmode=gpgmode,
            prefer_encrypt="nopreference"
        )
        if keyhandle is None:
            random_id = six.text_type(uuid.uuid4().hex)
            emailadr = "{}@random.muacrypt.org".format(random_id)
            keyhandle = self.bingpg.gen_secret_key(emailadr)
        else:
            keyhandle = self.bingpg.get_secret_keyhandle(keyhandle)
            if keyhandle is None:
                raise ValueError("no secret key for {!r}".format(keyhandle))
        keydata = self.bingpg.get_secret_keydata(keyhandle)
        self.ownstate.append_keygen(
            keyhandle=keyhandle, keydata=keydata,
        )

    def modify(self, email_regex=None, keyhandle=None, gpgbin=None, prefer_encrypt=None):
        kwargs = {}
        if email_regex is not None:
            kwargs["email_regex"] = email_regex
        if prefer_encrypt is not None:
            kwargs["prefer_encrypt"] = prefer_encrypt
        return self.ownstate.change_config(**kwargs)

    def delete(self):
        self._states.remove_account(self.name)

    @cached_property
    def bingpg(self):
        gpgmode = self.ownstate.gpgmode
        if gpgmode == "own":
            gpghome = self._states.get_own_gpghome(self.name)
        elif gpgmode == "system":
            gpghome = None
        else:
            gpghome = -1
        if gpghome == -1 or not self.ownstate.gpgbin:
            raise NotInitialized(
                "AccountManager directory {!r} not initialized".format(self.dir))
        return BinGPG(homedir=gpghome, gpgpath=self.ownstate.gpgbin)

    def make_ac_header(self, emailadr):
        return mime.make_ac_header_value(
            addr=emailadr,
            keydata=self.bingpg.get_public_keydata(self.ownstate.keyhandle),
            prefer_encrypt=self.ownstate.prefer_encrypt,
        )

    def exists(self):
        """ return True if the account exists. """
        return self.ownstate.is_configured()

    def export_public_key(self, keyhandle=None):
        """ return armored public key of this account or the one
        indicated by the key handle. """
        kh = keyhandle
        if kh is None:
            kh = self.ownstate.keyhandle
        return self.bingpg.get_public_keydata(kh, armor=True)

    def export_secret_key(self):
        """ return armored public key for this account. """
        return self.bingpg.get_secret_keydata(self.ownstate.keyhandle, armor=True)

    def process_incoming(self, msg):
        """ process incoming mail message and states information
        from any Autocrypt header for the From/Autocrypt peer
        which created the message.

        :type msg: email.message.Message
        :param msg: instance of a standard email Message.
        :rtype: ProcessIncomingResult
        """
        From = mime.parse_email_addr(msg["From"])
        peerstate = self.get_peerstate(From)
        msg_date = effective_date(parse_date_to_float(msg.get("Date")))
        msg_id = six.text_type(msg["Message-Id"])
        pah = self.process_autocrypt_header(msg, From, peerstate, msg_date, msg_id)
        if mime.is_encrypted(msg):
            dec_msg = self.decrypt_mime(msg).dec_msg
            gossip_pahs = self.process_gossip_headers(dec_msg, msg_date, msg_id)
            self.plugin_manager.hook.process_incoming_gossip(
                addr2pagh=gossip_pahs,
                account_key=self.ownstate.keyhandle,
                dec_msg=dec_msg
            )
        else:
            gossip_pahs = {}

        return ProcessIncomingResult(
            msg_id=msg_id,
            msg_date=msg_date,
            pah=pah,
            gossip_pahs=gossip_pahs,
            peerstate=peerstate,
            account=self,
        )

    def process_autocrypt_header(self, msg, From, peerstate, msg_date, msg_id):
        pah = mime.parse_one_ac_header_from_msg(msg, [From])
        if pah.error:
            if "no valid Autocrypt" not in pah.error:
                logging.error("{}: {}".format(msg_id, pah.error))
            keyhandle = None
        else:
            keyhandle = self._import_key(pah)
        peerstate.update_from_msg(
            msg_id=msg_id, effective_date=msg_date,
            prefer_encrypt=pah.prefer_encrypt,
            keydata=pah.keydata, keyhandle=keyhandle,
        )
        return pah

    def process_gossip_headers(self, msg, msg_date, msg_id):
        """ process gossip headers from payload mime part of mail message
        and update state information from any gossip header for the
        To or Cc recipients of the msg.

        :type msg: email.message.Message
        :param msg: decrypted message returned from decrypt_mime as dec_msg
        :rtype: ProcessIncomingResult
        """
        recipients = mime.get_target_emailadr(msg)
        processed = {}
        addr2pah = mime.get_gossip_headers_from_msg(msg)
        for recipient in recipients:
            pah = addr2pah.get(recipient)
            if pah is not None:
                peerstate = self.get_peerstate(recipient)
                keyhandle = self._import_key(pah)
                peerstate.update_from_msg_gossip(
                    msg_id=msg_id, effective_date=msg_date,
                    keydata=pah.keydata, keyhandle=keyhandle,
                )
                processed[recipient] = pah
        return processed

    def _import_key(self, pah):
        try:
            return self.bingpg.import_keydata(pah.keydata)
        except self.bingpg.InvocationFailure:
            pah.error = "failed to import key"
            return None

    def process_outgoing(self, msg):
        """ add Autocrypt header to outgoing message.
        :type msg: email.message.Message
        :param msg: outgoing message in mime format.
        :rtype: ProcessOutgoingResult
        """
        addr = mime.parse_email_addr(msg.get("From"))
        if "Autocrypt" in msg:
            added_autocrypt = None
        else:
            msg["Autocrypt"] = added_autocrypt = self.make_ac_header(addr)
        return ProcessOutgoingResult(
            msg=msg, account=self, addr=addr,
            added_autocrypt=added_autocrypt, had_autocrypt=msg["Autocrypt"]
        )

    def encrypt_mime(self, msg, toaddrs):
        """ create a new encrypted mime message.

        :type msg: email.message.Message
        :param msg: message to be encrypted
        :type toaddrs: list of e-mail addresses
        :param toaddrs: e-mail addresses to encrypt to
        :rtype: EncryptMimeResult
        """
        assert toaddrs, "requires non-empty recipient list"
        keyhandles = []
        recipient2keydata = {}
        clear_payload_msg = mime.make_content_message_from_email(msg)
        toaddrs = [mime.parse_email_addr(t) for t in toaddrs]
        for addr in toaddrs:
            peer = self.get_peerstate(addr)
            kh = peer.public_keyhandle
            assert kh, "keyhandle not found for: " + addr
            keyhandles.append(kh)
            recipient2keydata[addr] = peer.public_keydata
            value = mime.make_ac_header_value(addr, peer.public_keydata)
            clear_payload_msg.add_header('Autocrypt-Gossip', value)

        self.plugin_manager.hook.process_before_encryption(
            sender_addr=mime.parse_email_addr(msg["From"]),
            sender_keyhandle=self.ownstate.keyhandle,
            recipient2keydata=recipient2keydata,
            payload_msg=clear_payload_msg,
            _account=self,
        )

        clear_data = mime.msg2bytes(clear_payload_msg)  # .replace(b'\n', b'\r\n') TBD for RFC?
        enc_data = self.bingpg.encrypt(data=clear_data, recipients=keyhandles,
                                       text=True, signkey=self.ownstate.keyhandle)
        enc = mime.make_message('application/pgp-encrypted', payload="version: 1")
        data = mime.make_message("application/octet-stream", payload=enc_data)

        newmsg = mime.make_message("multipart/encrypted", payload=[enc, data])
        newmsg.set_param('protocol', 'application/pgp-encrypted')
        mime.transfer_non_content_headers(msg, newmsg)
        return EncryptMimeResult(enc_msg=newmsg, keyhandles=keyhandles)

    def decrypt_mime(self, msg):
        """ decrypt an encrypted mime message.

        :type msg: email.message.Message
        :param msg: message to be decrypted
        :rtype: DecryptMimeResult
        """
        assert mime.is_encrypted(msg)
        parts = msg.get_payload()
        enc_data = parts[1].get_payload().encode("ascii")
        dec, keyinfos = self.bingpg.decrypt(enc_data=enc_data)
        logging.debug("decrypted message {!r}".format(msg.get("message-id")))
        new_msg = mime.message_from_bytes(dec)
        mime.transfer_non_content_headers(msg, new_msg)
        return DecryptMimeResult(enc_msg=msg, dec_msg=new_msg, keyinfos=keyinfos)


@attrs
class DecryptMimeResult(object):
    """ Result returned from decrypt_mime() with
    'enc_msg' (encrypted message) 'dec_msg' (decrypted message)
    and 'keyinfos' (keys for which the message was encrypted).
    """
    enc_msg = attrib()
    dec_msg = attrib()
    keyinfos = attrib()


@attrs
class EncryptMimeResult(object):
    """ Result returned from encrypt_mime() with
    'msg' (encrypted message) and 'keyhandles' (list of
    public key handles used for encryption) attributes
    """
    enc_msg = attrib()
    keyhandles = attrib()


@attrs
class ProcessIncomingResult(object):
    msg_id = attrib_text()
    msg_date = attrib_float()
    peerstate = attrib()
    account = attrib()
    pah = attrib()
    gossip_pahs = attrib()


@attrs
class ProcessOutgoingResult(object):
    msg = attrib(type=email.message.Message)
    account = attrib(type=six.text_type)
    addr = attrib_text()
    added_autocrypt = attrib()
    had_autocrypt = attrib()
