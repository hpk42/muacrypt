# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

""" Contains Account class which offers all autocrypt related access
and manipulation methods. It also contains some internal helpers
which help to persist config and peer state.
"""
from __future__ import unicode_literals

import os
import re
import json
import shutil
import six
from attr import attrs, attrib
import uuid
import time
from copy import deepcopy
from .bingpg import cached_property, BinGPG
from contextlib import contextmanager
from base64 import b64decode
from . import mime
from .claimchain import ChainManager
import email.utils


def parse_date_to_float(date):
    return time.mktime(email.utils.parsedate(date))


def effective_date(date):
    assert isinstance(date, float)
    return min(date, time.time())


class PersistentAttrMixin(object):
    def __init__(self, path):
        self._path = path
        self._dict_old = {}

    @cached_property
    def _dict(self):
        if os.path.exists(self._path):
            with open(self._path, "r") as f:
                d = json.load(f)
        else:
            d = {}
        self._dict_old = deepcopy(d)
        return d

    # def _reload(self):
    #    try:
    #        self._property_cache.pop("_dict")
    #    except AttributeError:
    #        pass

    def has_changed(self):
        return self._dict != self._dict_old

    def _commit(self):
        if self.has_changed():
            with open(self._path, "w") as f:
                json.dump(self._dict, f)
            self._dict_old = deepcopy(self._dict)
            return True

    def exists(self):
        return os.path.exists(self._path)

    @contextmanager
    def atomic_change(self):
        # XXX allow multi-read/single-write multi-process concurrency model
        # by doing some file locking or using sqlite or something.
        try:
            yield
        except Exception:
            self._dict = deepcopy(self._dict_old)
            raise
        else:
            self._commit()


def persistent_property(name, typ, values=None):
    def get(self):
        return self._dict.setdefault(name, typ())

    def set(self, value):
        if not isinstance(value, typ):
            if not (typ == six.text_type and isinstance(value, bytes)):
                raise TypeError(value)
            value = value.decode("ascii")
        if values is not None and value not in values:
            raise ValueError("can only set to one of %r" % values)
        self._dict[name] = value

    return property(get, set)


class AccountConfig(PersistentAttrMixin):
    version = persistent_property("version", six.text_type)


class AccountException(Exception):
    """ an exception raised during method calls on an Account instance. """


@attrs
class NotInitialized(AccountException):
    msg = attrib(type=six.text_type)

    def __str__(self):
        return "Account not initialized: {}".format(self.msg)


@attrs
class IdentityNotFound(AccountException):
    msg = attrib(type=six.text_type)

    def __str__(self):
        return "IdentityNotFound: {}".format(self.msg)


class Account(object):
    """ Autocrypt Account class which allows to manipulate autocrypt
    configuration and state for use from mail processing agents.
    Autocrypt uses a standalone GPG managed keyring and persists its
    config to a default app-config location.

    You can init an account and then use it to generate Autocrypt
    headers and process incoming mails to discover and memorize
    a peer's Autocrypt headers.
    """

    def __init__(self, dir):
        """ Initialize the account configuration and internally
        used gpggrapper.

        :type dir: unicode
        :param dir:
             directory in which autocrypt will store all state
             including a gpg-managed keyring.
        """
        self.dir = dir
        self.config = AccountConfig(os.path.join(self.dir, "config.json"))
        self._idpath = os.path.join(self.dir, "id")

    def init(self):
        assert not self.config.exists()
        with self.config.atomic_change():
            self.config.version = "0.1"
        os.mkdir(self._idpath)

    def exists(self):
        return self.config.exists()

    def get_identity(self, id_name="default", check=True):
        assert id_name.isalnum(), id_name
        ident = Identity(os.path.join(self._idpath, id_name))
        if check and not ident.exists():
            raise IdentityNotFound("identity {!r} not known".format(id_name))
        return ident

    def list_identity_names(self):
        try:
            return [x for x in os.listdir(self._idpath) if x[0] != "."]
        except OSError:
            return []

    def list_identities(self):
        return [self.get_identity(x) for x in self.list_identity_names()]

    def add_identity(self, id_name="default", email_regex=".*",
                     keyhandle=None, gpgbin="gpg", gpgmode="own"):
        """ add a named identity to this account.

        :param id_name: name of this identity
        :param email_regex: regular expression which matches all email addresses
                            belonging to this identity.
        :param keyhandle: key fingerprint or uid to use for this identity.
        :param gpgbin: basename of or full path to gpg binary
        :param gpgmode: "own" (default) keeps all key state inside the identity
                        directory under the account.  "system" will store keys
                        in the user's system gnupg keyring.
        """
        ident = self.get_identity(id_name, check=False)
        assert not ident.exists()
        ident.create(id_name, email_regex=email_regex, keyhandle=keyhandle,
                     gpgbin=gpgbin, gpgmode=gpgmode)
        return ident

    def mod_identity(self, id_name="default", email_regex=None,
                     keyhandle=None, gpgbin=None, prefer_encrypt='nopreference'):
        """ modify a named identity.

        All arguments are optional: if they are not specified the underlying
        identity setting remains unchanged.

        :param id_name: name of this identity
        :param email_regex: regular expression which matches all email addresses
                            belonging to this identity.
        :param keyhandle: key fingerprint or uid to use for this identity.
        :param gpgbin: basename of or full path to gpg binary
        :param gpgmode: "own" keeps all key state inside the identity
                        directory under the account.  "system" will store keys
                        in the user's system gnupg keyring.
        :returns: Identity instance
        """
        ident = self.get_identity(id_name)
        changed = ident.modify(
            email_regex=email_regex, keyhandle=keyhandle, gpgbin=gpgbin,
            prefer_encrypt=prefer_encrypt,
        )
        return changed, ident

    def del_identity(self, id_name):
        """ fully remove an identity. """
        ident = self.get_identity(id_name)
        ident.delete()

    def get_identity_from_emailadr(self, emailadr, raising=False):
        """ get identity for a given email address. """
        for ident in self.list_identities():
            if re.match(ident.ownstate.email_regex, emailadr):
                return ident
        if raising:
            raise IdentityNotFound(emailadr)

    def remove(self):
        """ remove the account directory and reset this account configuration
        to empty.  You need to add identities to reinitialize.
        """
        shutil.rmtree(self.dir, ignore_errors=True)

    def make_header(self, emailadr, headername="Autocrypt: "):
        """ return an Autocrypt header line which uses our own
        key and the provided emailadr if this account is managing
        the emailadr.

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
        :returns: autocrypt header with prefix and value (or empty string)
        """
        if not self.list_identity_names():
            raise NotInitialized("no identities configured")
        ident = self.get_identity_from_emailadr(emailadr)
        if ident is None:
            return ""
        else:
            assert ident.ownstate.keyhandle
            return ident.make_ac_header(emailadr, headername=headername)

    def process_incoming(self, msg, delivto=None):
        """ process incoming mail message and store information
        from any Autocrypt header for the From/Autocrypt peer
        which created the message.

        :type msg: email.message.Message
        :param msg: instance of a standard email Message.
        :rtype: PeerState
        """
        if delivto is None:
            _, delivto = mime.parse_email_addr(msg.get("Delivered-To"))
            assert delivto
        ident = self.get_identity_from_emailadr(delivto)
        if ident is None:
            raise IdentityNotFound("no identity matches emails={}".format([delivto]))
        From = mime.parse_email_addr(msg["From"])[1]
        peerstate = ident.get_peerstate(From)
        peerchain = peerstate.peerchain

        msg_date = effective_date(parse_date_to_float(msg.get("Date")))
        msg_id = six.text_type(msg["Message-Id"])
        d = mime.parse_one_ac_header_from_msg(msg)
        if d.get("addr") != From:
            d = {}
        if d:
            if msg_date >= peerstate.autocrypt_timestamp:
                keydata = b64decode(d["keydata"])
                keyhandle = ident.bingpg.import_keydata(keydata)
                peerchain.append_ac_entry(
                    msg_id=msg_id, msg_date=msg_date,
                    prefer_encrypt=d["prefer-encrypt"],
                    keydata=keydata, keyhandle=keyhandle
                )
        else:
            if msg_date > peerstate.last_seen:
                peerchain.append_noac_entry(
                    msg_id=msg_id, msg_date=msg_date
                )

        return ProcessIncomingResult(
            msgid=msg_id,
            autocrypt_header=d,
            peerstate=peerstate,
            identity=ident
        )

    def process_outgoing(self, msg):
        """ process outgoing mail message and add Autocrypt
        header if it doesn't already exist.

        :type msg: email.message.Message
        :param msg: instance of a standard email Message.
        :rtype: PeerState
        """
        from .cmdline_utils import log_info
        _, addr = mime.parse_email_addr(msg["From"])
        if "Autocrypt" not in msg:
            h = self.make_header(addr, headername="")
            if not h:
                log_info("no identity associated with {}".format(addr))
            else:
                msg["Autocrypt"] = h
                log_info("Autocrypt header set for {!r}".format(addr))
        else:
            log_info("Found existing Autocrypt: {}...".format(msg["Autocrypt"][:35]))
        return msg, addr


class Identity:
    """ An Identity manages all Autocrypt settings and keys for a peer and stores
    it in a directory. Call create() for initializing settings."""
    def __init__(self, dir):
        self.dir = dir
        self.chain_manager = ChainManager(dir)
        self.ownstate = OwnState(self.chain_manager.get_ownchain())

    def __repr__(self):
        return "Identity(name={})".format(self.ownstate.name)

    def get_peerstate(self, addr):
        peerchain = self.chain_manager.get_peerchain(addr)
        return PeerState(peerchain)

    def get_peername_list(self):
        return self.chain_manager.get_peername_list()

    def create(self, name, email_regex, keyhandle, gpgbin, gpgmode):
        """ create all settings, keyrings etc for this identity.

        :param name: name of this identity
        :param email_regex: regular expression which matches all email addresses
                            belonging to this identity.
        :param keyhandle: key fingerprint or uid to use for this identity. If it is
                          None we generate a fresh Autocrypt compliant key.
        :param gpgbin: basename of or full path to gpg binary
        :param gpgmode: "own" keeps all key state inside the identity
                        directory under the account.  "system" will store keys
                        in the user's system GnuPG keyring.
        """
        assert gpgmode in ("own", "system")
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
        self.ownstate.ownchain.new_config(
            uuid=six.text_type(uuid.uuid4().hex),
            name=name,
            email_regex=email_regex,
            gpgbin=gpgbin,
            gpgmode=gpgmode,
            prefer_encrypt="nopreference"
        )
        if keyhandle is None:
            emailadr = "{}@uuid.autocrypt.org".format(self.ownstate.uuid)
            keyhandle = self.bingpg.gen_secret_key(emailadr)
        else:
            keyhandle = self.bingpg.get_secret_keyhandle(keyhandle)
            if keyhandle is None:
                raise ValueError("no secret key for {!r}".format(keyhandle))
        keydata = self.bingpg.get_secret_keydata(keyhandle)
        self.ownstate.ownchain.append_keygen(
            entry_date=time.time(), keyhandle=keyhandle,
            keydata=keydata,
        )

    def modify(self, email_regex=None, keyhandle=None, gpgbin=None, prefer_encrypt=None):
        kwargs = {}
        if email_regex is not None:
            kwargs["email_regex"] = email_regex
        if prefer_encrypt is not None:
            kwargs["prefer_encrypt"] = prefer_encrypt
        return self.ownstate.ownchain.change_config(**kwargs)

    def delete(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    @cached_property
    def bingpg(self):
        gpgmode = self.ownstate.gpgmode
        if gpgmode == "own":
            gpghome = os.path.join(self.dir, "gpghome")
        elif gpgmode == "system":
            gpghome = None
        else:
            gpghome = -1
        if gpghome == -1 or not self.ownstate.gpgbin:
            raise NotInitialized(
                "Account directory {!r} not initialized".format(self.dir))
        return BinGPG(homedir=gpghome, gpgpath=self.ownstate.gpgbin)

    def make_ac_header(self, emailadr, headername="Autocrypt: "):
        return headername + mime.make_ac_header_value(
            addr=emailadr,
            keydata=self.bingpg.get_public_keydata(self.ownstate.keyhandle),
            prefer_encrypt=self.ownstate.prefer_encrypt,
        )

    def exists(self):
        """ return True if the identity exists. """
        return self.ownstate.ownchain.latest_config() and \
            self.ownstate.ownchain.latest_keygen()

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


def config_property(name):
    def get(self):
        return getattr(self.ownchain.latest_config(), name)
    return property(get)


@attrs
class OwnState(object):
    """ Read-Only synthesized view on OwnState which contains
    our own account state. """
    ownchain = attrib()

    def __str__(self):
        return "OwnState key={keyhandle}".format(
            keyhandle=self.keyhandle,
        )

    uuid = config_property("uuid")
    name = config_property("name")
    email_regex = config_property("email_regex")
    gpgmode = config_property("gpgmode")
    gpgbin = config_property("gpgbin")
    prefer_encrypt = config_property("prefer_encrypt")

    @property
    def keyhandle(self):
        return self.ownchain.latest_keygen().keyhandle

    def exists(self):
        return self.uuid


@attrs
class PeerState(object):
    """ Read-Only synthesized view on PeerChains which link all
    message parsing results for a given peer. """
    peerchain = attrib()

    def __str__(self):
        return "PeerState addr={addr} key={keyhandle}".format(
            addr=self.addr, keyhandle=self.public_keyhandle
        )

    @property
    def addr(self):
        return self.peerchain.ident

    @property
    def last_seen(self):
        return getattr(self.peerchain.latest_msg_entry(), "msg_date", 0.0)

    @property
    def autocrypt_timestamp(self):
        return getattr(self.peerchain.latest_ac_entry(), "msg_date", 0.0)

    @property
    def public_keyhandle(self):
        return getattr(self.peerchain.latest_ac_entry(), "keyhandle", None)

    @property
    def public_keydata(self):
        return getattr(self.peerchain.latest_ac_entry(), "keydata", None)


@attrs
class ProcessIncomingResult(object):
    msgid = attrib(type=six.text_type)
    peerstate = attrib(type=PeerState)
    identity = attrib(type=six.text_type)
    autocrypt_header = attrib(type=six.text_type)
