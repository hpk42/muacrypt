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
import uuid
from copy import deepcopy
from .bingpg import cached_property, BinGPG
from contextlib import contextmanager
from base64 import b64decode
from . import mime
from email.utils import parsedate


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
        except:
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


class IdentityConfig(PersistentAttrMixin):
    uuid = persistent_property("uuid", six.text_type)
    name = persistent_property("name", six.text_type)
    email_regex = persistent_property("email_regex", six.text_type)
    gpgmode = persistent_property("gpgmode", six.text_type, ["system", "own"])
    gpgbin = persistent_property("gpgbin", six.text_type)
    own_keyhandle = persistent_property("own_keyhandle", six.text_type)
    prefer_encrypt = persistent_property("prefer_encrypt", six.text_type,
                                         ["nopreference", "mutual"])
    peers = persistent_property("peers", dict)

    def __repr__(self):
        return "IdentityConfig(name={}, own_keyhandle={}, numpeers={})".format(
            self.name, self.own_keyhandle, len(self.peers))

    def exists(self):
        return self.uuid


class AccountException(Exception):
    """ an exception raised during method calls on an Account instance. """


class NotInitialized(AccountException):
    def __init__(self, msg):
        super(NotInitialized, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return "Account not initialized: {}".format(self.msg)


class IdentityNotFound(AccountException):
    def __init__(self, msg):
        super(IdentityNotFound, self).__init__(msg)
        self.msg = msg

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
        :type gpgpath: unicode
        :param gpgpath:
            If the path contains path separators and points
            to an existing file we use it directly.
            If it contains no path separators, we lookup
            the path to the binary under the system's PATH.
            If we can not determine an eventual binary
            we raise ValueError.
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
                     keyhandle=None, gpgbin=None, prefer_encrypt=None):
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

    def get_identity_from_emailadr(self, emailadr_list, raising=False):
        """ get identity for a given email address list. """
        assert isinstance(emailadr_list, (list, tuple)), repr(emailadr_list)
        for ident in self.list_identities():
            for emailadr in emailadr_list:
                if re.match(ident.config.email_regex, emailadr):
                    return ident
        if raising:
            raise IdentityNotFound(emailadr_list)

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
        ident = self.get_identity_from_emailadr([emailadr])
        if ident is None:
            return ""
        else:
            assert ident.config.own_keyhandle
            return ident.make_ac_header(emailadr, headername=headername)

    def process_incoming(self, msg, delivto=None):
        """ process incoming mail message and store information
        from any Autocrypt header for the From/Autocrypt peer
        which created the message.

        :type msg: email.message.Message
        :param msg: instance of a standard email Message.
        :rtype: PeerInfo
        """
        if delivto is None:
            _, delivto = mime.parse_email_addr(msg.get("Delivered-To"))
            assert delivto
        ident = self.get_identity_from_emailadr([delivto])
        if ident is None:
            raise IdentityNotFound("no identity matches emails={}".format([delivto]))
        From = mime.parse_email_addr(msg["From"])[1]
        old = ident.config.peers.get(From, {})
        d = mime.parse_one_ac_header_from_msg(msg)
        date = msg.get("Date")
        if d and "addr" in d:
            if d["addr"] == From:
                if parsedate(date) >= parsedate(old.get("*date", date)):
                    d["*date"] = date
                    keydata = b64decode(d["keydata"])
                    keyhandle = ident.bingpg.import_keydata(keydata)
                    d["*keyhandle"] = keyhandle
                    with ident.config.atomic_change():
                        ident.config.peers[From] = d
                    return PeerInfo(ident, d)
        elif old:
            # we had an autocrypt header and now forget about it
            # because we got a mail which doesn't have one
            with ident.config.atomic_change():
                ident.config.peers[From] = {}

    def process_outgoing(self, msg):
        """ process outgoing mail message and add Autocrypt
        header if it doesn't already exist.

        :type msg: email.message.Message
        :param msg: instance of a standard email Message.
        :rtype: PeerInfo
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
        self.config = IdentityConfig(os.path.join(self.dir, "config.json"))

    def __repr__(self):
        return "Identity[{}]".format(self.config)

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
        with self.config.atomic_change():
            self.config.uuid = uuid.uuid4().hex
            self.config.name = name
            self.config.email_regex = email_regex
            self.config.prefer_encrypt = "nopreference"
            self.config.gpgbin = gpgbin
            self.config.gpgmode = gpgmode
            self.config.peers = {}
            if keyhandle is None:
                emailadr = "{}@uuid.autocrypt.org".format(self.config.uuid)
                keyhandle = self.bingpg.gen_secret_key(emailadr)
            else:
                keyinfos = self.bingpg.list_secret_keyinfos(keyhandle)
                for k in keyinfos:
                    is_in_uids = any(keyhandle in uid for uid in k.uids)
                    if is_in_uids or k.match(keyhandle):
                        keyhandle = k.id
                        break
                else:
                    raise ValueError("could not find secret key for {!r}, found {!r}"
                                     .format(keyhandle, keyinfos))
            self.config.own_keyhandle = keyhandle
        assert self.config.exists()

    def modify(self, email_regex=None, keyhandle=None, gpgbin=None, prefer_encrypt=None):
        with self.config.atomic_change():
            if email_regex is not None:
                self.config.email_regex = email_regex
            if prefer_encrypt is not None:
                self.config.prefer_encrypt = prefer_encrypt
            # if gpgbin is not None:
            #    self.gpgbin = gpgbin
            return self.config.has_changed()

    def delete(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    @cached_property
    def bingpg(self):
        gpgmode = self.config.gpgmode
        if gpgmode == "own":
            gpghome = os.path.join(self.dir, "gpghome")
        elif gpgmode == "system":
            gpghome = None
        else:
            gpghome = -1
        if gpghome == -1 or not self.config.gpgbin:
            raise NotInitialized(
                "Account directory {!r} not initialized".format(self.dir))
        return BinGPG(homedir=gpghome, gpgpath=self.config.gpgbin)

    def make_ac_header(self, emailadr, headername="Autocrypt: "):
        return headername + mime.make_ac_header_value(
            addr=emailadr,
            keydata=self.bingpg.get_public_keydata(self.config.own_keyhandle),
            prefer_encrypt=self.config.prefer_encrypt,
        )

    def get_peerinfo(self, emailadr):
        """ get peerinfo object for a given email address.

        :type emailadr: unicode
        :param emailadr: pure email address without any prefixes or real names.
        :rtype: PeerInfo or None
        """
        state = self.config.peers.get(emailadr)
        if state:
            return PeerInfo(self, state)

    def exists(self):
        """ return True if the identity exists. """
        return self.config.exists()

    def export_public_key(self, keyhandle=None):
        """ return armored public key of this account or the one
        indicated by the key handle. """
        kh = keyhandle
        if kh is None:
            kh = self.config.own_keyhandle
        return self.bingpg.get_public_keydata(kh, armor=True)

    def export_secret_key(self):
        """ return armored public key for this account. """
        return self.bingpg.get_secret_keydata(self.config.own_keyhandle, armor=True)


class PeerInfo:
    """ Read-Only info coming from the Parsed Autocrypt header from
    an incoming Mail from a peer. In addition to the public Autocrypt
    attributes (``addr``, ``keydata``, ``type``, ...) we process also py-autocrypt
    internal ``*date`` and ``*keyhandle`` attributes.
    """
    def __init__(self, identity, d):
        self._dict = dic = d.copy()
        self.identity = identity
        self.keyhandle = dic.pop("*keyhandle")
        self.date = dic.pop("*date")

    def __getitem__(self, name):
        return self._dict[name]

    def __setitem__(self, name, val):
        raise TypeError("setting of values not allowed")

    def __str__(self):
        d = self._dict.copy()
        return \
            "{addr}: key {keyhandle} [{bytes:d} bytes] " \
            "{attrs} from date={date}".format(
                addr=d.pop("addr"), keyhandle=self.keyhandle,
                bytes=len(d.pop("keydata")),
                date=self.date,
                attrs="; ".join(["%s=%s" % x for x in d.items()]))


class IdentityInfo:
    """ Read only information about an Identity in an account. """
    def __init__(self, name, email_regex, prefer_encrypt, keyhandle, peers, uuid):
        self.name = name
        self.email_regex = email_regex
        self.keyhandle = keyhandle or ""
        self.prefer_encrypt = prefer_encrypt
        self.uuid = uuid
        self._peers = peers

    @cached_property
    def peers(self):
        return dict((name, PeerInfo(self, self._peers[name])) for name in self._peers)

    def __str__(self):
        return "Identity(name={}, email_regex={}, keyhandle={}, num_peers={})".format(
               self.name, self.email_regex, self.keyhandle, len(self._peers))

    __repr__ = __str__
