"""
All muacrypt states are managed through this module.
We follow the Kappa architecture style
(http://milinda.pathirage.org/kappa-architecture.com/)
i.e. all state changes are added to append-only chains and they contain
immutable entries that may cross-reference other entries (even
from other chains). The linking between entries is done using
crytographic hashes.
"""
from __future__ import unicode_literals, print_function

import os
import logging
from .chainstore import HeadTracker, BlockService, Chain
from .myattr import (
    v, attr, attrs, attrib, attrib_text, attrib_bytes,
    attrib_bytes_or_none, attrib_text_or_none, attrib_float,
)

# ==================================================
# States
# =================================================


class States:
    """ Persisting Muacrypt and per-account settings."""
    _account_pat = "."
    _own_pat = "own:{id}"
    _oob_pat = "oob:{id}"
    _peer_pat = "peer:{id}:{addr}"

    def __init__(self, dirpath):
        self.dirpath = dirpath
        blockdir = os.path.join(dirpath, "blocks")
        if not os.path.exists(blockdir):
            os.makedirs(blockdir)
        self._heads = HeadTracker(os.path.join(dirpath, "heads"))
        self._blocks = BlockService(blockdir)

    def _makechain(self, headname):
        return Chain(self._blocks, self._heads, headname)

    def get_accountmanager_state(self):
        chain = self._makechain(self._account_pat)
        return AccountManagerState(chain)

    def get_account_names(self):
        return sorted(self._heads._getheads(prefix=self._own_pat.format(id="")))

    def get_num_peers(self, account):
        return len(self.get_peername_list())

    def get_peername_list(self, account_name):
        prefix = self._peer_pat.format(id=account_name, addr="")
        return sorted(self._heads._getheads(prefix=prefix))

    def get_peerstate(self, account_name, addr):
        head_name = self._peer_pat.format(id=account_name, addr=addr)
        chain = self._makechain(head_name)
        return PeerState(chain)

    def get_ownstate(self, account_name):
        head_name = self._own_pat.format(id=account_name)
        chain = self._makechain(head_name)
        return OwnState(chain)

    def get_own_gpghome(self, account_name):
        return os.path.join(self.dirpath, "gpg", account_name)

    def get_oobstate(self, account_name):
        head_name = self._oob_pat.format(id=account_name)
        chain = self._makechain(head_name)
        return OOBState(chain)

    def remove_account(self, account_name):
        def match_account(key, value):
            l = key.split(":", 2)
            if l[0] in ("own", "peer") and l[1] == account_name:
                return True
        self._heads.remove_if(match_account)

# ===========================================================
# PeerState for keeping track of incoming messages per peer
# ===========================================================


@attr.s
class MsgEntry(object):
    TAG = "msg"
    msg_id = attrib_text()
    msg_date = attrib_float()
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    keydata = attrib_bytes()
    keyhandle = attrib_text()


@attr.s
class MsgGossipEntry(object):
    TAG = "mge"
    msg_id = attrib_text()
    msg_date = attrib_float()
    keydata = attrib_bytes()
    keyhandle = attrib_text()


@attrs
class PeerState(object):
    """Synthesized Autocrypt state from parsing messages from a peer. """
    _chain = attrib()

    def __str__(self):
        return "PeerState addr={addr} key={keyhandle}".format(
            addr=self.addr, keyhandle=self.public_keyhandle
        )

    @property
    def addr(self):
        return self._chain.name.split(":", 2)[-1]

    @property
    def last_seen(self):
        return getattr(self._latest_msg_entry(), "msg_date", 0.0)

    @property
    def autocrypt_timestamp(self):
        return getattr(self._latest_ac_entry(), "msg_date", 0.0)

    @property
    def public_keyhandle(self):
        return getattr(self.entry_for_encryption(), "keyhandle", '')

    @property
    def public_keydata(self):
        return getattr(self.entry_for_encryption(), "keydata", b'')

    def has_direct_key(self):
        return bool(getattr(self._latest_ac_entry(), "keyhandle", ''))

    def entry_for_encryption(self):
        direct = self._latest_ac_entry()
        # TODO: perform propper checks on usability of ac entry here
        if getattr(direct, "keyhandle", None):
            return direct
        else:
            return self.latest_gossip_entry()

    @property
    def prefer_encrypt(self):
        return getattr(self.entry_for_encryption(), "prefer_encrypt", '')

    def _latest_ac_entry(self):
        """ Return latest message with Autocrypt header. """
        for entry in self._chain.iter_entries(MsgEntry):
            if entry.keydata:
                return entry

    def latest_gossip_entry(self):
        """ Return latest gossip entry. """
        return self._chain.latest_entry_of(MsgGossipEntry)

    def _latest_msg_entry(self):
        """ Return latest message with or without Autocrypt header. """
        return self._chain.latest_entry_of(MsgEntry)

    def has_message(self, msg_id):
        return self.get_message_entry(msg_id) is not None

    def get_message_entry(self, msg_id, class_=MsgEntry):
        # XXX make this less expensive
        for entry in self._chain.iter_entries(class_):
            if entry.msg_id == msg_id:
                return entry

    # methods which modify/add state
    def update_from_msg(self, msg_id, effective_date, prefer_encrypt,
                        keydata, keyhandle):
        if effective_date < self.autocrypt_timestamp:
            return
        entry = self.get_message_entry(msg_id)
        if entry is not None:
            if (entry.msg_date == effective_date and
                    entry.keydata == keydata and
                    entry.keyhandle == keyhandle and
                    entry.prefer_encrypt == prefer_encrypt):
                return

        if not keydata:
            if effective_date > self.last_seen:
                self._append_noac_entry(
                    msg_id=msg_id, msg_date=effective_date,
                )
                logging.debug("append noac %s", msg_id)
            return

        self._append_ac_entry(
            msg_id=msg_id, msg_date=effective_date,
            prefer_encrypt=prefer_encrypt,
            keydata=keydata or b'', keyhandle=keyhandle or '',
        )

    def update_from_msg_gossip(self, msg_id, effective_date, keydata, keyhandle):
        if effective_date < self.autocrypt_timestamp:
            return
        assert keydata
        entry = self.get_message_entry(msg_id, class_=MsgGossipEntry)
        if entry is not None:
            if (entry.msg_date == effective_date and
                    entry.keydata == keydata and
                    entry.keyhandle == keyhandle):
                return
        self._append_ac_gossip_entry(
            msg_id=msg_id, msg_date=effective_date,
            keydata=keydata, keyhandle=keyhandle,
        )

    def _append_ac_entry(self, msg_id, msg_date, prefer_encrypt, keydata, keyhandle):
        """append an Autocrypt message entry. """
        self._chain.append_entry(MsgEntry(
            msg_id=msg_id, msg_date=msg_date, prefer_encrypt=prefer_encrypt,
            keydata=keydata, keyhandle=keyhandle))

    def _append_ac_gossip_entry(self, msg_id, msg_date, keydata, keyhandle):
        """append an Autocrypt gossip entry. """
        self._chain.append_entry(MsgGossipEntry(
            msg_id=msg_id, msg_date=msg_date,
            keydata=keydata, keyhandle=keyhandle))

    def _append_noac_entry(self, msg_id, msg_date):
        """append a non-Autocrypt message entry. """
        self._chain.append_entry(MsgEntry(
            msg_id=msg_id, msg_date=msg_date,
            prefer_encrypt="nopreference", keyhandle="", keydata=b""
        ))


# ===========================================================
# OwnState keeps track of own crypto settings
# ===========================================================

def config_property(name):
    def get(self):
        return getattr(self._latest_config(), name)
    return property(get)


@attr.s
class KeygenEntry(object):
    TAG = "keygen"
    keydata = attrib_bytes_or_none()
    keyhandle = attrib_text_or_none()


def convert_bytes(x):
    if hasattr(x, "decode"):
        return x.decode("ascii")
    return x


@attr.s
class OwnConfigEntry(object):
    TAG = "cfg"
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']), converter=convert_bytes)
    name = attrib_text()
    email_regex = attrib_text()
    gpgmode = attrib(validator=v.in_(['system', 'own']))
    gpgbin = attrib_text()


@attrs
class OwnState(object):
    """Synthesized own state for an account. """
    _chain = attrib()

    def __str__(self):
        return "OwnState key={}".format(self.keyhandle)

    name = config_property("name")
    email_regex = config_property("email_regex")
    gpgmode = config_property("gpgmode")
    gpgbin = config_property("gpgbin")
    prefer_encrypt = config_property("prefer_encrypt")

    @property
    def keyhandle(self):
        return self._latest_keygen().keyhandle

    def exists(self):
        return self.name

    def _latest_keygen(self):
        return self._chain.latest_entry_of(KeygenEntry)

    def _latest_config(self):
        return self._chain.latest_entry_of(OwnConfigEntry)

    # methods which modify/add state
    def new_config(self, name, prefer_encrypt, email_regex, gpgmode, gpgbin):
        self._chain.append_entry(OwnConfigEntry(
            name=name, prefer_encrypt=prefer_encrypt, email_regex=email_regex,
            gpgmode=gpgmode, gpgbin=gpgbin,
        ))

    def change_config(self, **kwargs):
        entry = self._latest_config()
        new_entry = attr.evolve(entry, **kwargs)
        if new_entry != entry:
            self._chain.append_entry(new_entry)
            return True

    def append_keygen(self, keydata, keyhandle):
        self._chain.append_entry(KeygenEntry(
            keydata=keydata,
            keyhandle=keyhandle
        ))

    def is_configured(self):
        return self._latest_config() and self._latest_keygen()


# ===========================================================
# OOBChain keeps track of out-of-band verifications
# ===========================================================

@attr.s
class VerificationEntry(object):
    TAG = "oobverify"
    addr = attrib_text()
    public_keydata = attrib_bytes()
    origin = attrib(validator=v.in_(["self", "peer"]))


@attrs
class OOBState(object):
    """Synthesized Out of Band verification state for an account. """
    _chain = attrib()

    def get_verification(self, addr):
        for entry in self._chain.iter_entries(VerificationEntry):
            if addr == entry.addr:
                return entry

    def append_self_verification(self, addr, public_keydata):
        self._chain.append_entry(VerificationEntry(
            addr=addr,
            public_keydata=public_keydata,
            origin="self",
        ))

    def append_peer_verification(self, addr, public_keydata):
        self._chain.append_entry(VerificationEntry(
            addr=addr,
            public_keydata=public_keydata,
            origin="peer",
        ))


# ===========================================================
# AccountManagerState keeps track of account modifications
# ===========================================================

@attr.s
class AConfigEntry(object):
    TAG = "acfg"
    version = attrib_text()


@attrs
class AccountManagerState(object):
    """Synthesized AccountManagerState. """
    _chain = attrib()

    def _latest_config(self):
        return self._chain.latest_entry_of(AConfigEntry)

    @property
    def version(self):
        return getattr(self._latest_config(), "version", None)

    def __str__(self):
        return "AccountManagerState version={version}".format(version=self.version)

    def set_version(self, version):
        assert not self._latest_config()
        self._chain.append_entry(AConfigEntry(version=version))
