"""
Storage layer which mainly provides the Store class through which
all application state is persistet.  The Store uses
Kappa architecture http://milinda.pathirage.org/kappa-architecture.com/
i.e. all changes are added to append-only logs ("chains") and they contain
entries ("claims") that may cross-reference each other. The linking is done
using crytographic hashes.  The storage works by creating and accessing
immutable blocks through the BlockService. The HeadTracker keeps track
of named "heads" which can be queried through the Store class.

Both the current BlockService and the HeadTracker use the
file system for persistent storage.
"""

from __future__ import unicode_literals
from __future__ import print_function

import os
from . import mime
from .storage_fs import HeadTracker, BlockService
from pprint import pprint
from .myattr import (
    v, attr, attrs, attrib, attrib_text, attrib_text_or_none,
    attrib_bytes_or_none, attrib_float,
)

# ==================================================
# Store
# =================================================


class Store:
    """ Persisting configuration, identity and
     per-identity Autocrypt settings."""

    _account_pat = "."
    _own_pat = "own:{id}"
    _peer_pat = "peer:{id}:{addr}"

    def __init__(self, dirpath):
        self.dirpath = dirpath
        blockdir = os.path.join(dirpath, "blocks")
        if not os.path.exists(blockdir):
            os.makedirs(blockdir)
        self.heads = HeadTracker(os.path.join(dirpath, "heads"))
        self.blocks = BlockService(blockdir)

    def get_accountchain(self):
        return AccountChain(self.blocks, self.heads, self._account_pat)

    def get_accountstate(self):
        return AccountState(self.get_accountchain())

    def get_identity_names(self):
        return sorted(self.heads._getheads(prefix=self._own_pat.format(id="")))

    def get_num_peers(self, ident):
        return len(self.get_peername_list())

    def get_peername_list(self, id_name):
        prefix = self._peer_pat.format(id=id_name, addr="")
        return sorted(self.heads._getheads(prefix=prefix))

    def get_peerchain(self, id_name, addr):
        # XXX encode addr?
        assert addr.encode("ascii"), addr
        head_name = self._peer_pat.format(id=id_name, addr=addr)
        return PeerChain(self.blocks, self.heads, head_name)

    def get_peerstate(self, id_name, addr):
        return PeerState(self.get_peerchain(id_name, addr))

    def get_ownchain(self, id_name):
        head_name = self._own_pat.format(id=id_name)
        return OwnChain(self.blocks, self.heads, head_name)

    def get_ownstate(self, id_name):
        return OwnState(self.get_ownchain(id_name))

    def get_own_gpghome(self, id_name):
        return os.path.join(self.dirpath, "gpg", id_name)

    def remove_identity(self, id_name):
        def match_ident(key, value):
            l = key.split(":", 2)
            if l[0] in ("own", "peer") and l[1] == id_name:
                return True
        self.heads.remove_if(match_ident)


# ===========================================================
# Chain base classes and helpers
# ===========================================================

def config_property(name):
    def get(self):
        return getattr(self.ownchain.latest_config(), name)
    return property(get)


class EntryBase(object):
    pass


class ChainBase(object):
    """ A Chain maintains an append-only log where each entry
    in the chain has its own content-based address so that chains
    can cross-reference entries within each other.  Each entry in a chain
    carries a timestamp and a parent CID (block hash) and type-specific
    extra data.
    """

    def __init__(self, blockservice, headtracker, ident):
        self._bs = blockservice
        self._ht = headtracker
        self.ident = ident

    def dump(self):
        l = list(self.get_head_block())
        for x in reversed(l):
            pprint("{} {}: {}".format(x.timestamp, x.type, shortrepr(x.args)))

    def is_empty(self):
        return not self.get_head_block()

    def append_block(self, type, args):
        head = self.get_head_block()
        if head:
            head = head.cid
        block = self._bs.store_block(type, args, parent=head)
        self._ht.upsert(self.ident, block.cid)
        return block

    def append_entry(self, entry):
        assert isinstance(entry, EntryBase)
        args = attr.astuple(entry)
        return self.append_block(entry.TAG, args)

    def get_head_block(self):
        head_cid = self._ht.get_head_cid(self.ident)
        if head_cid:
            return self._bs.get_block(head_cid)

    def iter_blocks(self, type=None):
        """ yields blocks from head to root for this chain. """
        head_block = self.get_head_block()
        if head_block:
            for x in head_block:
                if type is None or x.type == type:
                    yield x

    def iter_entries(self, types):
        if not isinstance(types, (list, tuple)):
            tags = {types.TAG: types}
        else:
            tags = dict((x.TAG, x) for x in types)
        for block in self.iter_blocks():
            if block and block.type in tags:
                yield tags[block.type](*block.args)

    def latest_entry_of(self, entryclass):
        for entry in self.iter_entries(entryclass):
            return entry

    def num_blocks(self):
        return len(list(self.iter_blocks()))


class Chain(ChainBase):
    def add_genesis(self, keydata):
        assert not self.get_head_block(), "already have a genesis block"
        assert isinstance(keydata, bytes)
        ascii_keydata = mime.encode_binary_keydata(keydata)
        self.append_block("genesis", [ascii_keydata])

    def get_genesis_block(self):
        head = self.get_head_block()
        block = head.get_last_parent()
        assert block.type == "genesis"
        return block

    def add_oob_verify(self, email, cid):
        assert self.get_head_block()
        self.append_block("oob_verify", [email, cid])

    def is_oob_verified_block(self, cid):
        for block in self.iter_blocks(type="oob_verify"):
            email, _ = block.args
            head_cid = self._ht.get_head_cid(ident=email)
            head_block = self._bs.get_block(head_cid)
            if head_block.contains_cid(cid):
                return True


def shortrepr(obj):
    r = repr(obj)
    if len(r) > 50:
        r = r[:23] + "..." + r[-23:]
    return r


# ===========================================================
# PeerChains for keeping track of incoming messages per peer
# ===========================================================

@attr.s
class MsgEntryAC(EntryBase):
    TAG = "msgac"
    msg_id = attrib_text()
    msg_date = attrib_float()
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    keydata = attrib_bytes_or_none()
    keyhandle = attrib_text_or_none()


@attr.s
class MsgEntryNOAC(EntryBase):
    TAG = "msgno"
    msg_id = attrib_text()
    msg_date = attrib_float()


class PeerChain(ChainBase):
    def latest_ac_entry(self):
        """ Return latest message with Autocrypt header. """
        return self.latest_entry_of(MsgEntryAC)

    def latest_msg_entry(self):
        """ Return latest message with or without Autocrypt header. """
        return self.latest_entry_of((MsgEntryAC, MsgEntryNOAC))

    def append_ac_entry(self, **kwargs):
        """append an Autocrypt message entry. """
        entry = MsgEntryAC(**kwargs)
        return self.append_entry(entry)

    def append_noac_entry(self, **kwargs):
        """append a non-Autocrypt message entry. """
        entry = MsgEntryNOAC(**kwargs)
        return self.append_entry(entry)


# ===========================================
# OwnChain keeps track of own crypto settings
# ===========================================

@attr.s
class KeygenEntry(EntryBase):
    TAG = "keygen"
    entry_date = attrib_float()
    keydata = attrib_bytes_or_none()
    keyhandle = attrib_text_or_none()


@attr.s
class OwnConfigEntry(EntryBase):
    TAG = "cfg"
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    uuid = attrib_text()
    name = attrib_text()
    email_regex = attrib_text()
    gpgmode = attrib(validator=v.in_(['system', 'own']))
    gpgbin = attrib_text()


class OwnChain(ChainBase):
    def append_keygen(self, **kwargs):
        return self.append_entry(KeygenEntry(**kwargs))

    def latest_keygen(self):
        return self.latest_entry_of(KeygenEntry)

    def latest_config(self):
        return self.latest_entry_of(OwnConfigEntry)

    def new_config(self, name, prefer_encrypt, email_regex, gpgmode, gpgbin, uuid):
        self.append_entry(OwnConfigEntry(
            name=name, prefer_encrypt=prefer_encrypt, email_regex=email_regex,
            gpgmode=gpgmode, gpgbin=gpgbin, uuid=uuid,
        ))

    def change_config(self, **kwargs):
        entry = self.latest_config()
        new_entry = attr.evolve(entry, **kwargs)
        if new_entry != entry:
            self.append_entry(new_entry)
            return True


# =================================================
# AccountChain keeps track of account modifications
# =================================================

@attr.s
class AConfigEntry(EntryBase):
    TAG = "acfg"
    version = attrib_text()


class AccountChain(ChainBase):
    def set_version(self, version):
        assert not self.latest_config()
        return self.append_entry(AConfigEntry(version=version))

    def latest_config(self):
        return self.latest_entry_of(AConfigEntry)


@attrs
class AccountState(object):
    """ Read-Only synthesized AccountState view. """
    accountchain = attrib()

    @property
    def version(self):
        return getattr(self.accountchain.latest_config(), "version", None)

    def __str__(self):
        return "AccountState version={version}".format(version=self.version)


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
        return self.peerchain.ident.split(":", 2)[-1]

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
