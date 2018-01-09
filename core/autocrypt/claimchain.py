# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""
Basic ClaimChain implementation.

Each claimchain is associated with an externally provided identifier which is,
however, not part of the claimchain itself.  We presume each claimchain
instance relates either to an own account or to a remote peer (email address),
both of which are represented through a unique identifier.

The storage infrastructure for claimchains works by creating and accessing
immutable blocks through the BlockService. Each block serves as a ClaimChain
entry which is conceptually an append-only log.  The current head (last item
of the log) associated with each identifier is obtained and managed through
a HeadTracker instance.  Both the BlockService and the HeadTracker use the
file system for persistent storage.  If we could use IPFS libs (see below todo)
and a subset of their infrastructure we might also use a distributed global
BlockService without much coding change.  To protect blocks from public reading
we can add symmetric encryption and transfer the according secret in-band as well.

Each claimchain instance starts with a "genesis" entry which contains an Autocrypt
public key.  When receiving a claimchain from someone it should be framed within
a signature with this genesis key. One way to achieve this is to send ClaimChains
only within encrypted&signed messages.

Another claimchain entry type is "oob_verification" which expresses successful
out-of-band verification of claimchain heads and key material between two users.

todo/to-consider:

- properly implement oob verification

- look into using ipfs's modules/concepts for serializing
  and creating "content ids", i.e. self-describing hash addresses to blocks

- add crypto signing of each entry?  For in-band transmission of
  ClaimChains we can probably just sign the whole chain instead
  of the single entries.

"""
from __future__ import unicode_literals, print_function

import os
import time
import marshal
import hashlib
from pprint import pprint
from .myattr import (
    v, attr, attrib, attrib_text, attrib_text_or_none,
    attrib_bytes_or_none, attrib_float,
)
from autocrypt import mime


class BlockService:
    """ Filesystem Blockservice for storing and getting immutable blocks
    for use from ClaimChain instances. """
    def __init__(self, basedir):
        self._basedir = basedir

    def store_block(self, type, args, parent=None):
        # we choose the simplest data structure to create a block for a claimchain
        # each block references a parent block (or None if it's the
        # genesis block) and a timestamp.
        data = [type, parent, time.time()] + list(args)
        serialized = marshal.dumps(data)
        cid = hashlib.sha256(serialized).hexdigest()
        path = os.path.join(self._basedir, cid)
        with open(path, "wb") as f:
            f.write(serialized)
        return Block(cid, data, bs=self)

    def get_block(self, cid):
        path = os.path.join(self._basedir, cid)
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = marshal.load(f)
            return Block(cid, data, bs=self)


class Block:
    """ Basic entry for claim chains.  Each Block has the
    following attributes:
    - cid: the content address of this block
    - parent_cid: the parent content address or None
    - timestamp: when this block was created in seconds since epoch
    - args: the block-specific payload
    """
    def __init__(self, cid, data, bs):
        self.cid = cid
        self.type = data[0]
        self.parent_cid = data[1]
        self.timestamp = data[2]
        self.args = data[3:]
        self._bs = bs

    @property
    def parent(self):
        """ parent block or None. """
        if self.parent_cid:
            return self._bs.get_block(self.parent_cid)

    def __eq__(self, other):
        return self.cid == other.cid

    def __iter__(self):
        current = self
        while current:
            yield current
            current = current.parent

    def contains_cid(self, cid):
        for x in self:
            if x.cid == cid:
                return True

    def get_last_parent(self):
        for current in self:
            pass
        return current


class HeadTracker:
    """ Filesystem implementation for the mutable ID->HEAD mappings """
    def __init__(self, path):
        self._path = path

    def get_head_cid(self, ident):
        heads = self._getheads()
        return heads.get(ident)

    def _getheads(self, prefix=""):
        if os.path.exists(self._path):
            with open(self._path, "rb") as f:
                d = marshal.load(f)
                if prefix:
                    d = dict((x[len(prefix):], y) for x, y in d.items()
                             if x.startswith(prefix))
                return d
        return {}

    def remove_if(self, cal):
        heads = self._getheads()
        filtered = dict((x, y) for x, y in heads.items() if not cal(x, y))
        with open(self._path, "wb") as f:
            marshal.dump(filtered, f)

    def upsert(self, ident, cid):
        if isinstance(cid, Block):
            cid = cid.cid
        heads = self._getheads()
        heads[ident] = cid
        with open(self._path, "wb") as f:
            marshal.dump(heads, f)


class CCEntryBase(object):
    pass


class ClaimChainBase(object):
    """ A ClaimChain maintains an append-only log where each entry
    in the chain has its own content-based address so that claimchains
    can cross-reference entries within each other.  Each entry in a chain
    carries a timestamp and a parent CID (block hash) and type-specific
    extra data.  Here are the current types and the contained extra data:

    - genesis: cryptographic public key material.  parent must be None.

    - oob_verification: identity, verified-head of this identity)

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
        assert isinstance(entry, CCEntryBase)
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


class ClaimChain(ClaimChainBase):
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


# ===========================================================
# PeerChains for keeping track of incoming messages per peer
# ===========================================================

@attr.s
class MsgEntryAC(CCEntryBase):
    TAG = "msgac"
    msg_id = attrib_text()
    msg_date = attrib_float()
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    keydata = attrib_bytes_or_none()
    keyhandle = attrib_text_or_none()


@attr.s
class MsgEntryNOAC(CCEntryBase):
    TAG = "msgno"
    msg_id = attrib_text()
    msg_date = attrib_float()


class PeerChain(ClaimChainBase):
    def latest_ac_entry(self):
        """ Return latest message with autocrypt header. """
        return self.latest_entry_of(MsgEntryAC)

    def latest_msg_entry(self):
        """ Return latest message with or without autocrypt header. """
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
class KeygenEntry(CCEntryBase):
    TAG = "keygen"
    entry_date = attrib_float()
    keydata = attrib_bytes_or_none()
    keyhandle = attrib_text_or_none()


@attr.s
class OwnConfigEntry(CCEntryBase):
    TAG = "cfg"
    prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    uuid = attrib_text()
    name = attrib_text()
    email_regex = attrib_text()
    gpgmode = attrib(validator=v.in_(['system', 'own']))
    gpgbin = attrib_text()


class OwnChain(ClaimChainBase):
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
class AConfigEntry(CCEntryBase):
    TAG = "acfg"
    version = attrib_text()


class AccountChain(ClaimChainBase):
    def set_version(self, version):
        assert not self.latest_config()
        return self.append_entry(AConfigEntry(version=version))

    def latest_config(self):
        return self.latest_entry_of(AConfigEntry)


class ACStore:
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

    def get_ownchain(self, id_name):
        head_name = self._own_pat.format(id=id_name)
        return OwnChain(self.blocks, self.heads, head_name)

    def get_own_gpghome(self, id_name):
        return os.path.join(self.dirpath, "gpg", id_name)

    def remove_identity(self, id_name):
        def match_ident(key, value):
            l = key.split(":", 2)
            if l[0] in ("own", "peer") and l[1] == id_name:
                return True
        self.heads.remove_if(match_ident)


def shortrepr(obj):
    r = repr(obj)
    if len(r) > 50:
        r = r[:23] + "..." + r[-23:]
    return r
