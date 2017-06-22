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
import json
import hashlib
import codecs
from pprint import pprint
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
        serialized = json.dumps(data).encode("utf8")
        cid = hashlib.sha256(serialized).hexdigest()
        path = os.path.join(self._basedir, cid)
        with open(path, "wb") as f:
            f.write(serialized)
        return Block(cid, data, bs=self)

    def get_block(self, cid, raising=True):
        path = os.path.join(self._basedir, cid)
        if os.path.exists(path):
            with codecs.open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return Block(cid, data, bs=self)
        if raising:
            raise LookupError("block not found: {r}".format(cid))


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
    def __init__(self, basedir):
        self._basedir = basedir
        self._path = os.path.join(self._basedir, "heads")

    def get_head_cid(self, ident):
        heads = self._getheads()
        return heads.get(ident)

    def _getheads(self):
        if os.path.exists(self._path):
            with codecs.open(self._path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def upsert(self, ident, cid):
        heads = self._getheads()
        heads[ident] = cid
        with codecs.open(self._path, "w", encoding="utf-8") as f:
            json.dump(heads, f, indent=2, sort_keys=True)


class ClaimChain:
    """ A claimchain maintains an append-only log where each entry
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

    def append_block(self, type, args):
        head = self.get_head_block(raising=False)
        if head:
            head = head.cid
        block = self._bs.store_block(type, args, parent=head)
        self._ht.upsert(self.ident, block.cid)
        return block.cid

    def get_head_block(self, ident=None, raising=True):
        if ident is None:
            ident = self.ident
        head_cid = self._ht.get_head_cid(ident)
        if not head_cid:
            if raising:
                raise ValueError("no head found for {}".format(ident))
        else:
            return self._bs.get_block(head_cid, raising=raising)

    def iter_blocks(self, type=None):
        for x in self.get_head_block():
            if type is None or x.type == type:
                yield x

    def num_blocks(self):
        return len(list(self.iter_blocks()))

    def add_genesis(self, keydata):
        assert not self.get_head_block(raising=False), "already have a genesis block"
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
            head_block = self.get_head_block(ident=email)
            if head_block.contains_cid(cid):
                return True


def shortrepr(obj):
    r = repr(obj)
    if len(r) > 50:
        r = r[:23] + "..." + r[-23:]
    return r
