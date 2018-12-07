# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""
Storage mechanisms which manage immutable blocks and Chains
which consist of hash-linked entries.

The HeadTracker keeps track of named "heads" which can be queried
through the States class.  Both the current BlockService and the
HeadTracker use the file system for persistent storage.
"""
from __future__ import unicode_literals, print_function

import os
import time
from execnet.gateway_base import load, dump, dumps
import hashlib
from pprint import pprint
import attr


class BlockService:
    """ Filesystem Blockservice for storing and getting immutable blocks
    for use from Chain instances. """
    def __init__(self, basedir):
        self._basedir = basedir

    def store_block(self, type, args, parent=None):
        # we choose the simplest data structure to create a block for a states_fs
        # each block references a parent block (or None if it's the
        # genesis block) and a timestamp.
        data = [type, parent, time.time()] + list(args)
        serialized = dumps(data)
        cid = hashlib.sha256(serialized).hexdigest()
        path = os.path.join(self._basedir, cid)
        with open(path, "wb") as f:
            f.write(serialized)
        return Block(cid, data, bs=self)

    def get_block(self, cid):
        fn_cid = cid if not isinstance(cid, bytes) else cid.decode("ascii")
        path = os.path.join(self._basedir, fn_cid)
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = load(f)
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

    def get_head_cid(self, account):
        heads = self._getheads()
        return heads.get(account)

    def _getheads(self, prefix=""):
        if os.path.exists(self._path):
            with open(self._path, "rb") as f:
                d = load(f)
                if prefix:
                    d = dict((x[len(prefix):], y) for x, y in d.items()
                             if x.startswith(prefix))
                return d
        return {}

    def remove_if(self, cal):
        heads = self._getheads()
        filtered = dict((x, y) for x, y in heads.items() if not cal(x, y))
        with open(self._path, "wb") as f:
            dump(f, filtered)

    def upsert(self, account, cid):
        if isinstance(cid, Block):
            cid = cid.cid
        heads = self._getheads()
        heads[account] = cid
        with open(self._path, "wb") as f:
            dump(f, heads)


class ChainStates(object):
    def __init__(self, blockservice, headtracker, head_name):
        self._bs = blockservice
        self._ht = headtracker
        self.head_name = head_name

    def dump(self):
        l = list(self.get_head_block())
        for x in reversed(l):
            pprint("{} {}: {}".format(x.timestamp, x.type, shortrepr(x.args)))

    def iter_blocks(self, type=None):
        """ yields blocks from head to root for this chain. """
        head_block = self.get_head_block()
        if head_block:
            for x in head_block:
                if type is None or x.type == type:
                    yield x

    def new_head_block(self, type, args):
        head = self.get_head_block()
        if head:
            head = head.cid
        block = self._bs.store_block(type, args, parent=head)
        self._ht.upsert(self.head_name, block.cid)
        return block

    def get_head_block(self):
        head_cid = self._ht.get_head_cid(self.head_name)
        if head_cid:
            return self._bs.get_block(head_cid)


class Chain(object):
    """ A Chain maintains an append-only log where each entry
    in the chain has its own content-based address so that chains
    can cross-reference entries from the same or other chains. Each entry in a chain
    carries a timestamp and a parent CID (block hash) and Entry-specific
    extra data.
    """
    def __init__(self, blockservice, headtracker, chain_name):
        self._chainstore = ChainStates(blockservice, headtracker, chain_name)
        self.name = chain_name

    def __len__(self):
        return len(list(self.iter_entries()))

    def append_entry(self, entry):
        args = attr.astuple(entry)
        self._chainstore.new_head_block(entry.TAG, args)

    def iter_entries(self, entryclass=None):
        assert entryclass is None or hasattr(entryclass, "TAG")
        tag = getattr(entryclass, "TAG", None)
        for block in self._chainstore.iter_blocks():
            if block and (tag is None or block.type == tag):
                if entryclass:
                    yield entryclass(*block.args)
                else:
                    yield block.args

    def latest_entry_of(self, entryclass):
        for entry in self.iter_entries(entryclass):
            return entry


def shortrepr(obj):
    r = repr(obj)
    if len(r) > 50:
        r = r[:23] + "..." + r[-23:]
    return r
