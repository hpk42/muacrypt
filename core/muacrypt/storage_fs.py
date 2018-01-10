# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""
HeadTracker and BlockService filesystem implementation.
"""
from __future__ import unicode_literals, print_function

import os
import time
import marshal
import hashlib


class BlockService:
    """ Filesystem Blockservice for storing and getting immutable blocks
    for use from Chain instances. """
    def __init__(self, basedir):
        self._basedir = basedir

    def store_block(self, type, args, parent=None):
        # we choose the simplest data structure to create a block for a store_fs
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
