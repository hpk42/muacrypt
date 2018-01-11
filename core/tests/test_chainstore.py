# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals, print_function

import time
import hashlib
import pytest
from muacrypt.chainstore import BlockService, HeadTracker


class TestBlockService:
    @pytest.fixture
    def bs(self, tmpdir):
        return BlockService(tmpdir.mkdir("blocks").strpath)

    def test_states_get_initial(self, bs):
        args = ["hello", "world"]
        block = bs.store_block("genesis", args, parent=None)
        assert block.args == args
        assert block.parent is None
        assert block.timestamp <= time.time()

    def test_states2_getblocks(self, bs):
        args1 = ["hello", "world"]
        args2 = [42, 43]
        block1 = bs.store_block("genesis", args1)
        block2 = bs.store_block("something", args2, parent=block1.cid)
        l = list(block2)
        l.reverse()
        assert l[0].args == args1
        assert not l[0].parent
        assert l[1].args == args2
        assert l[1].parent_cid == block1.cid
        assert l[0].timestamp < l[1].timestamp

    def test_states2_get_last(self, bs):
        args1 = ["hello", "world"]
        args2 = [42, 43]
        block1 = bs.store_block("hello", args1)
        block2 = bs.store_block("hello", args2, parent=block1.cid)
        block = block2.get_last_parent()
        assert block == block1
        assert block.timestamp <= time.time()
        assert block.parent is None


class TestHeadTracker:
    @pytest.fixture
    def ht(self, tmpdir):
        return HeadTracker(tmpdir.join("heads").strpath)

    def test_get_empty(self, ht):
        assert not ht.get_head_cid("id1")

    def test_states_and_get_update_and_get(self, ht):
        cid1 = hashlib.sha256(b"1").hexdigest()
        cid2 = hashlib.sha256(b"2").hexdigest()
        ht.upsert("id1", cid1)
        assert ht.get_head_cid("id1") == cid1
        ht.upsert("id1", cid2)
        assert ht.get_head_cid("id1") == cid2
