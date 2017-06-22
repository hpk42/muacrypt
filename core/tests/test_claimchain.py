# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals, print_function

import itertools
import time
import hashlib
import pytest
from autocrypt import mime
from autocrypt.claimchain import ClaimChain, BlockService, HeadTracker


@pytest.fixture
def counter():
    counter = itertools.count()
    return lambda: str(next(counter))


@pytest.fixture
def cc_maker(tmpdir, bingpg_maker, counter):
    ht = HeadTracker(tmpdir.mkdir("heads").strpath)
    bs = BlockService(tmpdir.mkdir("blocks").strpath)

    def maker(genesis=True):
        num = counter()
        ident = "a{}@a.org".format(num)
        cc = ClaimChain(bs, ht, ident=ident)
        cc._bingpg = bingpg = bingpg_maker()
        if genesis:
            cc._own_keyhandle = bingpg.gen_secret_key(ident)
            cc.add_genesis(bingpg.get_public_keydata(cc._own_keyhandle))
        return cc
    return maker


class TestBlockService:
    @pytest.fixture
    def bs(self, tmpdir):
        return BlockService(tmpdir.mkdir("blocks").strpath)

    def test_store_get_initial(self, bs):
        args = ["hello", "world"]
        block = bs.store_block("genesis", args, parent=None)
        assert block.args == args
        assert block.parent is None
        assert block.timestamp <= time.time()

    def test_store2_getblocks(self, bs):
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

    def test_store2_get_last(self, bs):
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
        return HeadTracker(tmpdir.mkdir("heads").strpath)

    def test_get_empty(self, ht):
        assert not ht.get_head_cid("id1")

    def test_store_and_get_update_and_get(self, ht):
        cid1 = hashlib.sha256(b"1").hexdigest()
        cid2 = hashlib.sha256(b"2").hexdigest()
        ht.upsert("id1", cid1)
        assert ht.get_head_cid("id1") == cid1
        ht.upsert("id1", cid2)
        assert ht.get_head_cid("id1") == cid2


class TestClaimChain:
    def test_genesis(self, cc_maker, bingpg_maker):
        bingpg = bingpg_maker()
        cc1 = cc_maker(genesis=True)
        cc2 = ClaimChain(ident=cc1.ident, headtracker=cc1._ht,
                         blockservice=cc1._bs)
        blocks1 = list(cc1.iter_blocks())
        blocks2 = list(cc2.iter_blocks())
        assert len(blocks1) == len(blocks2) == 1

        assert cc2.get_genesis_block() == cc1.get_genesis_block()
        gen_block = cc2.get_genesis_block()
        keydata = mime.decode_keydata((gen_block.args[0]))
        handle = bingpg.import_keydata(keydata)
        assert handle == cc1._own_keyhandle

    def test_oob_verify(self, cc_maker):
        cc1 = cc_maker(genesis=True)
        assert cc1.num_blocks() == 1
        cc2 = cc_maker(genesis=True)
        cc1.add_oob_verify(email=cc2.ident, cid=cc2.get_head_block().cid)
        assert cc1.num_blocks() == 2
        cc2_genesis_cid = cc2.get_genesis_block().cid
        assert not cc1.is_oob_verified_block(cc2_genesis_cid[:-1])
        assert cc1.is_oob_verified_block(cc2_genesis_cid)
        cc1.dump()
