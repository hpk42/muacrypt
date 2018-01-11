from __future__ import unicode_literals, print_function

import itertools
import pytest
from muacrypt.storage import Chain, Store, HeadTracker, BlockService, mime


@pytest.fixture
def counter():
    counter = itertools.count()
    return lambda: str(next(counter))


@pytest.fixture
def chain_maker(tmpdir, bingpg_maker, counter):
    ht = HeadTracker(tmpdir.join("heads").strpath)
    bs = BlockService(tmpdir.mkdir("blocks").strpath)

    def maker(genesis=True):
        num = counter()
        account = "a{}@a.org".format(num)
        cc = Chain(bs, ht, account=account)
        cc._bingpg = bingpg = bingpg_maker()
        if genesis:
            cc._own_keyhandle = bingpg.gen_secret_key(account)
            cc.add_genesis(bingpg.get_public_keydata(cc._own_keyhandle))
        return cc
    return maker


class TestChain:
    def test_genesis(self, chain_maker, bingpg_maker):
        bingpg = bingpg_maker()
        cc1 = chain_maker(genesis=True)
        cc2 = Chain(account=cc1.account, headtracker=cc1._ht, blockservice=cc1._bs)
        blocks1 = list(cc1.iter_blocks())
        blocks2 = list(cc2.iter_blocks())
        assert len(blocks1) == len(blocks2) == 1

        assert cc2.get_genesis_block() == cc1.get_genesis_block()
        gen_block = cc2.get_genesis_block()
        keydata = mime.decode_keydata((gen_block.args[0]))
        handle = bingpg.import_keydata(keydata)
        assert handle == cc1._own_keyhandle

    def test_oob_verify(self, chain_maker):
        cc1 = chain_maker(genesis=True)
        assert cc1.num_blocks() == 1
        cc2 = chain_maker(genesis=True)
        cc1.add_oob_verify(email=cc2.account, cid=cc2.get_head_block().cid)
        assert cc1.num_blocks() == 2
        cc2_genesis_cid = cc2.get_genesis_block().cid
        assert not cc1.is_oob_verified_block(cc2_genesis_cid[:-1])
        assert cc1.is_oob_verified_block(cc2_genesis_cid)
        cc1.dump()


class TestStore:
    @pytest.fixture
    def cm(self, tmpdir):
        return Store(tmpdir.strpath)

    def test_get_peerchain_empty(self, cm):
        peerchain = cm.get_peerchain("id1", "name1@123")
        assert peerchain.is_empty()

    def test_get_peerchain_add_entries(self, cm):
        peerchain = cm.get_peerchain("id1", "name1@123")
        peerchain.append_ac_entry(
            msg_id='hello', msg_date=17.0, prefer_encrypt='nopreference',
            keydata=b'123', keyhandle='4567'
        )
        entry1 = peerchain.latest_ac_entry()
        assert entry1.msg_id == 'hello'
        assert entry1.msg_date == 17.0
        assert entry1.prefer_encrypt == 'nopreference'
        assert entry1.keydata == b'123'
        assert entry1.keyhandle == '4567'

        peerchain.append_noac_entry(
            msg_id='world', msg_date=50.0
        )
        entry2 = peerchain.latest_msg_entry()

        assert entry2.msg_id == 'world'
        assert entry2.msg_date == 50.0

        peerchain.append_ac_entry(
            msg_id='hello', msg_date=70.0, prefer_encrypt='nopreference',
            keydata=b'123', keyhandle='4567'
        )
        assert peerchain.latest_msg_entry().msg_date == 70.0
        assert peerchain.latest_ac_entry().msg_date == 70.0
