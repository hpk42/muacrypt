from __future__ import unicode_literals, print_function

import pytest
from muacrypt.storage import Store


@pytest.fixture
def store(tmpdir):
    return Store(tmpdir.strpath)


class TestOOB:
    def test_basic_verifications(self, store):
        oobstate = store.get_oobstate("account1")
        assert not oobstate.get_verification(addr="a@a.org")

        oobstate.append_self_verification(addr="a@a.org", public_keydata=b'123')
        assert oobstate.get_verification(addr="a@a.org").origin == "self"
        assert not oobstate.get_verification(addr="b@b.org")

        oobstate.append_peer_verification(addr="b@b.org", public_keydata=b'123')
        assert oobstate.get_verification(addr="b@b.org").origin == "peer"


class TestPeerChain:
    def test_empty(self, store):
        peerchain = store.get_peerchain("id1", "name1@123")
        assert peerchain.is_empty()

    def test_add_ac_and_not_ac(self, store):
        peerchain = store.get_peerchain("id1", "name1@123")
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
