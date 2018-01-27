# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from muacrypt.myattr import (
    attr, attrib_text
)
from muacrypt.recommendation import Recommendation


class TestRecommendation:

    def test_empty_peer_state(self, account_maker):
        addr = 'test@me.example'
        peerstate = PeerStateDouble(public_keyhandle='',
                gossip_keyhandle='')
        rec = Recommendation({addr: peerstate})
        assert rec.target_keys()[addr] is None
        assert rec.ui_recommendation() == 'disable'


@attr.s
class PeerStateDouble(object):
    # prefer_encrypt = attrib(validator=v.in_(['nopreference', 'mutual']))
    public_keyhandle = attrib_text()
    gossip_keyhandle = attrib_text()
