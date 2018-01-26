# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from muacrypt.recommendation import Recommendation


class TestRecommendation:

    def test_no_peer_state(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        rec = Recommendation(sender, {recipient.addr: None})
        assert rec.target_keys()[recipient.addr] is None
        assert rec.ui_recommendation() == 'disable'

    def test_empty_peer_state(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        peerstate = sender.get_peerstate(recipient.addr)
        rec = Recommendation(sender, {recipient.addr: peerstate})
        assert rec.target_keys()[recipient.addr] is None
        assert rec.ui_recommendation() == 'disable'
