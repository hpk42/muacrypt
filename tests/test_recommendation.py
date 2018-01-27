# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from muacrypt import mime
from muacrypt.recommendation import Recommendation


def send_ac_mail(sender, recipient, Date=None):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(recipient.addr),
        payload=None, charset=None, Date=Date,
    )
    recipient.process_incoming(mail)


def send_no_ac_mail(sender, recipient):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=None, payload=None, charset=None, Date=None,
    )
    recipient.process_incoming(mail)


def get_recommendation(composer, peer):
    peerstate = composer.get_peerstate(peer.addr)
    return Recommendation({peer.addr: peerstate})


class TestRecommendation:

    def test_disable_on_initial_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr] is None
        assert rec.ui_recommendation() == 'disable'

    def test_available_after_receiving_ac_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'available'

    def test_disable_after_receiving_no_ac_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr] is None
        assert rec.ui_recommendation() == 'disable'

    def test_available_long_after_receiving_ac_mail(self, account_maker):
        long_ago = 'Sun, 15 Jan 2017 15:00:00 -0000'
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer, Date=long_ago)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'available'

    def test_discourage_on_outdated_ac_header(self, account_maker):
        long_ago = 'Sun, 15 Jan 2017 15:00:00 -0000'
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer, Date=long_ago)
        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'discourage'
