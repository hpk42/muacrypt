# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from muacrypt import mime
from muacrypt.recommendation import Recommendation


def send_ac_mail(sender, recipient):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(recipient.addr),
        payload=None, charset=None, Date=None,
    )
    recipient.process_incoming(mail)


class TestRecommendation:

    def test_initial_mail(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        peerstate = sender.get_peerstate(recipient.addr)
        rec = Recommendation({recipient.addr: peerstate})
        assert rec.target_keys()[recipient.addr] is None
        assert rec.ui_recommendation() == 'disable'

    def test_reply_to_ac_mail(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        send_ac_mail(sender, recipient)
        peerstate = recipient.get_peerstate(sender.addr)
        rec = Recommendation({sender.addr: peerstate})
        assert rec.target_keys()[sender.addr]
        assert rec.ui_recommendation() == 'available'
