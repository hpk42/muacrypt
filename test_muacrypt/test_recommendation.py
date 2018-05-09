# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

import itertools
from muacrypt import mime

test_sendcount = itertools.count()


def get_testdate(Date):
    if Date is None:
        Date = next(test_sendcount)
    return Date


def get_testdate_50daysago():
    return get_testdate(-3600 * 24 * 50)


def send_ac_mail(sender, recipient, Date=None):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(sender.addr),
        Date=get_testdate(Date))
    recipient.process_incoming(mail)


def send_enc_ac_mail(sender, recipients, Date=None):
    addrs = [r.addr for r in recipients]
    msg = mime.gen_mail_msg(
        From=sender.addr, To=addrs,
        Autocrypt=sender.make_ac_header(sender.addr),
        Date=get_testdate(Date))
    r = sender.encrypt_mime(msg, addrs)
    for rec in recipients:
        rec.process_incoming(r.enc_msg)


def send_no_ac_mail(sender, recipient, Date=None):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Date=get_testdate(Date),
    )
    recipient.process_incoming(mail)


def get_recommendation(composer, peers, reply_to_enc=False):
    if not isinstance(peers, set):
        peers = {peers}
    peer_addrs = {peer.addr for peer in peers}
    return composer.get_recommendation(peer_addrs, reply_to_enc=reply_to_enc)


class TestRecommendation:

    def test_disable_on_initial_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        rec = get_recommendation(composer, peer)
        assert rec.target_keyhandles()[peer.addr] is None
        assert rec.ui_recommendation() == 'disable'

    def test_available_after_receiving_ac_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'available'

    def test_disable_after_receiving_no_ac_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        rec = get_recommendation(composer, peer)
        assert rec.ui_recommendation() == 'disable'

        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keyhandles()[peer.addr] is None

    def test_available_after_receiving_no_ac_mail_after_ac_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer)
        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.ui_recommendation() == 'available'
        assert rec.target_keyhandles()[peer.addr]

    def test_available_long_after_receiving_ac_mail(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer, Date=get_testdate_50daysago())
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'available'

    def test_discourage_on_outdated_ac_header(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer, Date=get_testdate_50daysago())
        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'discourage'

    def test_encrypt_on_mutual_preference(self, account_maker):
        composer, peer = account_maker(), account_maker()
        composer.modify(prefer_encrypt="mutual")
        peer.modify(prefer_encrypt="mutual")
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'encrypt'

        # send a mail without AC header and see that we get "available"
        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'available'

    def test_available_if_one_peer_without_prefer_encrypt(self, account_maker):
        composer, peer = account_maker(), account_maker()
        peer_with_no_preference = account_maker()
        composer.modify(prefer_encrypt="mutual")
        peer.modify(prefer_encrypt="mutual")
        send_ac_mail(peer, composer)
        send_ac_mail(peer_with_no_preference, composer)
        rec = get_recommendation(composer, {peer, peer_with_no_preference})
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'available'

    def test_available_if_only_peer_prefers_encrypt(self, account_maker):
        composer, peer = account_maker(), account_maker()
        peer.modify(prefer_encrypt="mutual")
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'available'

    # note: even though we send an encrypted mail in the setup the
    # reply to encrypted so far is only based on a flag.
    # We might want an additional function for preparing replies
    def test_encrypt_replies_to_encrypted(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(composer, peer)
        send_enc_ac_mail(peer, [composer])
        rec = get_recommendation(composer, peer, reply_to_enc=True)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'encrypt'

    def test_gossip_keys_recommendation(self, account_maker):
        composer, peer1, peer2 = account_maker(), account_maker(), account_maker()
        send_ac_mail(peer1, composer)
        send_ac_mail(peer2, composer)
        send_enc_ac_mail(composer, [peer1, peer2])
        rec = get_recommendation(peer1, peer2, reply_to_enc=True)
        # peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.ui_recommendation() == 'encrypt'
        assert rec.target_keyhandles()[peer2.addr]
        rec = get_recommendation(peer1, peer2, reply_to_enc=False)
        # peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.ui_recommendation() == 'discourage'
        assert rec.target_keyhandles()[peer2.addr]

    def test_disable_if_one_key_is_missing(self, account_maker):
        composer, peer = account_maker(), account_maker()
        no_ac_peer = account_maker()
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, {peer, no_ac_peer})
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'disable'

    def test_discourage_if_one_key_is_outdated(self, account_maker):
        composer, peer = account_maker(), account_maker()
        discourage_peer = account_maker()
        send_ac_mail(peer, composer)
        send_ac_mail(discourage_peer, composer, Date=get_testdate_50daysago())
        send_no_ac_mail(discourage_peer, composer)
        rec = get_recommendation(composer, {peer, discourage_peer})
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'discourage'
