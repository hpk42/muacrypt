# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from muacrypt import mime


def send_ac_mail(sender, recipient, Date=None):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(recipient.addr),
        Date=Date)
    recipient.process_incoming(mail)


def send_enc_ac_mail(sender, recipient):
    msg = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(recipient.addr))
    r = sender.encrypt_mime(msg, [recipient.addr])
    recipient.process_incoming(r.enc_msg)
    r = recipient.decrypt_mime(r.enc_msg)
    return r.dec_msg


def send_no_ac_mail(sender, recipient):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
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
        send_no_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keyhandles()[peer.addr] is None
        assert rec.ui_recommendation() == 'disable'

    def test_available_long_after_receiving_ac_mail(self, account_maker):
        long_ago = 'Sun, 15 Jan 2017 15:00:00 -0000'
        composer, peer = account_maker(), account_maker()
        send_ac_mail(peer, composer, Date=long_ago)
        rec = get_recommendation(composer, peer)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'available'

    def test_discourage_on_outdated_ac_header(self, account_maker):
        composer, peer = account_maker(), account_maker()
        long_ago = 'Sun, 15 Jan 2017 15:00:00 -0000'
        send_ac_mail(peer, composer, Date=long_ago)
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
        send_enc_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer, reply_to_enc=True)
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'encrypt'

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
        long_ago = 'Sun, 15 Jan 2017 15:00:00 -0000'
        send_ac_mail(peer, composer)
        send_ac_mail(discourage_peer, composer, Date=long_ago)
        send_no_ac_mail(discourage_peer, composer)
        rec = get_recommendation(composer, {peer, discourage_peer})
        peer_keyhandle = composer.get_peerstate(peer.addr).public_keyhandle
        assert rec.target_keyhandles()[peer.addr] == peer_keyhandle
        assert rec.ui_recommendation() == 'discourage'
