# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from muacrypt import mime


def send_ac_mail(sender, recipient, Date=None):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(recipient.addr),
        Date=Date,
    )
    recipient.process_incoming(mail)

def send_enc_ac_mail(sender, recipient):
    msg = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
        Autocrypt=sender.make_ac_header(recipient.addr),
    )
    r = sender.encrypt_mime(msg, [recipient.addr])
    recipient.process_incoming(r.enc_msg)
    r = recipient.decrypt_mime(r.enc_msg)
    return r.dec_msg

def send_no_ac_mail(sender, recipient):
    mail = mime.gen_mail_msg(
        From=sender.addr, To=[recipient.addr],
    )
    recipient.process_incoming(mail)


def get_recommendation(composer, peer, reply_to_enc=False):
    return composer.get_recommendation([peer.addr],
            reply_to_enc=reply_to_enc)


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

    def test_encrypt_on_mutual_preference(self, account_maker):
        composer, peer = account_maker(), account_maker()
        composer.modify(prefer_encrypt="mutual")
        peer.modify(prefer_encrypt="mutual")
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'encrypt'

    def test_available_if_only_composer_prefers_encrypt(self, account_maker):
        composer, peer = account_maker(), account_maker()
        composer.modify(prefer_encrypt="mutual")
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'available'

    def test_available_if_only_peer_prefers_encrypt(self, account_maker):
        composer, peer = account_maker(), account_maker()
        peer.modify(prefer_encrypt="mutual")
        send_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'available'

    def test_encrypt_replies_to_encrypted(self, account_maker):
        composer, peer = account_maker(), account_maker()
        send_ac_mail(composer, peer)
        decrypted = send_enc_ac_mail(peer, composer)
        rec = get_recommendation(composer, peer, reply_to_enc=True)
        assert rec.target_keys()[peer.addr]
        assert rec.ui_recommendation() == 'encrypt'
