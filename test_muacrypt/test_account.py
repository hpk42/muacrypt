# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import os
import time
from base64 import b64encode
import six
import email
from email.mime.image import MIMEImage
import pytest
from muacrypt.account import Account, AccountManager
from muacrypt import mime
from muacrypt.cmdline import make_plugin_manager


def gen_ac_mail_msg(sender, recipients, payload=None, charset=None,
                    Date=None, ENCRYPT=None, _dto=False):
    if isinstance(recipients, Account):
        recipients = [recipients]
    return mime.gen_mail_msg(
        From=sender.addr, To=[rec.addr for rec in recipients],
        Autocrypt=sender.make_ac_header(sender.addr),
        payload=payload, charset=charset, Date=Date,
        ENCRYPT=ENCRYPT, _dto=_dto,
    )


def gen_noac_mail_msg(sender, recipients, payload=None, charset=None, Date=None, _dto=False):
    if isinstance(recipients, Account):
        recipients = [recipients]
    return mime.gen_mail_msg(
        From=sender.addr, To=[rec.addr for rec in recipients],
        payload=payload, charset=charset, Date=Date,
        _dto=_dto,
    )


class TestAccount:
    def test_export_keys(self, account_maker, datadir):
        acc = account_maker()
        assert acc.export_public_key()
        assert acc.export_secret_key()

    def test_parse_incoming_mail_broken_ac_header(self, account_maker):
        acc1 = account_maker()
        msg = mime.gen_mail_msg(
            From=acc1.addr, To=[], Autocrypt="Autocrypt: to=123; key=12312k3")
        r = acc1.process_incoming(msg)
        assert r.pah.error
        assert r.msg_date

    def test_parse_incoming_mail_empty_ac_header(self, account_maker):
        acc1 = account_maker()
        msg = mime.gen_mail_msg(From=acc1.addr, To=[])
        msg["Autocrypt"] = ""
        r = acc1.process_incoming(msg)
        assert r.pah.error

    def test_ignore_multipart_report(self, account_maker, datadir):
        acc1 = account_maker()
        acc1.modify(email_regex='Jane_Sender@example.org')
        msg = mime.parse_message_from_file(datadir.open("multipart_report.eml"))
        r = acc1.process_incoming(msg)
        assert r.pah.error == "Ignoring 'multipart/report' message."

    def test_parse_incoming_mail_broken_date_header(self, account_maker):
        addr = "a@a.org"
        acc1 = account_maker()
        msg = mime.gen_mail_msg(
            From=addr, To=["b@b.org"], Date="l1k2j3")
        r = acc1.process_incoming(msg)
        assert r.pah.error
        assert r.msg_date == 0.0

    @pytest.mark.parametrize("keydata", [b64encode(b'123'), b'123123'])
    def test_parse_incoming_mail_broken_keydata(self, account_maker, keydata):
        addr = "a@a.org"
        acc1 = account_maker()
        msg = mime.gen_mail_msg(
            From=addr, To=["b@b.org"],
            Autocrypt="addr={}; keydata={}".format(addr, keydata)
        )
        r = acc1.process_incoming(msg)
        assert r.pah.error

    def test_parse_incoming_mail_broken_from(self, account_maker):
        acc1 = account_maker()
        msg = mime.gen_mail_msg(From="", To=["b@b.org"])
        r = acc1.process_incoming(msg)
        assert r.pah.error

    def test_ignore_incoming_mail_multiple_from(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        msg = mime.gen_mail_msg(From=','.join([sender.addr, "b@a.org"]),
                                To=[recipient.addr],
                                Autocrypt=sender.make_ac_header(sender.addr))
        r = recipient.process_incoming(msg)
        assert r.pah.error == "Ignoring message with more than one address in From header."

    def test_accept_incoming_mail_with_at_in_from_realname(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        msg = mime.gen_mail_msg(
            From=email.utils.formataddr([sender.addr, sender.addr]),
            To=[recipient.addr],
            Autocrypt=sender.make_ac_header(sender.addr),
        )
        r = recipient.process_incoming(msg)
        assert r.pah.error is None

    def test_parse_incoming_mail_unicode_from(self, account_maker):
        addr = 'x@k\366nig.de'
        acc1 = account_maker()
        msg = mime.gen_mail_msg(
            From=addr, To=["b@b.org"],
        )
        r = acc1.process_incoming(msg)
        assert r.pah.error

    def test_parse_incoming_unknown_prefer_encrypt(self, account_maker):
        acc1, acc2 = account_maker(), account_maker()
        acc1.modify(prefer_encrypt="mutual")
        msg = gen_ac_mail_msg(acc1, acc2)
        msg.replace_header("Autocrypt", msg["Autocrypt"].replace("mutual", "notset"))
        r = acc2.process_incoming(msg)
        assert r.pah.error

    def test_parse_incoming_mails_replace(self, account_maker):
        acc1, acc2, acc3 = account_maker(), account_maker(), account_maker()
        msg1 = mime.gen_mail_msg(
            From=acc1.addr, To=[acc2.addr],
            Autocrypt=acc1.make_ac_header(acc1.addr))
        r = acc2.process_incoming(msg1)
        assert r.peerstate.public_keyhandle == acc1.ownstate.keyhandle
        msg2 = mime.gen_mail_msg(
            From=acc1.addr, To=[acc2.addr],
            Autocrypt=acc3.make_ac_header(acc1.addr))
        r2 = acc2.process_incoming(msg2)
        assert r2.peerstate.public_keyhandle == acc3.ownstate.keyhandle

    def test_parse_incoming_msg_twice_same_entries(self, account_maker):
        acc1, acc2 = account_maker(), account_maker()
        msg1 = mime.gen_mail_msg(
            From=acc1.addr, To=[acc2.addr],
            Autocrypt=acc1.make_ac_header(acc1.addr))
        msg2 = mime.gen_mail_msg(
            From=acc1.addr, To=[acc2.addr],
            Autocrypt=acc1.make_ac_header(acc1.addr))
        r = acc2.process_incoming(msg1)
        assert r.peerstate.public_keyhandle == acc1.ownstate.keyhandle
        assert r.peerstate._latest_msg_entry().msg_id == msg1["Message-Id"]
        r = acc2.process_incoming(msg2)
        assert r.peerstate._latest_msg_entry().msg_id == msg2["Message-Id"]
        i = len(r.peerstate._chain)
        r = acc2.process_incoming(msg1, ignore_existing=False)
        r = acc2.process_incoming(msg2, ignore_existing=False)
        assert i == len(r.peerstate._chain)

    def test_parse_incoming_mails_effective_date(self, account_maker, monkeypatch):
        fixed_time = time.time()
        later_date = 'Thu, 16 Feb 2050 15:00:00 -0000'
        monkeypatch.setattr(time, "time", lambda: fixed_time)
        acc1, acc2 = account_maker(), account_maker()
        msg1 = gen_ac_mail_msg(acc1, acc2, Date=later_date)
        r = acc2.process_incoming(msg1)
        assert r.peerstate.last_seen == fixed_time
        assert r.msg_date == fixed_time

    def test_parse_incoming_mails_replace_by_date(self, account_maker):
        acc1, acc2, acc3 = account_maker(), account_maker(), account_maker()
        addr = acc1.addr
        msg2 = mime.gen_mail_msg(
            From=addr, To=["b@b.org"], Autocrypt=acc1.make_ac_header(addr),
            Date='Thu, 16 Feb 2017 15:00:00 -0000')
        r = acc2.process_incoming(msg2)
        assert r.account.get_peerstate(addr).public_keyhandle == acc1.ownstate.keyhandle
        assert r.msg_date == r.peerstate.autocrypt_timestamp

        msg1 = mime.gen_mail_msg(
            From=addr, To=["b@b.org"], Autocrypt=acc3.make_ac_header(addr),
            Date='Thu, 16 Feb 2017 13:00:00 -0000')
        r2 = acc2.process_incoming(msg1)
        assert r2.peerstate.public_keyhandle == acc1.ownstate.keyhandle
        assert r2.msg_date < r.msg_date
        assert r2.peerstate.autocrypt_timestamp == r.peerstate.autocrypt_timestamp

        msg3 = mime.gen_mail_msg(
            From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
            Date='Thu, 16 Feb 2017 17:00:00 -0000')
        r3 = acc1.process_incoming(msg3)
        assert "no valid" in r3.pah.error
        assert r3.msg_date > r2.msg_date
        assert r3.peerstate.last_seen == r3.msg_date
        assert r3.peerstate.last_seen > r.peerstate.autocrypt_timestamp

    def test_get_peer_keyhandle(self, account_maker, datadir):
        msg = mime.parse_message_from_file(datadir.open("rsa2048-simple.eml"))
        acc1 = account_maker()
        acc1.process_incoming(msg)
        ps = acc1.get_peerstate("alice@testsuite.autocrypt.org")
        assert ps.public_keyhandle == 'BAFC533CD993BD7F'

    def test_parse_incoming_mail_and_raw_encrypt(self, account_maker):
        acc1, acc2 = account_maker(), account_maker()
        msg = gen_ac_mail_msg(acc1, acc2)
        r = acc2.process_incoming(msg)
        assert r.peerstate.addr == acc1.addr
        enc = acc2.bingpg.encrypt(data=b"123", recipients=[r.peerstate.public_keyhandle])
        data, descr_info = acc1.bingpg.decrypt(enc)
        assert data == b"123"

    def test_parse_incoming_mail_8bit(self, account_maker, datadir):
        acc1 = account_maker()
        acc1.process_incoming(gen_ac_mail_msg(acc1, acc1))
        with datadir.open("msg_8bit.eml", "rb") as f:
            msg = mime.message_from_binary_file(f)
        r1 = acc1.encrypt_mime(msg, [acc1.addr])
        r2 = acc1.decrypt_mime(r1.enc_msg)
        assert r2.dec_msg.get_payload(decode=True) == msg.get_payload(decode=True)

    def test_parse_incoming_mail_iso_quopri(self, account_maker, datadir):
        acc1 = account_maker()
        acc1.process_incoming(gen_ac_mail_msg(acc1, acc1))
        with datadir.open("msg_iso8859_quopri.eml", "rb") as f:
            msg = mime.message_from_binary_file(f)
        r1 = acc1.encrypt_mime(msg, [acc1.addr])
        r2 = acc1.decrypt_mime(r1.enc_msg)
        assert r2.dec_msg.get_payload(decode=True) == msg.get_payload(decode=True)
        s = r2.dec_msg.get_payload(decode=True)
        assert six.text_type(s, "iso-8859-1") == u"angehört\n"

    def test_encrypt_decrypt_mime_text_plain(self, account_maker):
        acc1, acc2 = account_maker(), account_maker()

        # send a mail from addr1 with autocrypt key to addr2
        msg = gen_ac_mail_msg(acc1, acc2)
        r = acc2.process_incoming(msg)
        assert r.peerstate.addr == acc1.addr

        # send an encrypted mail from addr2 to addr1
        msg2 = gen_ac_mail_msg(acc2, acc1, payload="hello ä umlaut", charset="utf8")

        r = acc2.encrypt_mime(msg2, [acc1.addr])
        acc1.process_incoming(r.enc_msg)

        # decrypt the incoming mail
        r = acc1.decrypt_mime(r.enc_msg)
        dec = r.dec_msg
        assert dec.get_content_type() == "text/plain"
        assert dec.get_payload() == msg2.get_payload()

    def test_encrypt_decrypt_mime_mixed(self, account_maker):
        acc1, acc2 = account_maker(), account_maker()

        # send a mail from addr1 with autocrypt key to addr2
        acc2.process_incoming(gen_ac_mail_msg(acc1, acc2))

        # create a multipart/mixed mail
        msg2 = gen_ac_mail_msg(acc2, acc1, payload=[])
        msg2.attach(mime.make_message('text/plain', payload="some text"))
        img = MIMEImage(b'\003\005', "jpeg")
        img['Content-Disposition'] = 'attachment; filename="x.jpg"'
        msg2.attach(img)

        # send multipart/mixed back to acc1
        r = acc2.encrypt_mime(msg2, [acc1.addr])
        acc1.process_incoming(r.enc_msg)

        # decrypt the incoming mail
        r = acc1.decrypt_mime(r.enc_msg)
        dec = r.dec_msg
        assert dec.get_content_type() == "multipart/mixed"
        assert len(dec.get_payload()) == 2
        m1, m2 = dec.get_payload()
        assert m1.get_content_type() == msg2.get_payload()[0].get_content_type()
        assert m2.get_content_type() == img.get_content_type()
        assert m2.get_payload(decode=True) == img.get_payload(decode=True)

    def test_get_recommendation(self, account_maker):
        sender, recipient = account_maker(), account_maker()
        msg1 = mime.gen_mail_msg(
            From=sender.addr, To=[recipient.addr],
            Autocrypt=sender.make_ac_header(sender.addr))
        recipient.process_incoming(msg1)
        for addr in [sender.addr, "someprefix <{}>".format(sender.addr)]:
            recommend = recipient.get_recommendation([addr])
            assert recommend.ui_recommendation() == 'available'
            assert recommend.target_keyhandles()[sender.addr] == sender.ownstate.keyhandle

    def test_encrypt_with_gossip(self, account_maker):
        sender = account_maker()
        rec1, rec2 = account_maker(), account_maker()

        # make sure sender has all keys
        sender.process_incoming(gen_ac_mail_msg(rec1, sender))
        sender.process_incoming(gen_ac_mail_msg(rec2, sender))

        # send an encrypted mail from sender to both recipients
        gossip_msg = gen_ac_mail_msg(sender, [rec1, rec2])
        enc_msg = sender.encrypt_mime(gossip_msg, [rec1.addr, rec2.addr]).enc_msg
        r = rec1.process_incoming(enc_msg)

        ps = rec1.get_peerstate(rec2.addr)
        ge = ps.latest_gossip_entry()
        assert ge.keyhandle == rec2.ownstate.keyhandle
        assert r.gossip_pahs[rec2.addr].keydata == ge.keydata
        assert not ps._latest_ac_entry()  # no direct key
        assert not ps.prefer_encrypt
        i = len(ps._chain)
        rec1.process_incoming(enc_msg)
        assert i == len(ps._chain)

    def test_using_gossip_key(self, account_maker):
        sender = account_maker()
        rec1, rec2 = account_maker(), account_maker()

        # make sure sender has all keys
        sender.process_incoming(gen_ac_mail_msg(rec1, sender))
        sender.process_incoming(gen_ac_mail_msg(rec2, sender))

        # send an encrypted mail from sender to both recipients
        gossip_msg = gen_ac_mail_msg(sender, [rec1, rec2])
        enc_msg = sender.encrypt_mime(gossip_msg, [rec1.addr, rec2.addr]).enc_msg
        rec1.process_incoming(enc_msg)

        # reply as one of the recipients
        reply_msg = gen_ac_mail_msg(rec1, [sender, rec2])
        enc_reply = rec1.encrypt_mime(reply_msg, [sender.addr, rec2.addr]).enc_msg
        r = sender.process_incoming(enc_reply)

        # gossiping the gossiped key
        assert r.gossip_pahs[rec2.addr].keydata

    def test_gossip_leaves_direct_key_alone(self, account_maker):
        sender = account_maker()
        rec1, rec2 = account_maker(), account_maker()
        # sender gets all keys directly
        sender.process_incoming(gen_ac_mail_msg(rec1, sender))
        sender.process_incoming(gen_ac_mail_msg(rec2, sender))

        # rec2 changes its key
        rec2new = account_maker()
        rec2new.addr = rec2.addr
        assert rec2new.ownstate.keyhandle != rec2.ownstate.keyhandle

        # one recipient gets a direct key from the other
        rec1.process_incoming(gen_ac_mail_msg(rec2new, rec1))
        ps = rec1.get_peerstate(rec2new.addr)
        assert ps.public_keyhandle == rec2new.ownstate.keyhandle

        # send an encrypted mail from sender to both recipients
        gossip_msg = gen_ac_mail_msg(sender, [rec1, rec2])
        enc_msg = sender.encrypt_mime(gossip_msg, [rec1.addr, rec2new.addr]).enc_msg
        rec1.process_incoming(enc_msg)

        ps = rec1.get_peerstate(rec2new.addr)
        assert ps.public_keyhandle == rec2new.ownstate.keyhandle

    @pytest.mark.parametrize("encrypt", ["opportunistic", "no", "yes"])
    def test_process_outgoing_with_enc_header_nopreference(self, account_maker, encrypt):
        sender, recipient = account_maker(), account_maker()

        # let's first send a message to get the autocrypt haeder accross
        msg = gen_ac_mail_msg(sender, [recipient])
        r = recipient.process_incoming(msg)
        assert r.pah.keydata

        msg2 = gen_ac_mail_msg(recipient, sender, ENCRYPT=encrypt)
        r = recipient.process_outgoing(msg2)
        assert "ENCRYPT" not in r.msg
        if encrypt == "opportunistic" or encrypt == "no":
            assert not mime.is_encrypted(r.msg)
        elif encrypt == "yes":
            assert mime.is_encrypted(r.msg)

    @pytest.mark.parametrize("encrypt", ["opportunistic", "no", "yes"])
    def test_process_outgoing_with_enc_header_mutual(self, account_maker, encrypt):
        sender, recipient = account_maker(), account_maker()

        sender.modify(prefer_encrypt="mutual")
        recipient.modify(prefer_encrypt="mutual")

        # let's first send a message to get the autocrypt haeder accross
        msg = gen_ac_mail_msg(sender, [recipient])
        r = recipient.process_incoming(msg)
        assert r.pah.keydata

        msg2 = gen_ac_mail_msg(recipient, sender, ENCRYPT=encrypt)
        r = recipient.process_outgoing(msg2)
        assert "ENCRYPT" not in r.msg
        if encrypt == "opportunistic" or encrypt == "yes":
            assert mime.is_encrypted(r.msg)
        elif encrypt == "no":
            assert not mime.is_encrypted(r.msg)

    def test_process_outgoing_with_enc_header_no_key(self, account_maker):
        sender, recipient = account_maker(), account_maker()

        msg2 = gen_ac_mail_msg(recipient, sender, ENCRYPT="yes")
        with pytest.raises(ValueError):
            recipient.process_outgoing(msg2)

    def test_process_outgoing_with_imported_keydata(self, account_maker, datadir):
        sender, recipient = account_maker(), account_maker()
        recipient.addr = "test1@autocrypt.org"
        keydata = datadir.read_bytes("test1_autocrypt_org.key")
        sender.import_keydata_as_autocrypt(addr=recipient.addr,
                                           prefer_encrypt="nopreference",
                                           keydata=keydata)
        msg2 = gen_ac_mail_msg(sender, recipient, ENCRYPT="yes")
        r = sender.process_outgoing(msg2)
        assert mime.is_encrypted(r.msg)


class TestAccountManager:
    def test_account_handling(self, tmpdir):
        tmpdir = tmpdir.strpath
        mc = AccountManager(tmpdir, plugin_manager=make_plugin_manager())
        assert not mc.exists()
        mc.init()
        assert mc.exists()
        mc.remove()
        assert not mc.exists()

    def test_account_header_defaults(self, manager_maker):
        account_manager = manager_maker(init=False)
        addr = "hello@xyz.org"
        account_manager.init()
        account = account_manager.add_account()
        assert account.ownstate.gpgmode == "own"
        account = account_manager.get_account_from_emailadr(addr)
        h = "Autocrypt: " + account.make_ac_header(addr)
        r = mime.parse_one_ac_header_from_string(h)
        assert r.addr == addr
        key = account.bingpg.get_public_keydata(account.ownstate.keyhandle)
        assert r.keydata == key
        assert r.prefer_encrypt == "nopreference"

    def test_add_one_and_check_defaults(self, manager):
        regex = "(office|work)@example.org"
        manager.add_account("office", regex)
        account = manager.get_account_from_emailadr("office@example.org")
        assert account.ownstate.prefer_encrypt == "nopreference"
        assert account.ownstate.email_regex == regex
        assert account.ownstate.keyhandle
        assert account.bingpg.get_public_keydata(account.ownstate.keyhandle)
        assert account.bingpg.get_secret_keydata(account.ownstate.keyhandle)
        assert str(account)
        manager.del_account("office")
        assert not manager.list_account_names()
        assert not manager.get_account_from_emailadr("office@example.org")

    @pytest.mark.filterwarnings("ignore:.*GNUPGHOME.*")
    def test_add_existing_key(self, manager_maker, datadir, gpgpath, monkeypatch):
        manage1 = manager_maker()
        account1 = manage1.get_account()
        monkeypatch.setenv("GNUPGHOME", account1.bingpg.homedir)
        manage2 = manager_maker(init=False)
        gpgbin = os.path.basename(gpgpath)
        manage2.init()
        account2 = manage2.add_account(
            "default", email_regex=".*",
            gpgmode="system", gpgbin=gpgbin,
            keyhandle=account1.ownstate.keyhandle)
        assert account2.ownstate.gpgmode == "system"
        assert account2.ownstate.gpgbin == gpgbin
        assert account2.ownstate.keyhandle == account1.ownstate.keyhandle

    def test_add_two(self, manager_maker):
        manager = manager_maker(init=False)
        manager.add_account("office", email_regex="office@example.org")
        manager.add_account("home", email_regex="home@example.org")

        account1 = manager.get_account_from_emailadr("office@example.org")
        assert account1.name == "office"
        account2 = manager.get_account_from_emailadr("home@example.org")
        assert account2.name == "home"
        account3 = manager.get_account_from_emailadr("hqweome@example.org")
        assert account3 is None

    def test_add_two_modify_one(self, manager):
        manager.add_account("office", email_regex="office@example.org")
        manager.add_account("home", email_regex="home@example.org")

        manager.mod_account("home", email_regex="newhome@example.org")
        account1 = manager.get_account_from_emailadr("office@example.org")
        assert account1.name == "office"
        assert not manager.get_account_from_emailadr("home@example.org")
        account3 = manager.get_account_from_emailadr("newhome@example.org")
        assert account3.name == "home"

    @pytest.mark.parametrize("pref", ["mutual", "nopreference"])
    def test_account_set_prefer_encrypt_and_header(self, manager_maker, pref):
        addr = "hello@xyz.org"
        manager = manager_maker()
        account = manager.get_account()
        with pytest.raises(ValueError):
            account.modify(prefer_encrypt="random")
        with pytest.raises(ValueError):
            manager.mod_account(account.name, prefer_encrypt="random")

        manager.mod_account(account.name, prefer_encrypt=pref)
        h = "Autocrypt: " + account.make_ac_header(addr)
        r = mime.parse_one_ac_header_from_string(h)
        assert r.addr == addr
        key = account.bingpg.get_public_keydata(account.ownstate.keyhandle)
        assert r.keydata == key
        assert r.prefer_encrypt == pref
