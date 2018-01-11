# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import os
import time
import pytest
from muacrypt.account import AccountManager, NotInitialized
from muacrypt import mime


def test_account_header_defaults(manager_maker):
    account_manager = manager_maker(init=False)
    addr = "hello@xyz.org"
    with pytest.raises(NotInitialized):
        account_manager.make_header(addr)
    account_manager.init()
    account = account_manager.add_account()
    assert account.ownstate.gpgmode == "own"
    h = account_manager.make_header(addr)
    d = mime.parse_one_ac_header_from_string(h)
    assert d["addr"] == addr
    key = account.bingpg.get_public_keydata(account.ownstate.keyhandle, b64=True)
    assert d["keydata"] == key
    assert d["prefer-encrypt"] == "nopreference"
    assert d["type"] == "1"


def test_account_handling(tmpdir):
    tmpdir = tmpdir.strpath
    mc = AccountManager(tmpdir)
    assert not mc.exists()
    mc.init()
    assert mc.exists()
    mc.remove()
    assert not mc.exists()


def test_account_parse_incoming_mail_broken_ac_header(manager_maker):
    addr = "a@a.org"
    ac2 = manager_maker()
    msg = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt="Autocrypt: to=123; key=12312k3")
    r = ac2.process_incoming(msg)
    assert not r.autocrypt_header


def test_account_parse_incoming_mail_and_raw_encrypt(manager_maker):
    addr = "a@a.org"
    ac1 = manager_maker()
    ac2 = manager_maker()
    msg = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac1.make_header(addr, headername=""))
    r = ac2.process_incoming(msg)
    assert r.peerstate.addr == addr
    account2 = ac2.get_account()
    account1 = ac1.get_account()
    enc = account2.bingpg.encrypt(data=b"123", recipients=[r.peerstate.public_keyhandle])
    data, descr_info = account1.bingpg.decrypt(enc)
    assert data == b"123"


def test_account_parse_incoming_mails_replace(manager_maker):
    ac1 = manager_maker()
    ac2 = manager_maker()
    ac3 = manager_maker()
    addr = "alice@a.org"
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac2.make_header(addr, headername=""))
    r = ac1.process_incoming(msg1)
    account2 = ac2.get_account_from_emailadr(addr)
    assert r.peerstate.public_keyhandle == account2.ownstate.keyhandle
    msg2 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac3.make_header(addr, headername=""))
    r2 = ac1.process_incoming(msg2)
    assert r2.peerstate.public_keyhandle == ac3.get_account().ownstate.keyhandle


def test_account_parse_incoming_mails_effective_date(manager_maker, monkeypatch):
    manager = manager_maker()
    fixed_time = time.time()
    later_date = 'Thu, 16 Feb 2050 15:00:00 -0000'
    monkeypatch.setattr(time, "time", lambda: fixed_time)
    addr = "alice@a.org"
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Date=later_date,
        Autocrypt=manager.make_header(addr, headername=""))
    r = manager.process_incoming(msg1)
    assert r.peerstate.last_seen == fixed_time


def test_account_parse_incoming_mails_replace_by_date(manager_maker):
    ac1 = manager_maker()
    ac2 = manager_maker()
    ac3 = manager_maker()
    addr = "alice@a.org"
    msg2 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac3.make_header(addr, headername=""),
        Date='Thu, 16 Feb 2017 15:00:00 -0000')
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac2.make_header(addr, headername=""),
        Date='Thu, 16 Feb 2017 13:00:00 -0000')
    r = ac1.process_incoming(msg2)
    assert r.account.get_peerstate(addr).public_keyhandle == \
        ac3.get_account().ownstate.keyhandle
    r2 = ac1.process_incoming(msg1)
    assert r2.peerstate.public_keyhandle == \
        ac3.get_account().ownstate.keyhandle
    msg3 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Date='Thu, 16 Feb 2017 17:00:00 -0000')
    r = ac1.process_incoming(msg3)
    assert not r.autocrypt_header
    assert r.peerstate.last_seen > r.peerstate.autocrypt_timestamp


def test_account_export_public_key(manager_maker, datadir):
    manager = manager_maker()
    account = manager.get_account()
    msg = mime.parse_message_from_file(datadir.open("rsa2048-simple.eml"))
    r = manager.process_incoming(msg)
    assert r.account.name == account.name
    assert r.account.export_public_key(r.peerstate.public_keyhandle)


class TestAccountManager:
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
        h = manager.make_header(addr)
        d = mime.parse_one_ac_header_from_string(h)
        assert d["addr"] == addr
        key = account.bingpg.get_public_keydata(account.ownstate.keyhandle, b64=True)
        assert d["keydata"] == key
        assert d["prefer-encrypt"] == pref
        assert d["type"] == "1"
