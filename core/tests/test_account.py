# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import os
import pytest
from autocrypt.account import IdentityConfig, Account, NotInitialized
from autocrypt import mime


def test_identity_config(tmpdir):
    config = IdentityConfig(tmpdir.join("default").strpath)

    with pytest.raises(AttributeError):
        config.qwe

    assert not config.exists()

    assert config.uuid == ""
    assert config.own_keyhandle == ""
    assert config.peers == {}

    with config.atomic_change():
        config.uuid = "123"
        config.peers["hello"] = "world"
        assert config.exists()
    assert config.uuid == "123"
    assert config.peers["hello"] == "world"
    try:
        with config.atomic_change():
            config.uuid = "456"
            config.peers["hello"] = "aaaa"
            raise ValueError()
    except ValueError:
        assert config.uuid == "123"
        assert config.peers["hello"] == "world"
    else:
        assert 0


def test_account_header_defaults(account_maker):
    account = account_maker(init=False)
    addr = "hello@xyz.org"
    with pytest.raises(NotInitialized):
        account.make_header(addr)
    account.init()
    ident = account.add_identity()
    assert ident.config.gpgmode == "own"
    h = account.make_header(addr)
    d = mime.parse_one_ac_header_from_string(h)
    assert d["addr"] == addr
    key = ident.bingpg.get_public_keydata(ident.config.own_keyhandle, b64=True)
    assert d["keydata"] == key
    assert d["prefer-encrypt"] == "nopreference"
    assert d["type"] == "1"


def test_account_handling(tmpdir):
    tmpdir = tmpdir.strpath
    acc = Account(tmpdir)
    assert not acc.exists()
    acc.init()
    assert acc.exists()
    acc.remove()
    assert not acc.exists()


def test_account_parse_incoming_mail_broken_ac_header(account_maker):
    addr = "a@a.org"
    ac2 = account_maker()
    msg = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt="Autocrypt: to=123; key=12312k3")
    peerinfo = ac2.process_incoming(msg)
    assert not peerinfo


def test_account_parse_incoming_mail_and_raw_encrypt(account_maker):
    addr = "a@a.org"
    ac1 = account_maker()
    ac2 = account_maker()
    msg = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac1.make_header(addr, headername=""))
    peerinfo = ac2.process_incoming(msg)
    assert peerinfo["addr"] == addr
    ident2 = ac2.get_identity()
    ident1 = ac1.get_identity()
    enc = ident2.bingpg.encrypt(data=b"123", recipients=[peerinfo.keyhandle])
    data, descr_info = ident1.bingpg.decrypt(enc)
    assert data == b"123"


def test_account_parse_incoming_mails_replace(account_maker):
    ac1 = account_maker()
    ac2 = account_maker()
    ac3 = account_maker()
    addr = "alice@a.org"
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac2.make_header(addr, headername=""))
    peerinfo = ac1.process_incoming(msg1)
    ident2 = ac2.get_identity_from_emailadr([addr])
    assert peerinfo.keyhandle == ident2.config.own_keyhandle
    msg2 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac3.make_header(addr, headername=""))
    peerinfo2 = ac1.process_incoming(msg2)
    assert peerinfo2.keyhandle == ac3.get_identity().config.own_keyhandle


def test_account_parse_incoming_mails_replace_by_date(account_maker):
    ac1 = account_maker()
    ac2 = account_maker()
    ac3 = account_maker()
    addr = "alice@a.org"
    msg2 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac3.make_header(addr, headername=""),
        Date='Thu, 16 Feb 2017 15:00:00 -0000')
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Autocrypt=ac2.make_header(addr, headername=""),
        Date='Thu, 16 Feb 2017 13:00:00 -0000')
    peerinfo = ac1.process_incoming(msg2)
    id1 = peerinfo.identity
    assert id1.get_peerinfo(addr).keyhandle == ac3.get_identity().config.own_keyhandle
    ac1.process_incoming(msg1)
    assert id1.get_peerinfo(addr).keyhandle == ac3.get_identity().config.own_keyhandle
    msg3 = mime.gen_mail_msg(
        From="Alice <%s>" % addr, To=["b@b.org"], _dto=True,
        Date='Thu, 16 Feb 2017 17:00:00 -0000')
    peerinfo = ac1.process_incoming(msg3)
    assert peerinfo is None
    assert ac1.get_identity().get_peerinfo(addr) is None


def test_account_export_public_key(account, datadir):
    account.add_identity()
    msg = mime.parse_message_from_file(datadir.open("rsa2048-simple.eml"))
    peerinfo = account.process_incoming(msg)
    assert account.get_identity().export_public_key(peerinfo.keyhandle)


class TestIdentities:
    def test_add_one_and_check_defaults(self, account):
        regex = "(office|work)@example.org"
        account.add_identity("office", regex)
        ident = account.get_identity_from_emailadr(["office@example.org"])
        assert ident.config.prefer_encrypt == "nopreference"
        assert ident.config.email_regex == regex
        assert ident.config.uuid
        assert ident.config.own_keyhandle
        assert ident.bingpg.get_public_keydata(ident.config.own_keyhandle)
        assert ident.bingpg.get_secret_keydata(ident.config.own_keyhandle)
        assert ident.config.peers == {}
        assert str(ident)
        account.del_identity("office")
        assert not account.list_identities()
        assert not account.get_identity_from_emailadr(["office@example.org"])

    def test_add_existing_key(self, account_maker, datadir, gpgpath, monkeypatch):
        acc1 = account_maker()
        ident1 = acc1.get_identity()
        monkeypatch.setenv("GNUPGHOME", ident1.bingpg.homedir)
        acc2 = account_maker(init=False)
        gpgbin = os.path.basename(gpgpath)
        acc2.init()
        ident2 = acc2.add_identity(
            "default", email_regex=".*",
            gpgmode="system", gpgbin=gpgbin,
            keyhandle=ident1.config.own_keyhandle)
        assert ident2.config.gpgmode == "system"
        assert ident2.config.gpgbin == gpgbin
        assert ident2.config.own_keyhandle == ident1.config.own_keyhandle

    def test_add_two(self, account):
        account.add_identity("office", email_regex="office@example.org")
        account.add_identity("home", email_regex="home@example.org")

        ident1 = account.get_identity_from_emailadr(["office@example.org"])
        assert ident1.config.name == "office"
        ident2 = account.get_identity_from_emailadr(["home@example.org"])
        assert ident2.config.name == "home"
        ident3 = account.get_identity_from_emailadr(["hqweome@example.org"])
        assert ident3 is None

    def test_add_two_modify_one(self, account):
        account.add_identity("office", email_regex="office@example.org")
        account.add_identity("home", email_regex="home@example.org")

        account.mod_identity("home", email_regex="newhome@example.org")
        ident1 = account.get_identity_from_emailadr(["office@example.org"])
        assert ident1.config.name == "office"
        assert not account.get_identity_from_emailadr(["home@example.org"])
        ident3 = account.get_identity_from_emailadr(["newhome@example.org"])
        assert ident3.config.name == "home"

    @pytest.mark.parametrize("pref", ["mutual", "nopreference"])
    def test_account_set_prefer_encrypt_and_header(self, account_maker, pref):
        account = account_maker()
        addr = "hello@xyz.org"
        ident = account.get_identity()
        with pytest.raises(ValueError):
            ident.modify(prefer_encrypt="random")
        with pytest.raises(ValueError):
            account.mod_identity(ident.config.name, prefer_encrypt="random")

        account.mod_identity(ident.config.name, prefer_encrypt=pref)
        h = account.make_header(addr)
        d = mime.parse_one_ac_header_from_string(h)
        assert d["addr"] == addr
        key = ident.bingpg.get_public_keydata(ident.config.own_keyhandle, b64=True)
        assert d["keydata"] == key
        assert d["prefer-encrypt"] == pref
        assert d["type"] == "1"
