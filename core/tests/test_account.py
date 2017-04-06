# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import pytest
import logging

from autocrypt.account import IdentityConfig, Account, NotInitialized
from autocrypt import mime

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s -"\
         "%(funcName)s - %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)


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
    alice_ac = account_maker(init=False)
    logger.debug('alice_ac.list_identity_names %s',
                 alice_ac.list_identity_names())
    bob_adr = "bob@xyz.org"
    with pytest.raises(NotInitialized):
        alice_ac.make_header(bob_adr)
    alice_ac.init()
    logger.debug('alice_ac.list_identity_names %s',
                 alice_ac.list_identity_names())
    alice_ident = alice_ac.add_identity()
    logger.debug('alice_ac.list_identity_names %s',
                 alice_ac.list_identity_names())
    h = alice_ac.make_header(bob_adr)
    d = mime.parse_one_ac_header_from_string(h)
    assert d["to"] == bob_adr
    key = alice_ident.crypto.get_public_keydata(
            alice_ident.config.own_keyhandle, b64=True)
    assert d["key"] == key
    assert d["prefer-encrypt"] == "notset"
    assert d["type"] == "p"


def test_account_handling(tmpdir):
    tmpdir = tmpdir.strpath
    acc = Account(tmpdir)
    assert not acc.exists()
    acc.init()
    assert acc.exists()
    acc.remove()
    assert not acc.exists()


def test_account_parse_incoming_mail_broken_ac_header(account_maker):
    alice_adr = "a@a.org"
    alice_ac = account_maker()
    msg = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Autocrypt="Autocrypt: to=123; key=12312k3")
    peerinfo = alice_ac.process_incoming(msg)
    assert not peerinfo


def test_account_parse_incoming_mail_and_raw_encrypt(account_maker):
    alice_adr = "a@a.org"
    # create bob account
    bob_ac = account_maker()
    logger.debug('bob_ac %s', bob_ac)
    # create alice account
    alice_ac = account_maker()
    logger.debug('alice_ac %s', alice_ac)
    # alice generate mail for bob
    msg = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Autocrypt=alice_ac.make_header(alice_adr, headername=""))
    logger.debug('alice_ac generated msg for bob')
    # bob process mail from alice
    peerinfo = bob_ac.process_incoming(msg)
    logger.debug("bob_ac processed incoming msg %s", peerinfo)
    # the new bob's peer is alice
    assert peerinfo["to"] == alice_adr
    alice_ident = alice_ac.get_identity()
    logger.debug('alice_ident %s', alice_ident)
    bob_ident = bob_ac.get_identity()
    logger.debug('bob_ident %s', bob_ident)
    # bob encrypt message for alice
    enc = bob_ident.crypto.encrypt(data=b"123",
                                   recipients=[peerinfo.keyhandle])
    # alice decrypt message from bob
    data, descr_info = alice_ident.crypto.decrypt(str(enc))
    assert data == b"123"


def test_account_parse_incoming_mails_replace(account_maker):
    bob_ac = account_maker()
    alice_ac = account_maker()
    ac3 = account_maker()
    alice_adr = "alice@a.org"
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Autocrypt=alice_ac.make_header(alice_adr, headername=""))
    peerinfo = bob_ac.process_incoming(msg1)
    alice_ident = alice_ac.get_identity_from_emailadr([alice_adr])
    assert peerinfo.keyhandle == alice_ident.config.own_keyhandle
    msg2 = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Autocrypt=ac3.make_header(alice_adr, headername=""))
    peerinfo2 = bob_ac.process_incoming(msg2)
    assert peerinfo2.keyhandle == \
        ac3.get_identity().config.own_keyhandle


def test_account_parse_incoming_mails_replace_by_date(account_maker):
    bob_ac = account_maker()
    alice_ac = account_maker()
    ac3 = account_maker()
    alice_adr = "alice@a.org"
    msg2 = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Autocrypt=ac3.make_header(alice_adr, headername=""),
        Date='Thu, 16 Feb 2017 15:00:00 -0000')
    msg1 = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Autocrypt=alice_ac.make_header(alice_adr, headername=""),
        Date='Thu, 16 Feb 2017 13:00:00 -0000')
    peerinfo = bob_ac.process_incoming(msg2)
    id1 = peerinfo.identity
    assert id1.get_peerinfo(alice_adr).keyhandle == \
        ac3.get_identity().config.own_keyhandle
    bob_ac.process_incoming(msg1)
    assert id1.get_peerinfo(alice_adr).keyhandle == \
        ac3.get_identity().config.own_keyhandle
    msg3 = mime.gen_mail_msg(
        From="Alice <%s>" % alice_adr, To=["b@b.org"], _dto=True,
        Date='Thu, 16 Feb 2017 17:00:00 -0000')
    peerinfo = bob_ac.process_incoming(msg3)
    assert peerinfo is None
    assert bob_ac.get_identity().get_peerinfo(alice_adr) is None


def test_account_export_public_key(account, datadir):
    account.add_identity()
    msg = mime.parse_message_from_file(
            datadir.open("rsa2048-simple.eml"))
    peerinfo = account.process_incoming(msg)
    assert account.get_identity().export_public_key(peerinfo.keyhandle)


class TestIdentities:
    def test_add_one_and_check_defaults(self, account):
        regex = "(office|work)@example.org"
        account.add_identity("office", regex)
        logger.debug('added identity office to account %s', account)
        ident = account.get_identity_from_emailadr(
                    ["office@example.org"])
        logger.debug('got ident from mail %s', ident)
        assert ident.config.prefer_encrypt == "notset"
        assert ident.config.email_regex == regex
        assert ident.config.uuid
        assert ident.config.own_keyhandle
        assert ident.crypto.get_public_keydata(
                    ident.config.own_keyhandle)
        assert ident.crypto.get_secret_keydata(
                    ident.config.own_keyhandle)
        assert ident.config.peers == {}
        assert str(ident)
        account.del_identity("office")
        assert not account.list_identities()
        assert not account.get_identity_from_emailadr(
                    ["office@example.org"])

    def test_add_existing_key(self, account_maker, datadir):
        bob_ac = account_maker()
        logger.debug('created bob account %s', bob_ac)
        # logger.debug('bob_ac crypto %s', bob_ac.crypto)
        bob_ident = bob_ac.get_identity()
        logger.debug('created bob identity %s', bob_ident)
        logger.debug('bob_ident crypto %s', bob_ident.crypto)
        alice_ac = account_maker(init=False)
        logger.debug('created alice account without init %s', alice_ac)
        alice_ac.init()
        logger.debug('init alice_ac %s', alice_ac)
        # logger.debug('alice crypto %s', alice_ac.crypto)
        # # FIXME: alice can not have access to bob's private key
        # # to be correct it should add a key that is also in her "keyring"
        # # with private key
        # keyhandle = alice_ac.crypto.gen_secret_key()
        # alice_ident.crypto.publicpgpykeys = bob_ident.crypto.publicpgpykeys
        # alice_ident.crypto.secretpgpykeys = bob_ident.crypto.secretpgpykeys
        # alice_ident.crypto.export_keys()
        # alice_ident = alice_ac.add_identity(
        #     "default", email_regex=".*",
        #     keyhandle=bob_ident.config.own_keyhandle)
        # assert alice_ident.config.own_keyhandle == bob_ident.config.own_keyhandle

    def test_add_two(self, account):
        account.add_identity("office",
                             email_regex="office@example.org")
        account.add_identity("home",
                             email_regex="home@example.org")

        ident1 = account.get_identity_from_emailadr(
                    ["office@example.org"])
        assert ident1.config.name == "office"
        ident2 = account.get_identity_from_emailadr(
                    ["home@example.org"])
        assert ident2.config.name == "home"
        ident3 = account.get_identity_from_emailadr(
                    ["hqweome@example.org"])
        assert ident3 is None

    def test_add_two_modify_one(self, account):
        account.add_identity("office", email_regex="office@example.org")
        account.add_identity("home", email_regex="home@example.org")

        account.mod_identity("home", email_regex="newhome@example.org")
        ident1 = account.get_identity_from_emailadr(
                    ["office@example.org"])
        assert ident1.config.name == "office"
        assert not account.get_identity_from_emailadr(
                    ["home@example.org"])
        ident3 = account.get_identity_from_emailadr(
                    ["newhome@example.org"])
        assert ident3.config.name == "home"

    @pytest.mark.parametrize("pref", ["yes", "no", "notset"])
    def test_account_set_prefer_encrypt_and_header(self, account_maker,
                                                   pref):
        bob_ac = account_maker()
        bob_adr = "hello@xyz.org"
        bob_ident = bob_ac.get_identity()
        with pytest.raises(ValueError):
            bob_ident.modify(prefer_encrypt="random")
        with pytest.raises(ValueError):
            bob_ac.mod_identity(bob_ident.config.name,
                                prefer_encrypt="random")

        bob_ac.mod_identity(bob_ident.config.name, prefer_encrypt=pref)
        h = bob_ac.make_header(bob_adr)
        d = mime.parse_one_ac_header_from_string(h)
        assert d["to"] == bob_adr
        key = bob_ident.crypto.get_public_keydata(
                bob_ident.config.own_keyhandle, b64=True)
        assert d["key"] == key
        assert d["prefer-encrypt"] == pref
        assert d["type"] == "p"
