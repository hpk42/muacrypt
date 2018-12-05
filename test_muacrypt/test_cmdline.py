# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import print_function, unicode_literals
import os
import re
import six
import pytest
from muacrypt import mime
from .test_account import gen_ac_mail_msg


@pytest.fixture
def account_maker(mycmd):
    def account_maker(name, addr):
        mycmd.run_ok(["add-account", "-a", name, "--email-regex=" + addr])
        acc = mycmd.get_account(name)
        acc.addr = addr
        return acc
    return account_maker


def test_help(cmd):
    cmd.run_ok([], """
        *make-header*
        *export-public-key*
        *export-secret-key*
    """)
    cmd.run_ok(["--help"], """
        *access and manage*
    """)


def test_init_and_make_header(mycmd):
    mycmd.run_fail(["make-header", "xyz"], """
        *AccountNotFound*xyz*
    """)
    adr = "x@yz.org"
    mycmd.run_ok(["add-account", "--email-regex", adr])
    out = mycmd.run_ok(["make-header", adr])
    r = mime.parse_one_ac_header_from_string(out)
    assert "prefer-encrypt" not in out
    assert "type" not in out
    assert r.addr == adr
    out2 = mycmd.run_ok(["make-header", adr])
    assert out == out2


def test_init_and_make_header_with_envvar(cmd, tmpdir):
    with tmpdir.as_cwd():
        os.environ["MUACRYPT_BASEDIR"] = "."
        test_init_and_make_header(cmd)


def test_exports_and_status_plain(mycmd):
    mycmd.run_ok(["add-account", "--email-regex=123@z.org"])
    out = mycmd.run_ok(["export-public-key"])
    check_ascii(out)
    out = mycmd.run_ok(["export-secret-key"])
    check_ascii(out)
    out = mycmd.run_ok(["status"], """
        account-dir:*
        *account*default*
        *prefer-encrypt*nopreference*
        *own-keyhandle:*
    """)
    out = mycmd.run_ok(["status", "-v"], """
        account-dir:*
        *account*default*
        *prefer-encrypt*nopreference*
        *own-keyhandle:*
    """)


def check_ascii(out):
    if isinstance(out, six.text_type):
        out.encode("ascii")
    else:
        out.decode("ascii")


class TestProcessIncoming:
    def test_process_incoming(self, mycmd, datadir):
        mycmd.run_ok(["add-account", "-a", "account1", "--email-regex=some@example.org"])
        mail = datadir.read("rsa2048-simple.eml")
        mycmd.run_fail(["process-incoming"], """
            *AccountNotFound*bob@testsuite.autocrypt.org*
        """, input=mail)

        msg = mime.parse_message_from_string(mail)
        msg.replace_header("Delivered-To", "some@example.org")
        newmail = msg.as_string()
        out = mycmd.run_ok(["process-incoming"], """
            *processed*account*account1*
        """, input=newmail)

        # now export the public key
        m = re.search(r'key=(\w+)', out)
        keyhandle, = m.groups()
        mycmd.run_ok(["export-public-key", "--account=account1", keyhandle])
        mycmd.run_ok(["status"])

    def test_process_incoming_no_autocrypt(self, mycmd):
        mycmd.run_ok(["add-account", "--email-regex=b@b.org"])
        mycmd.run_ok(["peerstate", "a@a.org"])
        msg = mime.gen_mail_msg(From="Alice <a@a.org>", To=["b@b.org"], _dto=True)
        mycmd.run_ok(["process-incoming"], """
            *processed*default*no*Autocrypt*header*
        """, input=msg.as_string())
        mycmd.run_ok(["peerstate", "a@a.org"])

    def test_peerstate_with_ac_keys(self, mycmd, account_maker):
        acc1 = account_maker("acc1", "a@a.org")
        acc2 = account_maker("acc2", "b@b.org")
        acc2.process_incoming(gen_ac_mail_msg(acc1, acc2))
        mycmd.run_ok(["peerstate", "-a", "acc2", "a@a.org"])
        acc1.process_incoming(gen_ac_mail_msg(acc2, acc1))
        mycmd.run_ok(["peerstate", "-a", "acc1", "b@b.org"])

    def test_twice(self, mycmd, account_maker, linematch):
        acc1 = account_maker("acc1", "a@a.org")
        acc2 = account_maker("acc2", "b@b.org")
        msg = gen_ac_mail_msg(acc1, acc2)
        mycmd.run_ok(["process-incoming", "-a", "acc2"], input=msg.as_string())
        out = mycmd.run_ok(["process-incoming", "-a", "acc2"], input=msg.as_string())
        linematch(out, """
            *already known*
        """)
        out = mycmd.run_ok(["process-incoming", "-a", "acc2", "--reparse"], input=msg.as_string())
        linematch(out, """
            *processed*found*
        """)


class TestScandir:
    def test_scandir_incoming_ac(self, mycmd, account_maker, tmpdir):
        acc1 = account_maker("account1", "acc1@x.org")
        acc2 = account_maker("account2", "acc2@x.org")

        maildir = tmpdir.ensure("maildir", dir=True)
        msg = gen_ac_mail_msg(acc1, acc2, _dto=True)
        maildir.join("msg1").write(msg.as_string())

        peerstate = acc2.get_peerstate("acc1@x.org")
        assert not peerstate.has_direct_key()
        mycmd.run_ok(["scandir-incoming", str(maildir)])
        peerstate = acc2.get_peerstate("acc1@x.org")
        assert peerstate.has_direct_key()

    def test_scandir_incoming_ac_twice(self, mycmd, account_maker, tmpdir, linematch):
        acc1 = account_maker("account1", "acc1@x.org")
        acc2 = account_maker("account2", "acc2@x.org")

        maildir = tmpdir.ensure("maildir", dir=True)
        msg = gen_ac_mail_msg(acc1, acc2, _dto=True)
        maildir.join("msg1").write(msg.as_string())
        msg2 = gen_ac_mail_msg(acc1, acc2, _dto=True)
        maildir.join("msg2").write(msg2.as_string())
        mycmd.run_ok(["scandir-incoming", str(maildir)])
        peerstate = acc2.get_peerstate("acc1@x.org")
        assert peerstate.has_direct_key()
        out = mycmd.run_ok(["scandir-incoming", str(maildir)])
        linematch(out, """
            *already known*
        """)
        out = mycmd.run_ok(["scandir-incoming", "--reparse", str(maildir)])
        linematch(out, """
            *found Autocrypt*
        """)


class TestAccountCommands:
    def test_add_list_del_account(self, mycmd):
        mycmd.run_ok(["status"], """
            *no accounts configured*
        """)
        mycmd.run_ok(["add-account", "--email-regex=home@example.org"], """
            *account added*default*
        """)
        mycmd.run_ok(["status"], """
            *account*default*
            *home@example.org*
        """)
        mycmd.run_ok(["del-account"])
        mycmd.run_ok(["status"], """
            *no accounts configured*
        """)

    def test_add_two_accounts_requires_option(self, mycmd):
        mycmd.run_ok(["add-account"], """
            *account added*default*
        """)
        mycmd.run_fail(["add-account"], """
            AccountExists*default*
        """)

    def test_modify_account_prefer_encrypt(self, mycmd):
        mycmd.run_ok(["add-account"])
        mycmd.run_ok(["status"], """
            *account*default*
        """)
        mycmd.run_ok(["mod-account", "--prefer-encrypt=mutual"], """
            *account modified*default*
            *email?regex*.**
            *prefer-encrypt*mutual*
        """)
        mycmd.run_ok(["mod-account", "--email-regex=xyz"], """
            *account modified*default*
            *email?regex*xyz*
            *prefer-encrypt*mutual*
        """)

        mycmd.run_ok(["mod-account", "--prefer-encrypt=nopreference"], """
            *account modified*default*
            *email?regex*xyz*
            *prefer-encrypt*nopreference*
        """)

    def test_init_existing_key_native_gpg(self, mycmd, monkeypatch, bingpg, gpgpath):
        adr = "x@y.org"
        keyhandle = bingpg.gen_secret_key(adr)
        monkeypatch.setenv("GNUPGHOME", bingpg.homedir)
        mycmd.run_ok(["add-account", "--use-key", adr,
                      "--gpgbin=%s" % gpgpath, "--use-system-keyring"], """
                *gpgmode*system*
                *gpgbin*{}*
                *own-keyhandle*{}*
        """.format(gpgpath, keyhandle))
        mycmd.run_ok(["make-header", adr], """
            *Autocrypt*addr=x@y.org*
        """)

    def test_test_email(self, mycmd):
        mycmd.run_ok(["add-account", "--email-regex=(home|office)@example.org"])
        mycmd.run_ok(["find-account", "home@example.org"])
        mycmd.run_ok(["find-account", "office@example.org"])
        mycmd.run_fail(["find-account", "xhome@example.org"], """
            *AccountNotFound*xhome@example.org*
        """)


class TestProcessOutgoing:

    def test_simple(self, mycmd, gen_mail):
        mycmd.run_ok(["add-account"])
        mail = gen_mail()
        out1 = mycmd.run_ok(["process-outgoing"], input=mail.as_string())
        m = mime.parse_message_from_string(out1)
        assert len(m.get_all("Autocrypt")) == 1
        found_header = "Autocrypt: " + m["Autocrypt"]
        gen_header = mycmd.run_ok(["make-header", "a@a.org"])
        x1 = mime.parse_one_ac_header_from_string(gen_header)
        x2 = mime.parse_one_ac_header_from_string(found_header)
        assert x1 == x2

    def test_matching_account(self, mycmd, gen_mail):
        mycmd.run_ok(["add-account", "--email-regex=account1@a.org"])
        mail = gen_mail(From="x@y.org")
        # mycmd.run_fail(["process-outgoing"], input=mail.as_string(), fnl="""
        #     *AccountNotFound*x@y.org*
        # """)
        out0 = mycmd.run_fail(["process-outgoing"], input=mail.as_string())
        assert "Autocrypt" not in out0

        mail = gen_mail(From="account1@a.org")
        out1 = mycmd.run_ok(["process-outgoing"], input=mail.as_string())
        msg2 = mime.parse_message_from_string(out1)
        assert "account1@a.org" in msg2["Autocrypt"]

    def test_simple_dont_replace(self, mycmd, gen_mail):
        mycmd.run_ok(["add-account"])
        mail = gen_mail()
        gen_header = mycmd.run_ok(["make-header", "x@x.org"])
        mail.add_header("Autocrypt", gen_header)

        out1 = mycmd.run_ok(["process-outgoing"], input=mail.as_string())
        m = mime.parse_message_from_string(out1)
        assert len(m.get_all("Autocrypt")) == 1
        x1 = mime.parse_ac_headervalue(m["Autocrypt"])
        x2 = mime.parse_ac_headervalue(gen_header)
        assert x1 == x2

    @pytest.mark.parametrize("addr", ["a@a.org", "ño@example.org"])
    def test_sendmail(self, mycmd, gen_mail, popen_mock, addr):
        mycmd.run_ok(["add-account"])
        mail = gen_mail().as_string()
        pargs = ["-oi", addr]
        mycmd.run_ok(["sendmail", "-f", "--"] + pargs, input=mail)
        assert len(popen_mock.calls) == 1
        call = popen_mock.pop_next_call()
        for x in pargs:
            assert x in call.args
        # make sure unknown option is passed to pipe
        assert "-f" in call.args
        out_msg = mime.parse_message_from_string(call.input.decode("utf8"))
        assert "Autocrypt" in out_msg, out_msg.as_string()

    def test_sendmail_no_account(self, mycmd, gen_mail, popen_mock):
        mycmd.run_ok(["add-account", "--email-regex=account1@a.org"])
        mycmd.run_ok(["mod-account", "--email-regex", "123123"])
        mail = gen_mail().as_string()
        pargs = ["-oi", "b@b.org"]
        mycmd.run_fail(["sendmail", "-f", "--"] + pargs, input=mail)
        # assert len(popen_mock.calls) == 1
        # call = popen_mock.pop_next_call()
        # for x in pargs:
        #     assert x in call.args
        # # make sure unknown option is passed to pipe
        # assert "-f" in call.args
        # out_msg = mime.parse_message_from_string(call.input)
        # assert "Autocrypt" not in out_msg, out_msg.as_string()

    def test_sendmail_fails(self, mycmd, gen_mail, popen_mock):
        mycmd.run_ok(["add-account", "--email-regex=.*"])
        mail = gen_mail().as_string()
        pargs = ["-oi", "b@b.org"]
        popen_mock.mock_next_call(ret=2)
        mycmd.run_fail(["sendmail", "-f", "--", "--qwe"] + pargs, input=mail, code=2)
        assert len(popen_mock.calls) == 1
        call = popen_mock.pop_next_call()
        for x in pargs:
            assert x in call.args
        # make sure unknown option is passed to pipe
        assert "-f" in call.args
        assert "--qwe" in call.args

    def test_import_keydata(self, mycmd, datadir):
        mycmd.run_ok(["add-account"])
        keydata = datadir.read_bytes("test1_autocrypt_org.key")
        mycmd.run_ok(["import-public-key"], input=keydata)
        out = mycmd.run_ok(["recommend", "test1@autocrypt.org"])
        assert "available" in out

        mycmd.run_ok(["mod-account", "--prefer-encrypt", "mutual"])
        out = mycmd.run_ok(["import-public-key", "--prefer-encrypt=mutual"], input=keydata)
        assert "imported" in out
        out = mycmd.run_ok(["recommend", "test1@autocrypt.org"])
        assert "encrypt" in out

        mycmd.run_ok(["import-public-key", "--prefer-encrypt=nopreference"], input=keydata)
        out = mycmd.run_ok(["recommend", "test1@autocrypt.org"])
        assert "available" in out


class TestRecommendation:
    def test_recommend_empty(self, mycmd):
        mycmd.run_ok(["add-account", "-a", "home"])
        mycmd.run_ok(["recommend", "-a", "home", "unknown@email.org"])

    def test_recommend_one(self, mycmd):
        addr1 = "a@a.org"
        addr2 = "b@b.org"
        mycmd.run_ok(["add-account", "-a", "ac1", "--email-regex", addr1])
        mycmd.run_ok(["add-account", "-a", "ac2", "--email-regex", addr2])

        mycmd.send_mail(addr2, [addr1], Date=0)
        assert "available" == mycmd.parse_recommendation("ac1", [addr2])

        # switch addr2 and addr1 prefer_encrypt to "mutual", send a mail
        mycmd.run_ok(["mod-account", "-a", "ac1", "--prefer-encrypt", "mutual"])
        mycmd.run_ok(["mod-account", "-a", "ac2", "--prefer-encrypt", "mutual"])
        mycmd.send_mail(addr2, [addr1], Date=1)
        assert "encrypt" == mycmd.parse_recommendation("ac1", [addr2])

        # send a non-ac mail and ask recommend again
        mycmd.send_mail(addr2, [addr1], ac=False, Date=2)
        assert "available" == mycmd.parse_recommendation("ac1", [addr2])

    def test_recommend_two(self, mycmd):
        addrs = []
        for i in range(1, 4):
            addr = "%d@x.org" % i
            mycmd.run_ok(["add-account", "-a", "ac%d" % i, "--email-regex", addr])
            addrs.append(addr)
        addr1, addr2, addr3 = addrs

        mycmd.send_mail(addr2, [addr1])
        mycmd.send_mail(addr3, [addr1])
        assert "available" == mycmd.parse_recommendation("ac1", [addr2, addr2])

        # switch all accounts to mutual
        for name in "ac1 ac2 ac2".split():
            mycmd.run_ok(["mod-account", "-a", name, "--prefer-encrypt", "mutual"])
        mycmd.send_mail(addr2, [addr1])
        mycmd.send_mail(addr3, [addr1])
        assert "encrypt" == mycmd.parse_recommendation("ac1", [addr2, addr2])
