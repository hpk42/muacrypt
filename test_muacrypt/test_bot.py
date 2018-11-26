# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
from __future__ import unicode_literals, print_function

import six
import pytest
from muacrypt import mime
from muacrypt.bot import SimpleLog


@pytest.fixture(params=["sender@example.org", "sender <sender@example.org>"])
def ac_sender(manager_maker, request):
    manager = manager_maker(init=False)
    account = manager.add_account("sender", email_regex=request.param)
    account.adr = request.param
    account.ac_headerval = account.make_ac_header(account.adr)
    assert account.ac_headerval
    return account


@pytest.fixture
def bcmd(mycmd):
    adr = "bot@autocrypt.org"
    mycmd.run_ok(["add-account", "-a", "default", "--email-regex={}".format(adr)])
    mycmd.bot_adr = adr
    return mycmd


def decode_body(msg):
    assert msg.get_content_type() == "text/plain", msg.get_content_type()
    x = msg.get_payload(decode=True)
    cset = msg.get_content_charset()
    s = x.decode(cset if cset else "ascii")
    assert isinstance(s, six.text_type)
    return s


class TestSimpleLog:
    def test_basic(self):
        l = SimpleLog()
        l("hello")
        l("world")
        assert str(l) == "hello\nworld"

    def test_section(self):
        l = SimpleLog()
        with l.s("title"):
            l("hello")
            l("world")
        l("back")
        lines = str(l).splitlines()
        assert "title" in lines[0]
        assert not lines[1].strip()
        assert "  hello" == lines[2]
        assert "  world" == lines[3]
        assert not lines[4].strip()
        assert lines[5] == "back"
        with l.s("title2"):
            l("line2")
        l("back")
        lines = str(l).splitlines()
        assert not lines[6].strip()
        assert "title2" in lines[7]
        assert not lines[8].strip()
        assert lines[9] == "  " + "line2"
        assert not lines[10].strip()
        assert lines[11] == "back"

    def test_section_failing(self):
        l = SimpleLog()
        with l.s("some"):
            raise ValueError()
        lines = str(l).splitlines()
        assert "some" in lines[0]
        assert "Traceback" in lines[2]

    def test_section_failing_raising(self):
        l = SimpleLog()
        with pytest.raises(ValueError):
            with l.s("some", raising=True):
                raise ValueError()
        assert "some" in str(l)


class TestBot:
    def test_reply_no_delivto(self, bcmd, ac_sender, linematch):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Subject="hello")

        out = bcmd.run_ok(["bot-reply", "--fallback-delivto", bcmd.bot_adr],
                          input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        linematch(decode_body(reply_msg), """
            *processed*account*default*
        """)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["From"] == bcmd.bot_adr
        assert reply_msg["To"] == msg["From"]
        assert reply_msg["Autocrypt"]

    def test_empty_subject(self, bcmd, ac_sender):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject=None, _dto=True)

        bcmd.run_ok(["bot-reply"], input=msg.as_string())

    def test_reply_with_autocrypt(self, bcmd, ac_sender, linematch):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        linematch(decode_body(reply_msg), """
            *processed*account*default*
        """)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["From"] == bcmd.bot_adr
        assert reply_msg["To"] == msg["From"]
        assert reply_msg["Autocrypt"]
        r = mime.parse_ac_headervalue(reply_msg["Autocrypt"])
        assert r.addr == bcmd.bot_adr
        assert r.keydata
        body = decode_body(reply_msg)
        assert "no Autocrypt header" not in body
        assert "recommendation is available" in body
        print(body)

    def test_reply_with_cc_and_to_bot(self, bcmd, ac_sender):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Cc=['some@address.example'],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())
        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["To"] == send_adr
        assert reply_msg["Cc"] == msg["Cc"]

    def test_reply_with_cc_bot(self, bcmd, ac_sender):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=["some@address.example"],
            Cc=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=bcmd.bot_adr)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())
        assert not out

    def test_reply_puts_to_addresses_to_cc(self, bcmd, ac_sender, linematch):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=["bot2@example.org", bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=bcmd.bot_adr)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())
        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["To"] == send_adr
        assert reply_msg["Cc"] == "bot2@example.org"

    def test_reply_to_encrypted(self, bcmd, ac_sender, linematch):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        ac_sender.process_incoming(reply_msg)

        msg2 = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="encrypted", _dto=True)

        r = ac_sender.encrypt_mime(msg2, [bcmd.bot_adr])
        out2 = bcmd.run_ok(["bot-reply"], input=r.enc_msg.as_string())
        enc_reply_msg = mime.parse_message_from_string(out2)
        ac_sender.process_incoming(enc_reply_msg)
        decrypted = ac_sender.decrypt_mime(enc_reply_msg)
        body = decode_body(decrypted.dec_msg)
        print(body)
        linematch(body, """
            *processed*account*default*
        """)
        assert "no Autocrypt header" not in body
        assert "prefer_encrypt=nopreference" in body
        assert "recommendation is encrypt" in body

    def test_encrypted_if_mutual(self, bcmd, ac_sender, linematch):
        bcmd.run_ok(["mod-account", "--prefer-encrypt=mutual"])
        ac_sender.modify(prefer_encrypt='mutual')
        ac_sender.ac_headerval = ac_sender.make_ac_header(ac_sender.adr)
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["From"] == bcmd.bot_adr
        assert reply_msg["To"] == msg["From"]
        assert reply_msg["Autocrypt"]
        r = mime.parse_ac_headervalue(reply_msg["Autocrypt"])
        assert r.addr == bcmd.bot_adr
        assert r.keydata

        ac_sender.process_incoming(reply_msg)
        decrypted = ac_sender.decrypt_mime(reply_msg)
        body = decode_body(decrypted.dec_msg)
        linematch(body, """
            *processed*account*default*
        """)
        assert "no Autocrypt header" not in body
        assert "prefer_encrypt=mutual" in body
        assert "recommendation is encrypt" in body
        print(body)

    def test_reply_no_autocrypt(self, bcmd):
        adr = "somebody@example.org"
        msg = mime.gen_mail_msg(
            From=adr, To=[bcmd.bot_adr],
            Autocrypt=None, Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], input=msg.as_string())
        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["Autocrypt"]
        body = decode_body(reply_msg)
        print(body)
        assert "no valid autocrypt" in body.lower()

    @pytest.mark.parametrize("with_ac", [True, False])
    def test_send_reply(self, smtpserver, bcmd, ac_sender, with_ac, linematch):
        host, port = smtpserver.addr[:2]
        Autocrypt = None if not with_ac else ac_sender.ac_headerval
        msg = mime.gen_mail_msg(
            From=ac_sender.adr, To=[bcmd.bot_adr],
            MessageID=mime.make_msgid("5" * 50),  # long MessageID
            Autocrypt=Autocrypt, Subject="hello", _dto=True)

        bcmd.run_ok(["bot-reply", "--smtp={},{}".format(host, port)],
                    input=msg.as_string())

        assert len(smtpserver.outbox) == 1
        msg2 = smtpserver.outbox[0]
        assert msg2["To"] == msg["From"]
        assert msg2["From"] == msg["To"]
        assert msg2["In-Reply-To"] == msg["Message-ID"]
        assert msg["Subject"] in msg2["Subject"]
        body = decode_body(msg2)
        linematch(body, """
            *Got your mail*
            *Message-ID*{}*
        """.format(msg["Message-ID"][:20]))
        if with_ac:
            linematch(body, """
                *processed incoming*
                *{senderadr}*{senderkeyhandle}*
            """.format(
                senderadr=mime.parse_email_addr(ac_sender.adr),
                senderkeyhandle=ac_sender.ownstate.keyhandle,
            ))
