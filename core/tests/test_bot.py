# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
from __future__ import unicode_literals, print_function

import pytest
from autocrypt import mime


@pytest.fixture(params=["sender@example.org"])
def ac_sender(account, request):
    ident = account.add_identity("sender", email_regex=request.param)
    ident.adr = request.param
    ident.ac_headerval = ident.make_ac_header(ident.adr, headername="")
    assert ident.ac_headerval
    return ident


@pytest.fixture
def bcmd(mycmd):
    mycmd.run_ok(["init"])
    mycmd.bot_adr = "bot@autocrypt.org"
    return mycmd


class TestBot:
    def test_reply_no_delivto(self, bcmd, ac_sender):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Subject="hello")

        out = bcmd.run_ok(["bot-reply", "--fallback-delivto", bcmd.bot_adr], """
            *processed*identity*default*
        """, input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["From"] == bcmd.bot_adr
        assert reply_msg["To"] == msg["From"]
        assert reply_msg["Autocrypt"]

    def test_reply_with_autocrypt(self, bcmd, ac_sender):
        send_adr = ac_sender.adr
        msg = mime.gen_mail_msg(
            From=send_adr, To=[bcmd.bot_adr],
            Autocrypt=ac_sender.ac_headerval,
            Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], """
            *processed*identity*default*
        """, input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["From"] == bcmd.bot_adr
        assert reply_msg["To"] == msg["From"]
        assert reply_msg["Autocrypt"]
        ac_dict = mime.parse_ac_headervalue(reply_msg["Autocrypt"])
        assert ac_dict["to"] == bcmd.bot_adr
        assert ac_dict["key"]
        body = str(reply_msg.get_payload())
        assert "no Autocrypt header" not in body

    def test_reply_no_autocrypt(self, bcmd):
        adr = "somebody@example.org"
        msg = mime.gen_mail_msg(
            From=adr, To=[bcmd.bot_adr],
            Autocrypt=None, Subject="hello", _dto=True)

        out = bcmd.run_ok(["bot-reply"], """
            *processed*identity*default*
        """, input=msg.as_string())

        reply_msg = mime.parse_message_from_string(out)
        assert reply_msg["Subject"] == "Re: " + msg["Subject"]
        assert reply_msg["Autocrypt"]
        body = str(reply_msg.get_payload())
        print(body)
        assert "no autocrypt header" in body.lower()

    @pytest.mark.parametrize("with_ac", [True, False])
    def test_send_reply(self, smtpserver, bcmd, ac_sender, with_ac, linematch):
        host, port = smtpserver.addr[:2]
        Autocrypt = None if not with_ac else ac_sender.ac_headerval
        msg = mime.gen_mail_msg(
            From=ac_sender.adr, To=[bcmd.bot_adr],
            Autocrypt=Autocrypt, Subject="hello", _dto=True)

        bcmd.run_ok(["bot-reply", "--smtp={},{}".format(host, port)],
                    input=msg.as_string())

        assert len(smtpserver.outbox) == 1
        msg2 = smtpserver.outbox[0]
        assert msg2["To"] == msg["From"]
        assert msg2["From"] == msg["To"]
        assert msg["Subject"] in msg2["Subject"]
        body = str(msg2.get_payload())
        linematch(body, """
            *Got your mail*
            *Message-ID*{}*
        """.format(msg["Message-ID"]))
        if with_ac:
            linematch(body, """
                *processed incoming*found:*
                *{senderadr}*{senderkeyhandle}*
            """.format(
                senderadr=ac_sender.adr,
                senderkeyhandle=ac_sender.config.own_keyhandle,
            ))
