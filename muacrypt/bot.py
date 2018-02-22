# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""
Bot command line subcommand to receive and answer with Autocrypt related
information for mails to bot@autocrypt.org
"""
from __future__ import print_function

import sys
import six
import traceback
import contextlib
from . import mime
from .cmdline_utils import (
    get_account_manager, mycommand, click, trunc_string
)


def send_reply(host, port, msg):
    import smtplib
    smtp = smtplib.SMTP(host, port)
    return smtp.sendmail(msg["From"], msg["To"], msg.as_string())


@mycommand("bot-reply")
@click.option("--smtp", default=None, metavar="host,port",
              help="host and port where the reply should be "
                   "instead of to stdout.")
@click.option("--fallback-delivto", default=None,
              help="assume delivery to the specified email address if "
                   "no delivered-to header is found.")
@click.pass_context
def bot_reply(ctx, smtp, fallback_delivto):
    """reply to stdin mail as a bot.

    This command will generate a reply message and send it to stdout by default.
    The reply message contains an Autocrypt header and details of what
    was found and understood from the incoming mail.
    """
    account_manager = get_account_manager(ctx)
    msg = mime.parse_message_from_file(sys.stdin)
    From = msg["From"]

    log = SimpleLog()
    with log.s("reading headers", raising=True):
        delivto = mime.get_delivered_to(msg, fallback_delivto)
        log("determined Delivered-To: " + delivto)

    maxheadershow = 60

    with log.s("Got your mail, here is what i found in headers:"):
        for hn in ("Message-ID Delivered-To From To Subject "
                   "Date DKIM-Signature Autocrypt").split():
            if hn in msg:
                value = trunc_string(msg.get(hn).replace("\n", "\\n"), maxheadershow)
                log("{:15s} {}".format(hn + ":", value))
            else:
                log("{:15s} NOTFOUND".format(hn))

    with log.s("And this is the mime structure i saw:"):
        log(mime.render_mime_structure(msg))

    account = account_manager.get_account_from_emailadr(delivto)
    r = account.process_incoming(msg)
    with log.s("processed incoming mail for account {}:".format(r.account.name)):
        if r.pah.error:
            log(r.pah.error)
        else:
            ps = r.peerstate
            log("found peeraddr={} keyhandle={} prefer_encrypt={}".format(
                ps.addr, ps.public_keyhandle, ps.prefer_encrypt))

    log("\n")
    reply_to_encrypted = False
    if msg.get_content_type() == "multipart/encrypted":
        log("Your message was encrypted.")
        decrypted = account.decrypt_mime(msg)
        log("It was encrypted to the following keys:{}".format(
            decrypted.keyinfos))
        reply_to_encrypted = True

    log("have a nice day, {}".format(delivto))
    log("")
    log("P.S.: my current key {} is in the Autocrypt header of this reply."
        .format(r.account.ownstate.keyhandle))

    recom = account.get_recommendation([From], reply_to_encrypted)
    ui_recommendation = recom.ui_recommendation()
    log("P.P.S.: For this reply the encryption recommendation is {}"
        .format(ui_recommendation))

    reply_msg = mime.gen_mail_msg(
        From=delivto, To=[From],
        Subject="Re: " + msg["Subject"],
        _extra={"In-Reply-To": msg["Message-ID"]},
        Autocrypt=account.make_ac_header(delivto),
        payload=six.text_type(log), charset="utf8",
    )
    if ui_recommendation == 'encrypt':
        r = account.encrypt_mime(reply_msg, [From])
        reply_msg = r.enc_msg
    if smtp:
        host, port = smtp.split(",")
        send_reply(host, int(port), reply_msg)
        click.echo("send reply through smtp: {}".format(smtp))
    else:
        click.echo(reply_msg.as_string())


class SimpleLog:
    def __init__(self):
        self.logs = []
        self._indent = 0

    @property
    def indent(self):
        return u"  " * self._indent

    def __call__(self, msg=""):
        lines = msg.splitlines()
        if not lines:
            lines = [u""]
        self.logs.append(self.indent + lines[0])
        self.logs.extend([(self.indent + line) for line in lines[1:]])

    @contextlib.contextmanager
    def s(self, title, raising=False):
        # one extra empty line before a section
        if self.logs:
            self("")
        self(title)
        self()
        self._indent += 1
        try:
            try:
                yield
            finally:
                self._indent -= 1
        except Exception:
            if raising:
                raise
            self(traceback.format_exc())
        # one extra empty line after a section
        self("")

    def __str__(self):
        return "\n".join(self.logs)
