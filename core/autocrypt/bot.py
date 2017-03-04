# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""
simple bot functionality to work answering for bot@autocrypt.org
"""
from __future__ import print_function

import sys
import six
import traceback
import contextlib
from . import mime
from .cmdline_utils import (
    get_account, mycommand, click, trunc_string
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
    was found and understood from the bot and it's autocrypt account code
    in the stdin message.
    """
    account = get_account(ctx)
    msg = mime.parse_message_from_file(sys.stdin)
    From = msg["From"]

    log = SimpleLog()
    with log.s("reading headers", raising=True):
        _, delivto = mime.parse_email_addr(msg.get("Delivered-To"))
        if not delivto and fallback_delivto:
            _, delivto = mime.parse_email_addr(fallback_delivto)
        if not delivto:
            raise ValueError("could not determine my own delivered-to address")
        log("determined my own Delivered-To: " + delivto)

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

    with log.s("processing your mail through py-autocrypt:"):
        ident = account.get_identity_from_emailadr([delivto])
        peerinfo = account.process_incoming(msg, delivto=delivto)
        if peerinfo is not None:
            log("processed incoming mail for identity '{}', found:\n{}".format(
                ident.config.name, peerinfo))
        else:
            log("processed incoming mail for identity '{}', "
                "no Autocrypt header found.".format(ident.config.name))

    log("\n")
    log("have a nice day, {}".format(delivto))
    log("")
    log("P.S.: my current key {} is in the Autocrypt header of this reply."
        .format(ident.config.own_keyhandle))

    reply_msg = mime.gen_mail_msg(
        From=delivto, To=[From],
        Subject="Re: " + msg["Subject"],
        _extra={"In-Reply-To": msg["Message-ID"]},
        Autocrypt=account.make_header(delivto, headername=""),
        body=six.text_type(log)
    )
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
        except:
            if raising:
                raise
            self(traceback.format_exc())
        # one extra empty line after a section
        self("")

    def __str__(self):
        return "\n".join(self.logs)
