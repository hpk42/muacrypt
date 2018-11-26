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
    recipients = mime.get_target_emailadr(msg)
    return smtp.sendmail(msg["From"], recipients, msg.as_string())


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

    This command processes an incoming e-mail message for the bot
    and sends a reply if the bot was addressed in a "To" header.
    If the bot was only addressed in the CC header it will process
    the mail but not reply.

    If the bot replies, it will always do a group-reply: it replies
    to the sender and CCs anyone that was in CC or To.

    The reply message contains an Autocrypt header and details of what
    was found and understood from the incoming mail.

    If it is a group-reply and it is encrypted then the bot
    also adds Autocrypt-Gossip headers as mandated by the Level 1 spec.
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

    if delivto not in msg["To"]:
        # if we are not addressed directly we don't reply (to prevent
        # loops between CCed bots)
        return

    addrlist = mime.get_target_fulladr(msg)
    newlist = []
    for realname, addr in set(addrlist):
        if addr and addr != delivto:
            newlist.append(mime.formataddr((realname, addr)))

    reply_msg = mime.gen_mail_msg(
        From=delivto, To=[From], Cc=newlist,
        Subject="Re: " + msg.get("Subject", ""),
        _extra={"In-Reply-To": msg["Message-ID"]},
        Autocrypt=account.make_ac_header(delivto),
        payload=six.text_type(log), charset="utf8",
    )
    if ui_recommendation == 'encrypt':
        r = account.encrypt_mime(reply_msg, [From] + newlist)
        reply_msg = r.enc_msg
        assert mime.is_encrypted(reply_msg)
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
