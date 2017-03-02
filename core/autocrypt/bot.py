# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""
simple bot functionality to work answering for bot@autocrypt.org
"""

import sys
import traceback
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

    _, delivto = mime.parse_email_addr(msg.get("Delivered-To"))
    if not delivto and fallback_delivto:
        _, delivto = mime.parse_email_addr(fallback_delivto)
    if not delivto:
        raise ValueError("could not determine my own delivered-to address")

    maxheadershow = 60

    log = SimpleLog()

    log("* Got your mail, here are some headers i saw or didn't see from you:")
    log()
    for hn in ("Message-ID Delivered-To From To Subject "
               "Date DKIM-Signature Autocrypt").split():
        if hn in msg:
            value = trunc_string(msg.get(hn).replace("\n", "\\n"), maxheadershow)
            log("  {:15s} {}".format(hn + ":", value))
        else:
            log("  {:15s} NOTFOUND".format(hn))

    log()
    log("* now i am going to process your mail through py-autocrypt")
    try:
        ident = account.get_identity_from_emailadr([delivto])
        peerinfo = account.process_incoming(msg, delivto=delivto)
        if peerinfo is not None:
            log("\nprocessed incoming mail for identity '{}', found:\n{}".format(
                ident.config.name, peerinfo))
        else:
            log("\nprocessed incoming mail for identity '{}', "
                "no Autocrypt header found.".format(ident.config.name))

        log("\n")
        log("have a nice day, {}".format(delivto))
        log("")
        log("P.S.: my current key {} is in the Autocrypt header of this reply."
            .format(ident.config.own_keyhandle))

    except Exception:
        log(traceback.format_exc())

    reply_msg = mime.gen_mail_msg(
        From=delivto, To=[From],
        Subject="Re: " + msg["Subject"],
        _extra={"In-Reply-To": msg["Message-ID"]},
        Autocrypt=account.make_header(delivto, headername=""),
        body=str(log)
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

    def __call__(self, msg=""):
        lines = msg.splitlines()
        if not lines:
            lines = [""]
        self.logs.append(lines[0])
        self.logs.extend([("  " + line) for line in lines[1:]])

    def __str__(self):
        return "\n".join(self.logs)
