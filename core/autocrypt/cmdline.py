# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""Autocrypt Command line implementation.
"""

from __future__ import print_function

import logging
import os
import sys
import subprocess
import six
import click
from .cmdline_utils import (
    get_account, MyGroup, MyCommandUnknownOptions,
    out_red, log_info, mycommand,
)
from .account import Account, IdentityNotFound
from .utils import find_executable
from . import mime
from .bot import bot_reply

FORMAT = "%(levelname)s: %(filename)s:%(lineno)s -"\
         "%(funcName)s - %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)

@click.command(cls=MyGroup, context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--basedir", type=click.Path(),
              default=click.get_app_dir("autocrypt"),
              envvar="AUTOCRYPT_BASEDIR",
              help="directory where autocrypt account state is stored")
@click.version_option()
@click.pass_context
def autocrypt_main(context, basedir):
    """access and manage Autocrypt keys, options, headers."""
    basedir = os.path.abspath(os.path.expanduser(basedir))
    context.account = Account(basedir)


@mycommand()
@click.option("--replace", default=False, is_flag=True,
              help="delete autocrypt account directory before attempting init")
@click.option("--no-identity", default=False, is_flag=True,
              help="initializing without creating a default identity")
@click.pass_context
def init(ctx, replace, no_identity):
    """init autocrypt account state.

    By default this command creates account state in a directory with
    a default "catch-all" identity which matches all email addresses
    and uses default settings.  If you want to have more fine-grained
    control (which gpg binary to use, which existing key to use, if to
    use an existing system key ring ...) specify "--no-identity".
    """
    account = ctx.parent.account
    if account.exists():
        if not replace:
            out_red("account exists at {} and --replace was not specified".format(
                    account.dir))
            ctx.exit(1)
        else:
            out_red("deleting account directory: {}".format(account.dir))
            account.remove()
    if not os.path.exists(account.dir):
        os.mkdir(account.dir)
    account.init()
    click.echo("account directory initialized: {}".format(account.dir))
    if not no_identity:
        account.add_identity("default")
    _status(account)


option_use_key = click.option(
    "--use-key", default=None, type=str, metavar="KEYHANDLE", help= # NOQA
    "use specified secret key which must be findable "
    "through the specified keyhandle (e.g. email, keyid, fingerprint)")


option_email_regex = click.option(
    "--email-regex", default=".*", type=str, help= # NOQA
    "regex for matching all email addresses belonging to this identity.")

option_prefer_encrypt = click.option(
    "--prefer-encrypt", default=None, type=click.Choice(["notset", "yes", "no"]),
    help="modify prefer-encrypt setting, default is to not change it.")


@mycommand("add-identity")
@click.argument("identity_name", type=str, required=True)
@option_use_key
@option_email_regex
@click.pass_context
def add_identity(ctx, identity_name,
                 use_key, email_regex):
    """add an identity to this account.

    An identity requires an identity_name which is used to show, modify and delete it.

    Of primary importance is the "email_regex" which you typically
    set to a plain email address.   It is used when incoming or outgoing mails
    need to be associated with this identity.

    Instead of generating a key (the default operation) you may specify an
    existing key with --use-key=keyhandle where keyhandle may be
    something for which gpg finds it with 'gpg --list-secret-keys keyhandle'.
    Typically you will then also specify --use-system-keyring to make use of
    your existing keys.  All incoming autocrypt keys will thus be stored in
    the system key ring instead of an own keyring.
    """
    account = get_account(ctx)
    ident = account.add_identity(
        identity_name, keyhandle=use_key, email_regex=email_regex
    )
    click.echo("identity added: '{}'".format(ident.config.name))
    _status_identity(ident)


@mycommand("mod-identity")
@click.argument("identity_name", type=str, required=True)
@option_use_key
@option_email_regex
@option_prefer_encrypt
@click.pass_context
def mod_identity(ctx, identity_name, use_key, email_regex, prefer_encrypt):
    """modify properties of an existing identity.

    An identity requires an identity_name.

    Any specified option replaces the existing one.
    """
    account = get_account(ctx)
    changed, ident = account.mod_identity(
        identity_name, keyhandle=use_key,
        email_regex=email_regex, prefer_encrypt=prefer_encrypt,
    )
    s = " NOT " if not changed else " "
    click.echo("identity{}modified: '{}'".format(s, ident.config.name))
    _status_identity(ident)


@mycommand("del-identity")
@click.argument("identity_name", type=str, required=True)
@click.pass_context
def del_identity(ctx, identity_name):
    """delete an identity, its keys and all state.

    Make sure you have a backup of your whole account directory first.
    """
    account = get_account(ctx)
    account.del_identity(identity_name)
    click.echo("identity deleted: {!r}".format(identity_name))
    _status(account)


@mycommand("test-email")
@click.argument("emailadr", type=str, required=True)
@click.pass_context
def test_email(ctx, emailadr):
    """test which identity an email belongs to.

    Fail if no identity matches.
    """
    account = get_account(ctx)
    ident = account.get_identity_from_emailadr([emailadr], raising=True)
    click.echo(ident.config.name)


@mycommand("make-header")
@click.argument("emailadr", type=click.STRING)
@click.pass_context
def make_header(ctx, emailadr):
    """print autocrypt header for an emailadr. """
    account = get_account(ctx)
    click.echo(account.make_header(emailadr))


@mycommand("set-prefer-encrypt")
@click.argument("value", default=None, required=False,
                type=click.Choice(["notset", "yes", "no"]))
@click.pass_context
def set_prefer_encrypt(ctx, value):
    """print or set prefer-encrypted setting."""
    account = get_account(ctx)
    if value is None:
        click.echo(account.get_identity().config.prefer_encrypt)
    else:
        value = six.text_type(value)
        account.get_identity().set_prefer_encrypt(value)
        click.echo("set prefer-encrypt to %r" % value)


@mycommand("process-incoming")
@click.pass_context
def process_incoming(ctx):
    """parse autocrypt headers from stdin mail. """
    account = get_account(ctx)
    msg = mime.parse_message_from_file(sys.stdin)
    peerinfo = account.process_incoming(msg)
    if peerinfo is not None:
        click.echo("processed mail for identity '{}', found: {}".format(
                   peerinfo.identity.config.name, peerinfo))
    else:
        # XXX account.process_incoming() should return the identity
        _, delivto = mime.parse_email_addr(msg.get("Delivered-To"))
        ident = account.get_identity_from_emailadr([delivto])
        click.echo("processed mail for identity '{}', no Autocrypt header found.".format(
                   ident.config.name))


@mycommand("process-outgoing")
@click.pass_context
def process_outgoing(ctx):
    """add autocrypt header for outgoing mail.

    We process mail from stdin by adding an Autocrypt
    header and send the resulting message to stdout.
    If the mail from stdin contains an Autocrypt header we keep it
    for the outgoing message and do not add one.
    """
    account = get_account(ctx)
    msg, emailadr = _prepare_stdin_message(account)
    click.echo(msg.as_string())


@click.command(cls=MyCommandUnknownOptions)
@click.argument("args", nargs=-1)
@click.pass_context
def sendmail(ctx, args):
    """as process-outgoing but submit to sendmail binary.

    Processes mail from stdin by adding an Autocrypt
    header and pipes the resulting message to the "sendmail" program.
    If the mail from stdin contains an Autocrypt header we use it
    for the outgoing message and do not add one.

    Note that unknown options and all arguments are passed through to the
    "sendmail" program.
    """
    logger.info('args %s', args)
    assert args
    account = get_account(ctx)
    args = list(args)
    msg, emailadr = _prepare_stdin_message(account)

    input = msg.as_string()
    log_info("piping to: {}".format(" ".join(args)))
    sendmail = find_executable("sendmail")
    if not sendmail:
        sendmail = "/usr/sbin/sendmail"

    args.insert(0, sendmail)
    popen = subprocess.Popen(args, stdin=subprocess.PIPE)
    popen.communicate(input=input)
    ret = popen.wait()
    if ret != 0:
        out_red("sendmail return {!r} exitcode, path: {}".format(
                ret, sendmail))
        ctx.exit(ret)


def _prepare_stdin_message(account):
    msg = mime.parse_message_from_file(sys.stdin)
    _, adr = mime.parse_email_addr(msg["From"])
    if "Autocrypt" not in msg:
        h = account.make_header(adr, headername="")
        if not h:
            raise IdentityNotFound("no identity associated with {}".format([adr]))
        msg["Autocrypt"] = h
        log_info("Autocrypt header set for {!r}".format(adr))
    else:
        log_info("Found existing Autocrypt: {}...".format(msg["Autocrypt"][:35]))
    return msg, adr


id_option = click.option(
    "--id", default="default", metavar="identity",
    help="perform lookup through this identity")


@mycommand("export-public-key")
@id_option
@click.argument("keyhandle_or_email", default=None, required=False)
@click.pass_context
def export_public_key(ctx, id, keyhandle_or_email):
    """print public key of own or peer account."""
    account = get_account(ctx)
    ident = account.get_identity(id)
    data = ident.export_public_key(keyhandle_or_email)
    click.echo(data)


@mycommand("export-secret-key")
@id_option
@click.pass_context
def export_secret_key(ctx, id):
    """print secret key of own autocrypt account. """
    account = get_account(ctx)
    ident = account.get_identity(id)
    data = ident.export_secret_key()
    click.echo(data)


@mycommand()
@click.pass_context
def status(ctx):
    """print account and identity info. """
    account = get_account(ctx)
    _status(account)


def _status(account):
    click.echo("account-dir: " + account.dir)
    identities = account.list_identities()
    if not identities:
        out_red("no identities configured")
        return
    for ident in account.list_identities():
        _status_identity(ident)


def _status_identity(ident):
    ic = ident.config
    click.echo("")
    click.secho("identity: '{}' uuid {}".format(ic.name, ic.uuid), bold=True)

    def kecho(name, value):
        click.echo("  {:16s} {}".format(name + ":", value))

    kecho("email_regex", ic.email_regex)

    kecho("prefer-encrypt", ic.prefer_encrypt)

    # print info on key including uids
    keyinfos = ident.crypto.list_public_keyinfos(ic.own_keyhandle)
    uids = set()
    for k in keyinfos:
        uids.update(k.uids)
    kecho("own-keyhandle", ic.own_keyhandle)
    for uid in uids:
        kecho("^^ uid", uid)

    # print info on peers
    peers = ic.peers
    if peers:
        click.echo("  ----peers-----")
        for name, ac_dict in peers.items():
            d = ac_dict.copy()
            click.echo("  {to}: key {keyhandle} [{bytes:d} bytes] {attrs}".format(
                       to=d.pop("to"), keyhandle=d.pop("*keyhandle"),
                       bytes=len(d.pop("key")),
                       attrs="; ".join(["%s=%s" % x for x in d.items()])))
    else:
        click.echo("  ---- no peers registered -----")


autocrypt_main.add_command(init)
autocrypt_main.add_command(status)
autocrypt_main.add_command(add_identity)
autocrypt_main.add_command(mod_identity)
autocrypt_main.add_command(del_identity)
autocrypt_main.add_command(process_incoming)
autocrypt_main.add_command(process_outgoing)
autocrypt_main.add_command(sendmail)
autocrypt_main.add_command(test_email)
autocrypt_main.add_command(make_header)
autocrypt_main.add_command(export_public_key)
autocrypt_main.add_command(export_secret_key)
autocrypt_main.add_command(bot_reply)
