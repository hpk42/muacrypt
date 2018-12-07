# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""Muacrypt Command line implementation.
"""
from __future__ import print_function

import os
import time
import datetime
import sys
import subprocess
import email
import click
import pluggy
import muacrypt
from .cmdline_utils import (
    get_account, get_account_manager, MyGroup, MyCommandUnknownOptions,
    out_red, log_info, mycommand,
)
from .account import AccountManager, AccountNotFound, effective_date, parse_date_to_float
from .bingpg import find_executable
from . import mime, hookspec
from .bot import bot_reply


@click.command(cls=MyGroup, context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--basedir", type=click.Path(),
              default=click.get_app_dir("muacrypt"),
              envvar="MUACRYPT_BASEDIR",
              help="directory where muacrypt state is stored")
@click.version_option()
@click.pass_context
def muacrypt_main(context, basedir):
    """access and manage Autocrypt keys, options, headers."""
    basedir = os.path.abspath(os.path.expanduser(basedir))
    context.account_manager = AccountManager(basedir, _pluginmanager)
    context.plugin_manager = _pluginmanager


@mycommand("destroy-all")
@click.option("--yes", default=False, is_flag=True,
              help="needs to be specified to actually destroy")
@click.pass_context
def destroy_all(ctx, yes):
    """destroy all muacrypt state.

    By default this command creates account(s) state in a directory with
    a default "catch-all" account which matches all email addresses
    and uses default settings.  If you want to have more fine-grained
    control (which gpg binary to use, which existing key to use, if to
    use an existing system key ring ...) specify "--no-account".
    """
    account_manager = get_account_manager(ctx)
    if not yes:
        out_red("specify --yes if you really want to destroy all state")
        ctx.exit(1)

    basedir = account_manager.dir
    if account_manager.exists():
        out_red("deleting directory: {}".format(basedir))
        account_manager.remove()
    else:
        log_info("state directory empty: {}".format(basedir))


option_use_key = click.option(
    "--use-key", default=None, type=str, metavar="KEYHANDLE", help= # NOQA
    "use specified secret key which must be findable "
    "through the specified keyhandle (e.g. email, keyid, fingerprint)")

option_use_system_keyring = click.option(
    "--use-system-keyring", default=False, is_flag=True, help= # NOQA
    "use system keyring for all secret/public keys instead of storing "
    "keyring state inside our account directory.")

option_gpgbin = click.option(
    "--gpgbin", default="gpg", type=str, metavar="FILENAME", help= # NOQA
    "use specified gpg filename. If it is a simple name it "
    "is looked up on demand through the system's PATH.")

option_email_regex = click.option(
    "--email-regex", default=None, type=str,
    help="regex for matching all email addresses belonging to this account.")

option_prefer_encrypt = click.option(
    "--prefer-encrypt", default=None,
    type=click.Choice(["nopreference", "mutual"]),
    help="modify prefer-encrypt setting, default is to not change it.")

account_option = click.option(
    "-a", "--account", "account_name", default="default", metavar="name",
    help="use this account name, and default to account named 'default'")

account_option_none = click.option(
    "-a", "--account", "account_name", default=None, metavar="name",
    help="if not set, automatically determine account")

verbose_option = click.option(
    "-v", "--verbose", default=False, is_flag=True, help="be more verbose")

option_reparse = click.option(
    "--reparse", default=False, is_flag=True,
    help="force reparsing message even if it is already known")


@mycommand("add-account")
@account_option
@option_use_key
@option_use_system_keyring
@option_gpgbin
@option_email_regex
@click.pass_context
def add_account(ctx, account_name, use_system_keyring,
                use_key, gpgbin, email_regex):
    """add named account for set of e-mail addresses.

    An account requires an account_name which is used to show, modify and delete it.

    Of primary importance is the "email_regex" which you typically
    set to a plain email address.   It is used when incoming or outgoing mails
    need to be associated with this account.

    Instead of generating an Autocrypt-compliant key (the default operation) you may
    specify an existing key with --use-key=keyhandle where keyhandle may be
    something for which gpg finds it with 'gpg --list-secret-keys keyhandle'.
    Typically you will then also specify --use-system-keyring to make use of
    your existing keys.  All incoming muacrypt keys will thus be statesd in
    the system key ring instead of an own keyring.
    """
    account_manager = get_account_manager(ctx)
    account = account_manager.add_account(
        account_name, keyhandle=use_key, gpgbin=gpgbin,
        gpgmode=u"system" if use_system_keyring else u"own",
        email_regex=email_regex
    )
    click.echo("account added: '{}'".format(account.name))
    _status_account(account)


@mycommand("mod-account")
@account_option
@option_use_key
@option_gpgbin
@option_email_regex
@option_prefer_encrypt
@click.pass_context
def mod_account(ctx, account_name, use_key, gpgbin, email_regex, prefer_encrypt):
    """modify properties of an existing account.

    Any specified option replaces the existing one.
    """
    account_manager = get_account_manager(ctx)
    changed, account = account_manager.mod_account(
        account_name, keyhandle=use_key, gpgbin=gpgbin,
        email_regex=email_regex, prefer_encrypt=prefer_encrypt,
    )
    s = " NOT " if not changed else " "
    click.echo("account{}modified: '{}'".format(s, account.name))
    _status_account(account)


@mycommand("del-account")
@account_option
@click.pass_context
def del_account(ctx, account_name):
    """delete an account, its keys and all state.

    Make sure you have a backup of your whole account directory first.
    """
    account_manager = get_account_manager(ctx)
    account_manager.del_account(account_name)
    click.echo("account deleted: {!r}".format(account_name))
    _status(account_manager, verbose=True)


@mycommand("find-account")
@click.argument("emailadr", type=str, required=True)
@click.pass_context
def find_account(ctx, emailadr):
    """print matching account for an e-mail address.

    Fail if no account matches.
    """
    account_manager = get_account_manager(ctx)
    account = account_manager.get_account_from_emailadr(emailadr, raising=True)
    click.echo(account.name)


@mycommand("make-header")
@click.option("--val", default=False, is_flag=True,
              help="only print autocrypt header value, not full header")
@click.argument("emailadr", type=click.STRING)
@click.pass_context
def make_header(ctx, emailadr, val):
    """print Autocrypt header for an emailadr. """
    account_manager = get_account_manager(ctx)
    account = account_manager.get_account_from_emailadr(emailadr, raising=True)
    header_val = account.make_ac_header(emailadr)
    if val:
        header = header_val
    else:
        header = "Autocrypt: " + header_val
    click.echo(header)


@mycommand("recommend")
@account_option
@click.argument("emailadr", type=click.STRING, nargs=-1)
@click.pass_context
def recommend(ctx, account_name, emailadr):
    """print Autocrypt UI recommendation for target e-mail addresses.
    The first line of output contains an ui recommendation of "discourage",
    "available" or "encrypt". Subsequent lines may contain additional information
    which you may process or ignore.
    """
    account = get_account(ctx, account_name)
    recommend = account.get_recommendation(list(emailadr))
    click.echo(recommend.ui_recommendation())


@mycommand("peerstate")
@account_option
@click.argument("emailadr", type=click.STRING, required=True)
@click.pass_context
def peerstate(ctx, account_name, emailadr):
    """print current autocrypt state information about a peer. """
    account = get_account(ctx, account_name)
    peerstate = account.get_peerstate(emailadr)

    def D(timestamp):
        if timestamp:
            d = datetime.datetime.fromtimestamp(timestamp)
            return d.isoformat()
        return ""

    click.echo("{: <16} {}".format("peer address", peerstate.addr))
    click.echo("{: <16} {}".format("keyhandle", peerstate.public_keyhandle))
    click.echo("{: <16} {}".format("direct_key", peerstate.has_direct_key()))
    click.echo("{: <16} {}".format("prefer_encrypt", peerstate.prefer_encrypt))

    click.echo("{: <16} {}".format("last_seen", D(peerstate.last_seen)))
    msg_entry = peerstate._latest_msg_entry()
    click.echo("{: <16} {}".format("last_msg", getattr(msg_entry, "msg_id", "")))

    click.echo("{: <16} {}".format("ac timestamp", D(peerstate.autocrypt_timestamp)))
    ac_entry = peerstate._latest_msg_entry()
    click.echo("{: <16} {}".format("last_ac_msg", getattr(ac_entry, "msg_id", "")))
    # XXX add gossip info (latest_gossip_entry)


@mycommand("process-incoming")
@account_option_none
@option_reparse
@click.pass_context
def process_incoming(ctx, reparse, account_name):
    """parse Autocrypt info from stdin message
    if it was addressed to one of our managed accounts.
    """
    account_manager = get_account_manager(ctx)
    msg = mime.parse_message_from_file(sys.stdin)

    if account_name is None:
        account = account_manager.get_matching_account_for_incoming_message(msg)
    else:
        account = account_manager.get_account(account_name)

    r = account.process_incoming(msg, ignore_existing=not reparse)
    if r is None:
        click.echo("message with {} already known, skipping processing".format(
                   msg["Message-Id"]))
        return

    if r.peerstate.autocrypt_timestamp == r.peerstate.last_seen:
        msg = "found: " + str(r.peerstate)
    else:
        msg = "no Autocrypt header found"
    click.echo("processed mail for account '{}', {}".format(
               r.account.name, msg))


@mycommand("scandir-incoming")
@option_reparse
@click.argument("directory", default=None, type=click.Path(), required=True)
@click.pass_context
def scandir_incoming(ctx, directory, reparse):
    """scan directory for incoming messages and process
    Autocrypt and Autocrypt-gossip headers from them.
    """
    from termcolor import colored as C

    def R(msg):
        return C(msg, "red")

    def G(msg):
        return C(msg, "green")

    account_manager = get_account_manager(ctx)
    now = time.time()

    def is_too_old(d):
        diffdays = (now - d) / (60 * 60 * 24)
        return diffdays > 90

    for i, lpath in enumerate(os.listdir(directory)):
        path = os.path.join(directory, lpath)
        st = os.stat(path)
        if is_too_old(st.st_mtime):
            print("[%s] msgfile %s older than 90 days, skipped" % (i, lpath))
            continue

        with open(path, "rb") as f:
            reader = getattr(email, "message_from_binary_file", email.message_from_file)
            msg = reader(f)
        if msg is None:
            continue
        msg_id = msg.get("message-id", None)
        if msg_id is None:
            continue
        msg_date = effective_date(parse_date_to_float(msg.get("Date")))
        if is_too_old(msg_date):
            print("[%s] message %s older than 90 days, skipped" % (i, msg_id))
            continue

        try:
            account = account_manager.get_matching_account_for_incoming_message(msg)
        except AccountNotFound as e:
            print("[%s] msg %s: %s" % (i, msg_id, e))
            continue
        except ValueError as e:
            print("[%s] msg %s: %s" % (i, msg_id, e))
            continue
        try:
            r = account.process_incoming(msg, ignore_existing=not reparse)
        except muacrypt.bingpg.InvocationFailure:
            print("[%s] msg could not decrypt %s, skipping" % (i, msg_id))
            continue
        if r is None:
            status = "already known message, skipped processing"
        elif r.pah is None:
            status = " (old)"
        elif not r.pah.error:
            status = "found Autocrypt addr={} keyhandle={}".format(
                r.peerstate.addr, r.peerstate.public_keyhandle,)
            if r.msg_date == r.peerstate.autocrypt_timestamp:
                status += G(" (updated)")
            else:
                status += " (old)"
        else:
            status = r.pah.error
            if "no valid Autocrypt header" not in r.pah.error:
                status = R(status)
        print("[%s] [%s] msg %s -- %s" % (i, account.name, msg_id, status))


@mycommand("process-outgoing")
@click.pass_context
def process_outgoing(ctx):
    """add Autocrypt header for outgoing mail if the From matches
    a managed account.

    We read mail from stdin by adding an Autocrypt
    header and send the resulting message to stdout.
    If the mail from stdin contains an Autocrypt header we keep it
    for the outgoing message and do not add one.
    """
    msg = _process_outgoing(ctx)
    click.echo(msg.as_string())


def _process_outgoing(ctx):
    account_manager = get_account_manager(ctx)
    Parser = getattr(email.parser, "BytesParser", email.parser.Parser)
    msg = Parser().parse(click.get_binary_stream("stdin"))
    addr = mime.parse_email_addr(msg["From"])
    account = account_manager.get_account_from_emailadr(addr)
    if account is None:
        raise click.ClickException("No Account associated for 'From: {}'".format(addr))
    else:
        r = account.process_outgoing(msg)
        dump_info_outgoing_result(r)
        return r.msg


def dump_info_outgoing_result(r):
    if r.added_autocrypt:
        log_info("Autocrypt header set for {!r}".format(r.addr))
    elif r.had_autocrypt:
        log_info("Found existing Autocrypt: {}...".format(r.had_autocrypt[:35]))


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
    assert args
    args = list(args)
    msg = _process_outgoing(ctx)
    input = msg.as_string().encode("utf-8")
    log_info(u"piping to: {}".format(" ".join(args)))
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


@mycommand("import-public-key")
@account_option
@click.option(
    "--prefer-encrypt", default="mutual",
    type=click.Choice(["nopreference", "mutual"]),
    help="prefer-encrypt setting for imported key")
@click.option(
    "--email", type=str, default=None,
    help="associate key with this e-mail address")
@click.pass_context
def import_public_key(ctx, account_name, prefer_encrypt, email):
    """import public key data as an Autocrypt key.

    This commands reads from stdin an ascii-armored public PGP key.
    By default all e-mail addresses contained in the UIDs will be
    associated with the key. Use options to change these default behaviours.
    """
    acc = get_account(ctx, account_name)
    keydata = sys.stdin.read().encode("ascii")
    r = acc.import_keydata_as_autocrypt(
        keydata=keydata, prefer_encrypt=prefer_encrypt, addr=email
    )
    click.echo("imported key {!r} with prefer-encrypt={} for addresses".format(
               r.keyhandle, r.prefer_encrypt))
    for addr in r.addrs:
        click.echo(" " + addr)


@mycommand("export-public-key")
@account_option
@click.argument("keyhandle_or_email", default=None, required=False)
@click.pass_context
def export_public_key(ctx, account_name, keyhandle_or_email):
    """print public key of own or peer account."""
    account = get_account(ctx, account_name)
    data = account.export_public_key(keyhandle_or_email)
    click.echo(data)


@mycommand("export-secret-key")
@account_option
@click.pass_context
def export_secret_key(ctx, account_name):
    """print secret key of own account."""
    account = get_account(ctx, account_name)
    data = account.export_secret_key()
    click.echo(data)


@mycommand()
@account_option_none
@verbose_option
@click.pass_context
def status(ctx, account_name, verbose):
    """print account info and status. """
    if account_name is None:
        account_manager = get_account_manager(ctx)
        _status(account_manager, verbose)
    else:
        _status_account(get_account(ctx, account_name), verbose)


def _status(account_manager, verbose):
    click.echo("account-dir: " + account_manager.dir)
    names = account_manager.list_account_names()
    if not names:
        out_red("no accounts configured")
        return
    for name in names:
        account = account_manager.get_account(name)
        _status_account(account, verbose)
        click.echo("")


def _status_account(account, verbose=False):
    ic = account.ownstate
    click.secho("account: {!r}".format(ic.name), bold=True)

    def kecho(name, value):
        click.echo("  {:16s} {}".format(name + ":", value))

    kecho("email_regex", ic.email_regex)
    if ic.gpgmode == "own":
        kecho("gpgmode", "{} [home: {}]".format(ic.gpgmode, account.bingpg.homedir))
    else:
        kecho("gpgmode", ic.gpgmode)
    if os.sep not in ic.gpgbin:
        kecho("gpgbin", "{} [currently resolves to: {}]".format(
              ic.gpgbin, find_executable(ic.gpgbin)))
    else:
        kecho("gpgbin", ic.gpgbin)

    kecho("prefer-encrypt", account.ownstate.prefer_encrypt)

    # print info on key including uids
    keyinfos = account.bingpg.list_public_keyinfos(account.ownstate.keyhandle)
    uids = set()
    for k in keyinfos:
        uids.update(k.uids)
    kecho("own-keyhandle", account.ownstate.keyhandle)
    for uid in uids:
        kecho("^^ uid", uid)

    if verbose:
        # print info on peers
        peernames = account.get_peername_list()
        if peernames:
            click.echo("  ----peers-----")
            for name in peernames:
                pi = account.get_peerstate(name)
                # when = time.ctime(pi.last_seen) if pi.last_seen else "never"
                if pi.last_seen == pi.autocrypt_timestamp:
                    status = "last-was-autocrypt"
                elif pi.public_keyhandle:
                    status = "past-autocrypt"
                else:
                    continue
                click.echo("  {to}: last seen key {keyhandle}, status: {status}, "
                           "last_seen: {last_seen}".format(
                               to=pi.addr, keyhandle=pi.public_keyhandle,
                               last_seen=time.ctime(pi.last_seen),
                               status=status))
        else:
            click.echo("  ---- no peers registered -----")


muacrypt_main.add_command(status)
muacrypt_main.add_command(add_account)
muacrypt_main.add_command(mod_account)
muacrypt_main.add_command(del_account)
muacrypt_main.add_command(find_account)
muacrypt_main.add_command(process_incoming)
muacrypt_main.add_command(scandir_incoming)
muacrypt_main.add_command(import_public_key)
muacrypt_main.add_command(peerstate)
muacrypt_main.add_command(recommend)
muacrypt_main.add_command(process_outgoing)
muacrypt_main.add_command(sendmail)
muacrypt_main.add_command(make_header)
muacrypt_main.add_command(export_public_key)
muacrypt_main.add_command(export_secret_key)
muacrypt_main.add_command(bot_reply)
muacrypt_main.add_command(destroy_all)


# we need a plugin manager early to add sub commands
def make_plugin_manager():
    pm = pluggy.PluginManager("muacrypt")
    pm.add_hookspecs(hookspec)
    pm.load_setuptools_entrypoints("muacrypt")
    pm.hook.add_subcommands(plugin_manager=pm, command_group=muacrypt_main)
    return pm


_pluginmanager = make_plugin_manager()
