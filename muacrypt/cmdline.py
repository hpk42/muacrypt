# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""Muacrypt Command line implementation.
"""
from __future__ import print_function

import os
import sys
import subprocess
import click
import pluggy
from .cmdline_utils import (
    get_account, get_account_manager, MyGroup, MyCommandUnknownOptions,
    out_red, log_info, mycommand,
)
from .account import AccountManager  # , AccountNotFound
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
def autocrypt_main(context, basedir):
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


@mycommand("add-account")
@click.argument("account_name", type=str, required=True)
@option_use_key
@option_use_system_keyring
@option_gpgbin
@option_email_regex
@click.pass_context
def add_account(ctx, account_name, use_system_keyring,
                use_key, gpgbin, email_regex):
    """add a named account.

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
        gpgmode="system" if use_system_keyring else "own",
        email_regex=email_regex
    )
    click.echo("account added: '{}'".format(account.name))
    _status_account(account)


@mycommand("mod-account")
@click.argument("account_name", type=str, required=True)
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
@click.argument("account_name", type=str, required=True)
@click.pass_context
def del_account(ctx, account_name):
    """delete an account, its keys and all state.

    Make sure you have a backup of your whole account directory first.
    """
    account_manager = get_account_manager(ctx)
    account_manager.del_account(account_name)
    click.echo("account deleted: {!r}".format(account_name))
    _status(account_manager)


account_option = click.option(
    "-a", "--account", default=u"default", metavar="name",
    help="perform lookup through this account")


@mycommand("test-email")
@click.argument("emailadr", type=str, required=True)
@click.pass_context
def test_email(ctx, emailadr):
    """test which account an email belongs to.

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
    header = account_manager.make_header(emailadr)
    if val:
        header = header.split("Autocrypt: ", 1)[1]
    click.echo(header)


@mycommand("recommend")
@click.argument("account_name", type=str, required=True)
@click.argument("emailadr", type=click.STRING, nargs=-1)
@click.pass_context
def recommend(ctx, account_name, emailadr):
    """print AC Level 1 recommendation for sending from an
    account to one or more target addresses. The first
    line contains an ui recommendation of "discourage", "available"
    or "encrypt". Subsequent lines may contain additional information.
    """
    account = get_account(ctx, account_name)
    recommend = account.get_recommendation(list(emailadr))
    click.echo(recommend.ui_recommendation())


@mycommand("process-incoming")
@click.pass_context
def process_incoming(ctx):
    """parse Autocrypt headers from stdin-read mime message
    if it was delivered to one of our managed accounts.
    """
    account_manager = get_account_manager(ctx)
    msg = mime.parse_message_from_file(sys.stdin)
    delivto = mime.get_delivered_to(msg)
    account = account_manager.get_account_from_emailadr(delivto, raising=True)
    r = account.process_incoming(msg)
    if r.peerstate.autocrypt_timestamp == r.peerstate.last_seen:
        msg = "found: " + str(r.peerstate)
    else:
        msg = "no Autocrypt header found"
    click.echo("processed mail for account '{}', {}".format(
               r.account.name, msg))


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
    msg = mime.parse_message_from_file(sys.stdin)
    addr = mime.parse_email_addr(msg["From"])
    account = account_manager.get_account_from_emailadr(addr)
    if account is None:
        log_info("No Account associated with addr={!r}".format(addr))
        return msg
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
    input = msg.as_string()
    # with open("/tmp/mail", "w") as f:
    #    f.write(input)
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


@mycommand("export-public-key")
@account_option
@click.argument("keyhandle_or_email", default=None, required=False)
@click.pass_context
def export_public_key(ctx, account, keyhandle_or_email):
    """print public key of own or peer account."""
    account = get_account(ctx, account)
    data = account.export_public_key(keyhandle_or_email)
    click.echo(data)


@mycommand("export-secret-key")
@account_option
@click.pass_context
def export_secret_key(ctx, account):
    """print secret key of own account."""
    account = get_account(ctx, account)
    data = account.export_secret_key()
    click.echo(data)


@mycommand()
@click.argument("account_name", type=str, required=False, default=None)
@click.pass_context
def status(ctx, account_name):
    """print account info and status. """
    if account_name is None:
        account_manager = get_account_manager(ctx)
        _status(account_manager)
    else:
        _status_account(get_account(ctx, account_name))


def _status(account_manager):
    click.echo("account-dir: " + account_manager.dir)
    names = account_manager.list_account_names()
    if not names:
        out_red("no accounts configured")
        return
    for name in names:
        account = account_manager.get_account(name)
        _status_account(account)
        click.echo("")


def _status_account(account):
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
            click.echo("  {to}: last seen key {keyhandle}, status: {status}".format(
                       to=pi.addr, keyhandle=pi.public_keyhandle,
                       status=status))
    else:
        click.echo("  ---- no peers registered -----")


autocrypt_main.add_command(status)
autocrypt_main.add_command(add_account)
autocrypt_main.add_command(mod_account)
autocrypt_main.add_command(del_account)
autocrypt_main.add_command(process_incoming)
autocrypt_main.add_command(process_outgoing)
autocrypt_main.add_command(sendmail)
autocrypt_main.add_command(test_email)
autocrypt_main.add_command(recommend)
autocrypt_main.add_command(make_header)
autocrypt_main.add_command(export_public_key)
autocrypt_main.add_command(export_secret_key)
autocrypt_main.add_command(bot_reply)
autocrypt_main.add_command(destroy_all)


# we need a plugin manager early to add sub commands
def make_plugin_manager():
    pm = pluggy.PluginManager("muacrypt")
    pm.add_hookspecs(hookspec)
    pm.load_setuptools_entrypoints("muacrypt")
    pm.hook.add_subcommands(plugin_manager=pm, command_group=autocrypt_main)
    return pm


_pluginmanager = make_plugin_manager()
