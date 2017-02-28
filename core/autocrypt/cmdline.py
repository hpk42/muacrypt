# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""Autocrypt Command line implementation.
"""

from __future__ import print_function

import os
import sys
import subprocess
import six
import click
from .account import Account, AccountException, NotInitialized, NoIdentityFound
from .bingpg import find_executable
from . import mime


def out_red(msg):
    click.secho(msg, fg="red")


def log_info(string):
    """log information to stderr. """
    # we can't log to stderr because the tests do currently
    # not separate err and out for now, so our debugging output
    # intermingles
    # with open("/tmp/log", "a") as f:
    #    print(string, file=f)
    #    # click.echo("[info] " + string, err=True)


class MyGroup(click.Group):
    """ small click group to enforce order of subcommands in help. """
    def add_command(self, cmd):
        self.__dict__.setdefault("_cmdlist", [])
        self._cmdlist.append(cmd.name)
        return super(MyGroup, self).add_command(cmd)

    def list_commands(self, ctx):
        commands = super(MyGroup, self).list_commands(ctx)
        assert sorted(commands) == sorted(self._cmdlist)
        return self._cmdlist


class MyCommand(click.Command):
    def invoke(self, ctx):
        try:
            return super(MyCommand, self).invoke(ctx)
        except AccountException as e:
            abort(ctx, e)


def abort(ctx, exc):
    out_red(str(exc))
    ctx.exit(1)


class MyCommandUnknownOptions(MyCommand):
    ignore_unknown_options = True


def mycommand(*args):
    return click.command(*args, cls=MyCommand)


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
@click.option("--without-identity", default=False, is_flag=True,
              help="initializing without creating a default identity")
@click.pass_context
def init(ctx, replace, without_identity):
    """init autocrypt account state.

    By default this command creates account state in a directory with
    a default "catch-all" identity which matches all email addresses
    and uses default settings.  If you want to have more fine-grained
    control (which gpg binary to use, which existing key to use, if to
    use an existing system key ring ...) specify "--without-identity".
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
    if not without_identity:
        account.add_identity("default")
    _status(account)


@mycommand("add-identity")
@click.argument("identity_name", type=str, required=True)
@click.option("--use-existing-key", default=None, type=str,
              help="use specified secret key which must be findable "
                   "through the specified keyhandle (e.g. email, keyid, fingerprint)")
@click.option("--use-system-keyring", default=False, is_flag=True,
              help="use system keyring for all secret/public keys instead of storing "
                   "keyring state inside our account identity directory.")
@click.option("--gpgbin", default="gpg", type=str,
              help="use specified gpg binary. if it is a simple name it "
                   "is looked up on demand through the system's PATH.")
@click.option("--email-regex", default=".*", type=str,
              help="regex for matching all email addresses belonging to "
                   "this identity.")
@click.pass_context
def add_identity(ctx, identity_name, use_system_keyring,
                 use_existing_key, gpgbin, email_regex):
    """add an identity to this account.

    An identity requires an identity_name which is used to show, modify and delete it.

    Of primary importance is the "email_regex" which you typically
    set to a plain email address.   It is used when incoming or outgoing mails
    need to be associated with this identity.

    Instead of generating a key (the default operation) you may specify an
    existing key with --use-existing-key=keyhandle where keyhandle may be
    something for which gpg finds it with 'gpg --list-secret-keys keyhandle'.
    Typically you will then also specify --use-system-keyring to make use of
    your existing keys.  All incoming autocrypt keys will thus be stored in
    the system key ring instead of an own keyring.
    """
    account = get_account(ctx)
    ident = account.add_identity(
        identity_name, keyhandle=use_existing_key, gpgbin=gpgbin,
        gpgmode="system" if use_system_keyring else "own", email_regex=email_regex
    )
    click.echo("identity added: {!r}".format(ident.config.name))
    _status(account)


@mycommand("mod-identity")
@click.argument("identity_name", type=str, required=True)
@click.option("--use-existing-key", default=None, type=str,
              help="use specified secret key which must be findable "
                   "through the specified keyhandle (e.g. email, keyid, fingerprint)")
@click.option("--gpgbin", default=None, type=str,
              help="use specified gpg binary. if it is a simple name it "
                   "is looked up on demand through the system's PATH. "
                   "if it is None (the default) no change is made")
@click.option("--email-regex", default=None, type=str,
              help="regex for matching all email addresses belonging to "
                   "this identity. If it None (the default) no change is made "
                   "to the existing regex.")
@click.option("--prefer-encrypt", default=None, type=click.Choice(["notset", "yes", "no"]),
              help="modify prefer-encrypt setting, default is to not change it.")
@click.pass_context
def mod_identity(ctx, identity_name, use_existing_key, gpgbin, email_regex, prefer_encrypt):
    """modify properties of an existing identity.

    An identity requires an identity_name which is used to show, modify and delete it.

    Any specified email_regex replaces the existing one.

    Any specified key replaces the existing one.
    """
    account = get_account(ctx)
    changed, ident = account.mod_identity(
        identity_name, keyhandle=use_existing_key, gpgbin=gpgbin,
        email_regex=email_regex, prefer_encrypt=prefer_encrypt,
    )
    s = " NOT " if not changed else " "
    click.echo("identity{}modified: '{}'".format(s, ident.config.name))
    _status(account)


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
    ident = account.get_identity_from_emailadr([emailadr])
    if ident is None:
        raise NoIdentityFound([emailadr])
    click.echo(ident.config.name)


def get_account(ctx):
    account = ctx.parent.account
    if not account.exists():
        raise NotInitialized(account.dir)
    return account


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
    click.echo("processed mail for identity '{}', found: {}".format(
               peerinfo.identity.config.name, peerinfo))


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
    assert args
    account = get_account(ctx)
    args = list(args)
    msg, emailadr = _prepare_stdin_message(account)

    input = msg.as_string()
    log_info("piping to: {}".format(" ".join(args)))
    sendmail = find_executable("sendmail")
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
            raise NoIdentityFound([adr])
        msg["Autocrypt"] = h
        log_info("Autocrypt header set for {!r}".format(adr))
    else:
        log_info("Found existing Autocrypt: {}...".format(msg["Autocrypt"][:35]))
    return msg, adr


@mycommand("export-public-key")
@click.argument("keyhandle_or_email", default=None, required=False)
@click.pass_context
def export_public_key(ctx, keyhandle_or_email):
    """print public key of own or peer account."""
    account = get_account(ctx)
    kh = keyhandle_or_email
    if kh is not None:
        if "@" in kh:
            kh = account.get_identity().get_peerinfo(kh).keyhandle
    click.echo(account.get_identity().export_public_key(keyhandle=kh))


@mycommand("export-secret-key")
@click.pass_context
def export_secret_key(ctx):
    """print secret key of own autocrypt account. """
    account = get_account(ctx)
    click.echo(account.get_identity().export_secret_key())


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
        ic = ident.config
        click.echo("")
        click.secho("identity: '{}' uuid {}".format(ic.name, ic.uuid), bold=True)
        click.echo("  email_regex: {}".format(ic.email_regex))
        if ic.gpgmode == "own":
            click.echo("  gpgmode: {} [home: {}]".format(ic.gpgmode, ident.bingpg.homedir))
        else:
            click.echo("  gpgmode: {}".format(ic.gpgmode))
        if os.sep not in ic.gpgbin:
            click.echo("  gpgbin: {} [currently resolves to: {}]".format(
                       ic.gpgbin, find_executable(ic.gpgbin)))
        else:
            click.echo("  gpgbin: {}".format(ic.gpgbin))
        click.echo("  own-keyhandle: " + ic.own_keyhandle)
        click.echo("  prefer-encrypt: " + ic.prefer_encrypt)

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


# @click.command()
# @click.pass_obj
# def bot(ctx):
#     """Bot invocation and account generation commands. """
#     assert 0, obj.account_dir
