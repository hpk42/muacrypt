# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
from __future__ import unicode_literals, print_function

import click
from .account import AccountException


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


def get_account_manager(ctx):
    return ctx.parent.account_manager


def get_account(ctx, name):
    return get_account_manager(ctx).get_account(name)


def trunc_string(s, maxlen=80):
    if len(s) <= maxlen:
        return s
    begin = s[:(maxlen - 20)]
    return begin + "[truncated {} chars]".format(len(s) - maxlen + 20)
