# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

import logging
import mailbox
import shutil
import os
import itertools
import pytest
import pluggy
from _pytest.pytester import LineMatcher
from .bingpg import find_executable, BinGPG
from . import mime
from .account import AccountManager, Account
from .cmdline import make_plugin_manager
from .states import States
import muacrypt


def pytest_addoption(parser):
    parser.addoption("--no-test-cache", action="store_true",
                     help="ignore test cache state")

    parser.addoption("--with-gpg2", action="store_true",
                     help="run tests also with gpg2")

    parser.addoption("--with-plugins", action="store_true",
                     help="run tests with enabled plugins (usually they are not loaded "
                          "during core tests")


@pytest.fixture
def tmpdir(tmpdir_factory, request):
    base = str(hash(request.node.nodeid))[:3]
    bn = tmpdir_factory.mktemp(base)
    return bn


@pytest.fixture(params=["gpg1", "gpg2"], scope="module")
def gpgpath(request):
    """ return twice with system paths of "gpg" and "gpg2"
    respectively.  If one is not present the test requesting
    this fixture is skipped. By default we do not run gpg2
    tests because they are much slower.  A clean "tox" run
    will also run the gpg2 tests.
    """
    name = "gpg" if request.param == "gpg1" else "gpg2"
    if name == "gpg2" and not request.config.getoption("--with-gpg2"):
        pytest.skip("skipped gpg2 tests (specify --with-gpg2 to run)")
    path = find_executable(name)
    if path is None:
        pytest.skip("can not find executable: %s" % request.param)
    return path


@pytest.fixture(autouse=True)
def no_setuptools_entrypoints(request, monkeypatch):
    if not request.config.getoption("--with-plugins"):
        monkeypatch.setattr(pluggy.PluginManager, "load_setuptools_entrypoints",
                            lambda self, name: None)


@pytest.fixture(autouse=True)
def _testcache_bingpg_(request, get_next_cache, monkeypatch):
    # cache generation of secret keys
    old_gen_secret_key = BinGPG.gen_secret_key

    def gen_secret_key(self, emailadr):
        basekey = request.node.nodeid
        next_cache = get_next_cache(basekey)
        if self.homedir and next_cache.exists():
            logging.debug("restoring homedir {}".format(self.homedir))
            return next_cache.restates(self.homedir)
        else:
            if self.homedir is None:
                assert "GNUPGHOME" in os.environ
            ret = old_gen_secret_key(self, emailadr)
            if self.homedir is not None:
                if os.path.exists(self.homedir):
                    next_cache.states(self.homedir, ret)
            return ret

    monkeypatch.setattr(BinGPG, "gen_secret_key", gen_secret_key)

    # make sure any possibly started agents are killed
    old_init = BinGPG.__init__

    def __init__(self, *args, **kwargs):
        old_init(self, *args, **kwargs)
        request.addfinalizer(self.killagent)

    monkeypatch.setattr(BinGPG, "__init__", __init__)
    return


@pytest.fixture
def bingpg_maker(request, tmpdir, gpgpath):
    """ return a function which creates initialized BinGPG instances. """
    counter = itertools.count()

    def maker(native=False):
        if native:
            bingpg = BinGPG(gpgpath=gpgpath)
        else:
            p = tmpdir.join("bingpg%d" % next(counter))
            bingpg = BinGPG(p.strpath, gpgpath=gpgpath)
        return bingpg
    return maker


@pytest.fixture
def bingpg(bingpg_maker):
    """ return an initialized bingpg instance. """
    return bingpg_maker()


@pytest.fixture
def bingpg2(bingpg_maker):
    """ return an initialized bingpg instance different from the first. """
    return bingpg_maker()


class ClickRunner:
    def __init__(self, main):
        from click.testing import CliRunner
        self.runner = CliRunner()
        self._main = main
        self._rootargs = []

    def set_basedir(self, account_dir):
        self._rootargs.insert(0, "--basedir")
        self._rootargs.insert(1, account_dir)
        self.account_dir = account_dir

    def get_account(self, account_name):
        from .cmdline import _pluginmanager
        from .account import AccountManager
        am = AccountManager(self.account_dir, _pluginmanager)
        return am.get_account(account_name)

    def run_ok(self, args, fnl=None, input=None):
        __tracebackhide__ = True
        argv = self._rootargs + args
        # we use our nextbackup helper to cache account creation
        # unless --no-test-cache is specified
        res = self.runner.invoke(self._main, argv, catch_exceptions=False,
                                 input=input)
        if res.exit_code != 0:
            print(res.output)
            raise Exception("cmd exited with %d: %s" % (res.exit_code, argv))
        return _perform_match(res.output, fnl)

    def run_fail(self, args, fnl=None, input=None, code=None):
        __tracebackhide__ = True
        argv = self._rootargs + args
        res = self.runner.invoke(self._main, argv, catch_exceptions=False,
                                 input=input)
        if res.exit_code == 0 or (code is not None and res.exit_code != code):
            print (res.output)
            raise Exception("got exit code {!r}, expected {!r}, output: {}".format(
                res.exit_code, code, res.output))
        return _perform_match(res.output, fnl)

    def parse_recommendation(self, account_name, adrlist):
        out = self.run_ok(["recommend", "-a", account_name] + list(adrlist))
        return out.splitlines()[0].strip()

    def send_mail(self, sender, receivers, ac=True, Date=None):
        sender_header = self.run_ok(["make-header", "--val", sender])
        msg = mime.gen_mail_msg(From=sender, To=receivers, Date=Date, _dto=True)
        if ac and sender_header:
            msg["Autocrypt"] = sender_header
        for rec in receivers:
            self.run_ok(["process-incoming"], input=msg.as_string())


def _perform_match(output, fnl):
    __tracebackhide__ = True
    if fnl:
        lm = LineMatcher(output.splitlines())
        lines = [x.strip() for x in fnl.strip().splitlines()]
        try:
            lm.fnmatch_lines(lines)
        except Exception:
            print(output)
            raise
    return output


@pytest.fixture
def linematch():
    return _perform_match


@pytest.fixture
def cmd():
    """ invoke a command line subcommand. """
    from muacrypt.cmdline import muacrypt_main
    return ClickRunner(muacrypt_main)


@pytest.fixture
def mycmd(cmd, tmpdir, request):
    cmd.set_basedir(tmpdir.mkdir("account").strpath)
    return cmd


@pytest.fixture()
def datadir(request):
    """ get, read, open test files from the "data" directory. """
    class D:
        def __init__(self, basepath):
            self.basepath = basepath

        def open(self, name, mode="r"):
            return self.basepath.join(name).open(mode)

        def join(self, name):
            return self.basepath.join(name).strpath

        def read_bytes(self, name):
            with self.open(name, "rb") as f:
                return f.read()

        def read(self, name):
            with self.open(name, "r") as f:
                return f.read()

        def get_mime(self, name):
            with self.open(name, "rb") as f:
                return mime.message_from_binary_file(f)

        def parse_ac_header_from_email(self, name):
            msg = self.get_mime(name)
            From = mime.parse_email_addr(msg["From"])
            return mime.parse_one_ac_header_from_msg(msg, FromList=[From])

    return D(request.fspath.dirpath("data"))


def pytest_report_header():
    from muacrypt.cmdline import _pluginmanager
    l = ["muacrypt-{}".format(muacrypt.__version__)]
    for name, dist in _pluginmanager.list_plugin_distinfo():
        l.append(repr(dist))
    return "versions: " + ", ".join(l)


@pytest.fixture(scope="session")
def get_next_cache(pytestconfig):
    cache = pytestconfig.cache
    counters = {}

    def next_cache(basekey):
        count = counters.setdefault(basekey, itertools.count())
        key = basekey + str(next(count))
        return DirCache(cache, key, pytestconfig)
    return next_cache


class DirCache:
    def __init__(self, cache, key, pytestconfig):
        self.cache = cache
        self.disabled = pytestconfig.getoption("--no-test-cache")
        self.key = key
        self.backup_path = self.cache._cachedir.joinpath(self.key)

    def exists(self):
        dummy = object()
        return not self.disabled and \
            self.cache.get(self.key, dummy) != dummy and \
            self.backup_path.exists()

    def states(self, path, ret):
        if self.backup_path.exists():
            shutil.rmtree(str(self.backup_path))
        else:
            if not self.backup_path.parent.exists():
                os.makedirs(str(self.backup_path.parent))

        def ignore(src, names):
            # ignore gpg socket special files
            return [n for n in names if n.startswith("S.")]

        shutil.copytree(path, str(self.backup_path), ignore=ignore)
        self.cache.set(self.key, ret)

    def restates(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)
        shutil.copytree(str(self.backup_path), path)
        return self.cache.get(self.key, None)


@pytest.fixture
def account_maker(tmpdir, gpgpath):
    """ return a function which creates a new account, by default initialized.
    pass init=False to the function to avoid initizialtion.
    """
    # we have to be careful to not generate too long paths
    # because gpg-2.1.11 chokes while trying to start gpg-agent
    count = itertools.count()

    def maker(email_regex=u'.*', gpgmode=u'own', gpgbin=gpgpath):
        i = next(count)
        bname = u"ac%d" % i
        basedir = tmpdir.mkdir(bname).strpath
        states = States(basedir)
        account = Account(states, bname, plugin_manager=make_plugin_manager())
        account.create(name=bname, email_regex=email_regex, gpgmode=gpgmode, gpgbin=gpgbin,
                       keyhandle=None)
        account.addr = "%d@x.org" % (i, )
        account._fulladdr = "%s <%s>" % (bname, account.addr)
        account.plugin_manager.hook.instantiate_account(
            plugin_manager=account.plugin_manager,
            basedir=basedir,
        )
        return account
    return maker


@pytest.fixture
def manager(manager_maker):
    """ return an uninitialized AccountManager instance. """
    return manager_maker(addid=False)


@pytest.fixture
def manager_maker(tmpdir, gpgpath):
    """ return a function which creates a new AccountManager account, by default initialized.
    pass init=False to the function to avoid initizialtion.
    """
    # we have to be careful to not generate too long paths
    # because gpg-2.1.11 chokes while trying to start gpg-agent
    count = itertools.count()

    def maker(init=True, addid=True):
        basedir = tmpdir.mkdir("a%d" % next(count)).strpath
        mc = AccountManager(basedir, plugin_manager=make_plugin_manager())
        if init:
            mc.init()
            if addid:
                mc.add_account(gpgbin=gpgpath)
        return mc
    return maker


@pytest.fixture
def gen_mail(request):
    nid = request.node.nodeid
    counter = itertools.count()

    def do_gen_mail(From="a@a.org", body=None):
        msg = mime.gen_mail_msg(
            From=From, To=["b@b.org"],
            Subject="test mail {} [{}]".format(next(counter), nid),
        )
        if body is not None:
            msg.set_payload(body)
        return msg
    return do_gen_mail


@pytest.fixture
def popen_mock(monkeypatch):
    """ returns a subprocess mock controller object and mocks out all calls to
    subprocess.Popen() so that you can later look at them by calling
    ``mock_controller.pop_next_call()`` which returns an object which has all
    parameters of the mocked ``subprocess.Popen()`` call as attributes.

    Note that this only works if the code-under-test accesses ``subprocess.Popen``
    and has not imported ``Popen`` directly.
    """
    import subprocess

    class PopenMock:
        def __init__(self):
            self.calls = []
            self._nextcall_ret = 0

        def _on_call(self, mcall):
            self.calls.append(mcall)

        def pop_next_call(self):
            return self.calls.pop(0)

        def mock_next_call(self, ret=0):
            self._nextcall_ret = ret

    class MCall:
        def __init__(self, args, kwargs):
            self.args = list(args)
            self.__dict__.update(kwargs)

    pm = PopenMock()

    class MyPopen:
        def __init__(self, args, **kwargs):
            self._ongoing_call = c = MCall(args, kwargs)
            pm._on_call(c)

        def wait(self):
            return pm._nextcall_ret

        def communicate(self, input):
            self._ongoing_call.input = input
            return "", ""

    monkeypatch.setattr(subprocess, "Popen", MyPopen)
    return pm


@pytest.fixture
def maildir(tmpdir):
    return Maildir(tmpdir.join("maildir").strpath)


class Maildir:
    def __init__(self, tmpdir):
        self.maildir = mailbox.Maildir(tmpdir)

    def store(self, msg):
        self.maildir.add(msg)
        logging.debug("stored msgid={} path: {}".format(
            msg.get("message-id"), self.maildir._path))
