# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from click.testing import CliRunner
import logging
import shutil
import os
import itertools
import pytest
from _pytest.pytester import LineMatcher
from autocrypt.bingpg import find_executable, BinGPG
from autocrypt import mime
from autocrypt.account import Account
from autocrypt.pgpycrypto import PGPyCrypto


def pytest_addoption(parser):
    parser.addoption("--no-test-cache", action="store_true",
                     help="ignore test cache state")

    parser.addoption("--with-gpg2", action="store_true",
                     help="run tests also with gpg2")


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
        pytest.skip("can not find executable: %s" % request.name)
    return path


@pytest.fixture(autouse=True)
def _testcache_bingpg_(request, get_next_cache, monkeypatch):
    # cache generation of secret keys
    old_gen_secret_key = BinGPG.gen_secret_key

    def gen_secret_key(self, emailadr):
        basekey = request.node.nodeid
        next_cache = get_next_cache(basekey)
        if self.homedir and next_cache.exists():
            logging.debug("restoring homedir {}".format(self.homedir))
            return next_cache.restore(self.homedir)
        else:
            if self.homedir is None:
                assert "GNUPGHOME" in os.environ
            ret = old_gen_secret_key(self, emailadr)
            if self.homedir is not None:
                if os.path.exists(self.homedir):
                    next_cache.store(self.homedir, ret)
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
        self.runner = CliRunner()
        self._main = main
        self._rootargs = []

    def set_basedir(self, account_dir):
        self._rootargs.insert(0, "--basedir")
        self._rootargs.insert(1, account_dir)

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


def _perform_match(output, fnl):
    __tracebackhide__ = True
    if fnl:
        lm = LineMatcher(output.splitlines())
        lines = [x.strip() for x in fnl.strip().splitlines()]
        try:
            lm.fnmatch_lines(lines)
        except:
            print(output)
            raise
    return output


@pytest.fixture
def linematch():
    return _perform_match


@pytest.fixture
def cmd():
    """ invoke a command line subcommand. """
    from autocrypt.cmdline import autocrypt_main
    return ClickRunner(autocrypt_main)


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

        def parse_ac_header_from_email(self, name):
            with self.open(name) as fp:
                msg = mime.parse_message_from_file(fp)
                return mime.parse_one_ac_header_from_msg(msg)

    return D(request.fspath.dirpath("data"))


@pytest.fixture(scope="session")
def get_next_cache(pytestconfig):
    cache = pytestconfig.cache
    counters = {}

    def next_cache(basekey):
        count = counters.setdefault(basekey, itertools.count())
        key = basekey + str(next(count))
        return DirCache(cache, key)
    return next_cache


class DirCache:
    def __init__(self, cache, key):
        self.cache = cache
        self.disabled = cache.config.getoption("--no-test-cache")
        self.own_pgpykey = key
        self.backup_path = self.cache._cachedir.join(self.own_pgpykey)

    def exists(self):
        dummy = object()
        return not self.disabled and \
               self.cache.get(self.own_pgpykey, dummy) != dummy and \
               self.backup_path.exists()

    def store(self, path, ret):
        if self.backup_path.exists():
            self.backup_path.remove()
        else:
            self.backup_path.dirpath().ensure(dir=1)

        def ignore(src, names):
            # ignore gpg socket special files
            return [n for n in names if n.startswith("S.")]

        shutil.copytree(path, self.backup_path.strpath, ignore=ignore)
        self.cache.set(self.own_pgpykey, ret)

    def restore(self, path):
        if os.path.exists(path):
            shutil.rmtree(path)
        shutil.copytree(self.backup_path.strpath, path)
        return self.cache.get(self.own_pgpykey, None)


@pytest.fixture
def account(account_maker):
    """ return an uninitialized Autocrypt account. """
    return account_maker(addid=False)


@pytest.fixture
def account_maker(tmpdir, gpgpath):
    """ return a function which creates a new Autocrypt account, by default initialized.
    pass init=False to the function to avoid initizialtion.
    """
    # we have to be careful to not generate too long paths
    # because gpg-2.1.11 chokes while trying to start gpg-agent
    count = itertools.count()

    def maker(init=True, addid=True):
        basedir = tmpdir.mkdir("a%d" % next(count)).strpath
        ac = Account(basedir)
        if init:
            ac.init()
            if addid:
                ac.add_identity(gpgbin=gpgpath)
        return ac
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
def crypto_maker(request, tmpdir):
    """Return a function which creates initialized PGPyCrypto instances."""
    counter = itertools.count()

    from autocrypt.examples_data import PGPHOME
    def maker(native=False, pgphome=PGPHOME):
        from autocrypt.pgpycrypto import PGPyCrypto
        if pgphome:
            pgpycrypto = PGPyCrypto(pgphome)
        else:
            p = tmpdir.join("pgpycrypto%d" % next(counter))
            pgpycrypto = PGPyCrypto(p.strpath)
        return pgpycrypto
    return maker


@pytest.fixture
def pgpycrypto(crypto_maker):
    """Return an initialized pgpycrypto instance."""
    return crypto_maker()

