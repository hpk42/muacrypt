
import pytest

@pytest.fixture
def gpg(tmpdir, datadir):
    from inbome.gpg import GPG
    p = tmpdir.mkdir("keyring")
    p.chmod(0o700)
    g = GPG(p.strpath)
    # import RSA 2048 key for "bot@autocrypt.org"
    g.import_keyfile(datadir.join("testbot.secretkey").strpath)
    return g

@pytest.fixture()
def datadir(request):
    class D:
        def __init__(self, basepath):
            self.basepath = basepath
        def open(self, name):
            return self.basepath.join(name).open()
        def join(self, name):
            return self.basepath.join(name)

    return D(request.fspath.dirpath("data"))

