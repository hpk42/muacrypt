import pytest

from autocrypt.claimchain import ClaimChain

@pytest.fixture
def cc():
    return ClaimChain()


class TestBasic:
    def test_two_claims_save_load(self, cc, tmpdir):
        path = tmpdir.join("cc").strpath
        cc.add_claim("genesis", "123")
        cc.add_claim("ccverify", "456")
        assert len(cc.claims) == 2
        cc.save_claims(path)
        cc2 = ClaimChain()
        cc2.load_claims(path)
        assert cc.claims == cc2.claims

