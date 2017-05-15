"""
Basic ClaimChain implementation.

A claimchain is associated with each account and keeps track of out of band verified
cryptographic identities.

"""

import json

def init_claimchain(uid):
    """ return a fresh initialized claimchain instance for the given account"""


def load_claimchain(uid):
    """ load a claimchain instance for the given account. """


class ClaimChain:
    def __init__(self):
        self.claims = []

    def load_claims(self, path):
        assert not self.claims
        with open(path) as f:
            d = json.load(f)
        for cl in d:
            self.claims.append(cl)

    def save_claims(self, path):
        with open(path, "w") as f:
            json.dump(self.claims, f, indent=2, sort_keys=True)

    def add_claim(self, name, payload):
        self.claims.append([name, payload])
