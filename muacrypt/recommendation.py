class Recommendation:
    """ Calculating recommendations for encryption """

    def __init__(self, account, peerstates):
        self.account = account
        self.peerstates = peerstates

    def ui_recommendation(self):
        # only consider first peer for now
        peer = list(self.peerstates.values())[0]
        return self._peer_recommendation(peer)

    def target_keys(self):
        return {addr: self._key_for_peer(peer) for addr, peer in
                self.peerstates.items()}

    def _peer_recommendation(self, peer):
        if peer is None:
            return 'disable'
        if len(peer.public_keyhandle):
            return 'available'
        else:
            return 'disable'

    def _key_for_peer(self, peer):
        if peer and len(peer.public_keyhandle):
            return peer.public_keyhandle
