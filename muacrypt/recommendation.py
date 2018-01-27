class Recommendation:
    """ Calculating recommendations for encryption """

    def __init__(self, peerstates):
        self.peerstates = peerstates

    def ui_recommendation(self):
        # only consider first peer for now
        peer = list(self.peerstates.values())[0]
        return self._peer_recommendation(peer)

    def target_keys(self):
        return {addr: self._target_key(peer) for addr, peer in
                self.peerstates.items()}

    def _peer_recommendation(self, peer):
        if self._target_key(peer):
            return 'available'
        else:
            return 'disable'

    def _target_key(self, peer):
        return self._public_key(peer) or self._gossip_key(peer)

    def _public_key(self, peer):
        return self._key(peer.public_keyhandle)

    def _gossip_key(self, peer):
        # gossip keyhandle is not implemented yet.
        if hasattr(peer, 'gossip_keyhandle'):
            return self._key(peer.gossip_keyhandle)

    # logic for checking if a key is usable could go here.
    def _key(self, handle):
        if handle:
            return handle
