class Recommendation:
    """ Calculating recommendations for encryption """

    def __init__(self, peerstates):
        self.peerstates = peerstates

    def ui_recommendation(self):
        # only consider first peer for now
        peer = list(self.peerstates.values())[0]
        return PeerRecommendation(peer).ui_recommendation()

    def target_keys(self):
        return {addr: PeerRecommendation(peer).target_key() for addr, peer in
                self.peerstates.items()}


class PeerRecommendation:
    """ Calculating recommendation for a single peer """

    def __init__(self, peer):
        self.peer = peer

    def ui_recommendation(self):
        if self.target_key() is None:
            return 'disable'
        if self._ac_is_outdated():
            return 'discourage'
        return 'available'

    def target_key(self):
        return self._public_key() or self._gossip_key()

    def _ac_is_outdated(self):
        timeout = 35 * 24 * 60 * 60
        return (self.peer.last_seen - self.peer.autocrypt_timestamp > timeout)

    def _public_key(self):
        return self._key(self.peer.public_keyhandle)

    def _gossip_key(self):
        # gossip keyhandle is not implemented yet.
        if hasattr(self.peer, 'gossip_keyhandle'):
            return self._key(self.peer.gossip_keyhandle)

    # logic for checking if a key is usable could go here.
    def _key(self, handle):
        if handle:
            return handle
