class Recommendation:
    """ Calculating recommendations for encryption """

    def __init__(self, peerstates, prefer_encrypt, reply_to_enc=False):
        self.peerstates = peerstates
        self.prefer_encrypt = prefer_encrypt
        self.reply_to_enc = reply_to_enc

    def ui_recommendation(self):
        # only consider first peer for now
        peer = list(self.peerstates.values())[0]
        return self._peer_recommendation(peer).ui_recommendation()

    def target_keys(self):
        return {addr: self._peer_recommendation(peer).target_key()
                for addr, peer in
                self.peerstates.items()}

    def _peer_recommendation(self, peer):
        return PeerRecommendation(peer, self.prefer_encrypt,
                self.reply_to_enc)


class PeerRecommendation:
    """ Calculating recommendation for a single peer """

    def __init__(self, peer, prefer_encrypt, reply_to_enc):
        self.peer = peer
        self.prefer_encrypt = prefer_encrypt
        self.reply_to_enc = reply_to_enc

    def ui_recommendation(self):
        pre = self._preliminary_recommendation()
        if ((pre == 'available' or pre == 'discourage') and
                self.reply_to_enc):
            return 'encrypt'
        if (pre == 'available' and
                self.prefer_encrypt == 'mutual' and
                self.peer.prefer_encrypt == 'mutual'):
            return 'encrypt'
        return pre

    def target_key(self):
        return self._public_key() or self._gossip_key()

    def _preliminary_recommendation(self):
        if self.target_key() is None:
            return 'disable'
        if self._ac_is_outdated():
            return 'discourage'
        return 'available'

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
