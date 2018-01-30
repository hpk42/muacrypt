class Recommendation:
    """ Calculating recommendations for encryption """

    def __init__(self, peerstates, prefer_encrypt, reply_to_enc=False):
        self.peerstates = peerstates
        self.prefer_encrypt = prefer_encrypt
        self.reply_to_enc = reply_to_enc

    def ui_recommendation(self):
        # only consider first peer for now
        peer_recommendations = [
            self._peer_recommendation(peer).ui_recommendation()
            for peer in self.peerstates.values()]
        for rec in ['disable', 'discourage', 'available', 'encrypt']:
            if rec in peer_recommendations:
                return rec

    def target_keyhandles(self):
        return {addr: self._peer_recommendation(peer).target_keyhandle()
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

    def target_keyhandle(self):
        return (getattr(self.peer, 'public_keyhandle', None) or
                getattr(self.peer, 'gossip_keyhandle', None))

    def _preliminary_recommendation(self):
        if self.target_keyhandle() is None:
            return 'disable'
        timeout = 35 * 24 * 60 * 60
        if (self.peer.last_seen - self.peer.autocrypt_timestamp >
                timeout):
            return 'discourage'
        return 'available'
