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
        return {addr: state.public_keyhandle for addr, state in
                self.peerstates.items()}

    def _peer_recommendation(self, state):
        if len(state.public_keyhandle):
            return 'available'
        else:
            return 'disable'
