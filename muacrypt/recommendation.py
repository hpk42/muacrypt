class Recommendation:
    """ Calculating recommendations for encryption """

    def __init__(self, account, peerstates):
        self.account = account
        self.peerstates = peerstates

    def ui_recommendation(self):
        return 'available'

    def target_keys(self):
        return {addr: state.public_keyhandle for addr, state in
                self.peerstates.items()}
