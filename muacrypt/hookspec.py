import pluggy

hookspec = pluggy.HookspecMarker("muacrypt")


@hookspec
def instantiate_account(plugin_manager, basedir):
    """called with the configuration dir"""


@hookspec
def process_incoming_gossip(addr2pagh, account_key, dec_msg):
    """called after decrypting incoming message."""
