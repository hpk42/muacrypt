import pluggy

hookspec = pluggy.HookspecMarker("muacrypt")
hookimpl = pluggy.HookimplMarker("muacrypt")


@hookspec
def add_subcommands(command_group, plugin_manager):
    """add click sub commands to command group. """


@hookspec
def instantiate_account(plugin_manager, basedir):
    """called with the configuration dir"""


@hookspec
def process_incoming_gossip(addr2pagh, account_key, dec_msg):
    """called after decrypting incoming message."""


@hookspec
def process_before_encryption(sender_addr, sender_keyhandle,
                              recipient2keydata, payload_msg, _account):
    """called before encrypting a mime message.

    sender_addr is the routable e-mail address part of the sender.

    sender_keyhandle is the keyhandle which is to be used for signing.

    recipient2keydata is a dictionary mapping recipient routeable
    addresses to their respective keydata.

    payload_msg is the cleartext mime message -- you can add extra
    headers to this (via .add_header(name, value)) which will be
    encrypted along with the rest of the payload message.

    _account is muacrypt's internal Account class. It's API is
    not yet stable and might change/go away in future releases.
    """
