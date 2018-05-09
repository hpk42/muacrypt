import os.path

from test_muacrypt.test_account import gen_ac_mail_msg
from muacrypt.cmdline import make_plugin_manager
from muacrypt.hookspec import hookimpl


def get_own_pubkey(account):
    return account.bingpg.get_public_keydata(account.ownstate.keyhandle)


class TestPluginHooks:
    def test_get_account_pluggy_instantiate_account(self, manager_maker, datadir):
        manage1 = manager_maker()
        l = []

        class Plugin:
            @hookimpl
            def instantiate_account(self, plugin_manager, basedir):
                assert plugin_manager == manage1.plugin_manager
                l.append(basedir)

        manage1.plugin_manager.register(Plugin())
        account1 = manage1.get_account()
        assert len(l) == 1
        assert os.path.basename(l[0]) == account1.name

    def test_process_incoming_calls_hook(self, account_maker):
        sender = account_maker()
        rec1, rec2 = account_maker(), account_maker()

        # make sure sender has all keys
        sender.process_incoming(gen_ac_mail_msg(rec1, sender))
        sender.process_incoming(gen_ac_mail_msg(rec2, sender))

        # send an encrypted mail from sender to both recipients
        gossip_msg = gen_ac_mail_msg(sender, [rec1, rec2])
        enc_msg = sender.encrypt_mime(gossip_msg, [rec1.addr, rec2.addr]).enc_msg

        l = []

        class Plugin:
            @hookimpl
            def process_incoming_gossip(self, addr2pagh, account_key, dec_msg):
                l.append((addr2pagh, account_key, dec_msg))

        rec1.plugin_manager.register(Plugin())
        rec1.process_incoming(enc_msg)
        assert len(l) == 1
        addr2pagh, account_key, dec_msg = l[0]
        assert account_key == rec1.ownstate.keyhandle
        assert dec_msg["Message-Id"] == gossip_msg["Message-Id"]
        assert rec1.addr in addr2pagh
        assert rec2.addr in addr2pagh

        assert addr2pagh[rec1.addr].keydata == get_own_pubkey(rec1)
        assert addr2pagh[rec2.addr].keydata == get_own_pubkey(rec2)

    def test_process_outgoing_calls_hook(self, account_maker):
        sender = account_maker()
        rec1, rec2 = account_maker(), account_maker()

        # make sure sender has all keys
        sender.process_incoming(gen_ac_mail_msg(rec1, sender))
        sender.process_incoming(gen_ac_mail_msg(rec2, sender))
        gossip_msg = gen_ac_mail_msg(sender, [rec1, rec2])

        l = []

        class Plugin:
            @hookimpl
            def process_before_encryption(self, sender_addr, sender_keyhandle,
                                          recipient2keydata, payload_msg, _account):
                l.append((
                    sender_addr, sender_keyhandle,
                    recipient2keydata, payload_msg, _account,
                ))
                payload_msg["My-Plugin-Header"] = "My own header"

        sender.plugin_manager.register(Plugin())

        # send an encrypted mail from sender to both recipients
        enc_msg = sender.encrypt_mime(gossip_msg, [rec1._fulladdr, rec2.addr]).enc_msg

        assert len(l) == 1
        sender_addr, sender_keyhandle = l[0][:2]
        recipient2keydata, payload_msg, _account = l[0][2:]
        assert _account == sender
        assert sender_keyhandle == sender.ownstate.keyhandle
        assert sender_addr == sender.addr
        assert len(recipient2keydata) == 2
        assert recipient2keydata[rec1.addr] == get_own_pubkey(rec1)
        assert recipient2keydata[rec2.addr] == get_own_pubkey(rec2)
        assert enc_msg["Message-Id"] == gossip_msg["Message-Id"]
        rec1.process_incoming(enc_msg)
        dec_msg = rec1.decrypt_mime(enc_msg).dec_msg
        assert dec_msg["My-Plugin-Header"] == "My own header"

    def test_add_subcommands(self, account_maker):
        pm = make_plugin_manager()

        l = []

        class Plugin:
            @hookimpl
            def add_subcommands(self, command_group, plugin_manager):
                l.append(1)

        pm.register(Plugin())
        pm.hook.add_subcommands(plugin_manager=pm, command_group=[])
        assert len(l) == 1
