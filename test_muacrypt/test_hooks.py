import os.path
import pluggy

from test_muacrypt.test_account import gen_ac_mail_msg


hookimpl = pluggy.HookimplMarker("muacrypt")


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

        def getpk(account):
            return account.bingpg.get_public_keydata(account.ownstate.keyhandle)

        assert addr2pagh[rec1.addr].keydata == getpk(rec1)
        assert addr2pagh[rec2.addr].keydata == getpk(rec2)

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
            def process_outgoing_before_encryption(self, account_key, msg):
                l.append((account_key, msg))
                msg["Plugin-Header"] = "My own header"

        sender.plugin_manager.register(Plugin())

        # send an encrypted mail from sender to both recipients
        enc_msg = sender.encrypt_mime(gossip_msg, [rec1.addr, rec2.addr]).enc_msg

        assert len(l) == 1
        account_key, msg = l[0]
        assert account_key == sender.ownstate.keyhandle
        assert enc_msg["Message-Id"] == gossip_msg["Message-Id"]
        assert msg['to'] == gossip_msg['to']
        rec1.process_incoming(enc_msg)
        dec_msg = rec1.decrypt_mime(enc_msg).dec_msg
        assert dec_msg["Plugin-Header"] == "My own header"
