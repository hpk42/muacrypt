# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals

import logging
import pytest
from autocrypt.crypto import cached_property, KeyInfo


FORMAT = "%(levelname)s: %(filename)s:%(lineno)s -"\
         "%(funcName)s - %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger(__name__)


def test_cached_property_object():
    l = []

    class A(object):
        @cached_property
        def x1(self):
            l.append('x')
            return 1

    a = A()
    assert len(l) == 0
    assert a.x1 == 1
    assert l == ['x']
    assert a.x1 == 1
    assert l == ['x']
    a.x1 = 10
    assert a.x1 == 10
    assert l == ['x']


@pytest.mark.parametrize("id1,id2", [
    ("90123456", "1234567890123456"),
    ("1234567890123456", "1234567890123456"),
])
def test_keyinfo_match(id1, id2):
    k = KeyInfo(type="1", bits=2048, id=id1, uid="123",
                date_created="Di 21. Feb 10:43:40 CET 2017")
    assert k.match(id2), k


class TestCrypto:

    def test_gen_key_and_get_public_keydata(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        logger.debug('keyhandle %s', keyhandle)
        keydata = crypto.get_public_keydata(keyhandle, armor=True)
        # logger.debug('keydata %s', keydata)
        # TODO: as below, not implemented

    def test_gen_key_and_get_secret_keydata(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        logger.debug('keyhandle %s', keyhandle)
        keydata = crypto.get_secret_keydata(keyhandle, armor=True)
        # logger.debug('keydata %s', keydata)
        # TODO: the following is not implemented
        # packets = bingpg.list_packets(keydata)
        # # maybe the below a bit too strict?
        # assert len(packets) == 5
        # assert packets[0][0] == "secret key packet"
        # assert packets[1][0] == "user ID packet"
        # assert packets[1][1] == '" <hello@xyz.org>"'
        # assert packets[2][0] == "signature packet"
        # assert packets[3][0] == "secret sub key packet"
        # assert packets[4][0] == "signature packet"
        #
        # keydata = bingpg.get_public_keydata(keyhandle)
        # packets = bingpg.list_packets(keydata)
        # assert len(packets) == 5
        # assert packets[0][0] == "public key packet" == packets[0][0]
        # assert packets[1][0] == "user ID packet"
        # assert packets[1][1] == '" <hello@xyz.org>"'
        # assert packets[2][0] == "signature packet"
        # assert packets[3][0] == "public sub key packet"
        # assert packets[4][0] == "signature packet"

    def test_list_secret_keyhandles(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        l = crypto.list_secret_keyinfos(keyhandle)
        logger.debug('l %s', l)
        assert len(l) == 2
        assert l[0].id == keyhandle

    def test_list_public_keyhandles(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        l = crypto.list_public_keyinfos(keyhandle)
        assert len(l) == 2
        assert l[0].match(keyhandle)

    # TODO: fix test encryptying/decrypting
    @pytest.mark.parametrize("armor", [True, False])
    def test_transfer_key_and_encrypt_decrypt_roundtrip(self, crypto,
                                                        armor):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        priv_keydata = crypto.get_secret_keydata(keyhandle=keyhandle,
                                                 armor=armor)
        logger.debug('test get secret data')
        if armor:
            priv_keydata.decode("ascii")
        public_keydata = crypto.get_public_keydata(keyhandle=keyhandle,
                                                   armor=armor)
        logger.debug('test get public data')
        if armor:
            public_keydata.decode("ascii")
        keyhandle2 = crypto.import_keydata(public_keydata)
        logger.debug('test import public data')
        assert keyhandle2 == keyhandle
        logger.debug('both keyhandles are the same')
        # FIXME:encryption works when testing in shell, but for some
        # reason when using public key here, obtain:
        # AttributeError: 'NoneType' object has no attribute 'fingerprint'
        # pgp.py:1359: AttributeError
        # and when using private key:
        # E               PGPError: Expected: is_public == True. Got: False
        # decorators.py:112: PGPError
        # out_encrypt = crypto.encrypt(b"123", recipients=[keyhandle])
        #
        # out, decrypt_info = crypto.decrypt(out_encrypt)
        # assert out == b"123"
        # assert len(decrypt_info) == 1
        # k = decrypt_info[0]
        # assert str(k)
        # assert k.bits == 2048
        # assert k.type == "RSA"
        # assert k.date_created
        # keyinfos = crypto.list_public_keyinfos(keyhandle)
        # for keyinfo in keyinfos:
        #     if keyinfo.match(k.id):
        #         break
        # else:
        #     pytest.fail("decryption key {!r} not found in {}".format(
        #                 k.id, keyinfos))

    def test_gen_key_and_sign_verify(self, crypto):
        keyhandle = crypto.gen_secret_key(emailadr="hello@xyz.org")
        sig = crypto.sign(b"123", keyhandle=keyhandle)
        ver = crypto.verify(data=b'123', signature=sig)
        kh = ver.good_signatures.next().by
        i = min(len(kh), len(keyhandle))
        assert keyhandle[-i:] == kh[-i:]
