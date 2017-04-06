# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

"""Crypto implements GPG operations needed for Autocrypt.
API is copied from bingpg.py
"""

from __future__ import print_function, unicode_literals
import logging
import os
import glob
import sys
from base64 import b64encode
import re
import getpass
from operator import attrgetter
from pgpy import PGPKey, PGPUID, PGPMessage, PGPKeyring
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm

logger = logging.getLogger(__name__)


def key_base64(pgpykey):
    """Base 64 representation of key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: Base 64 representation of pgpykey bytes
    :rtype: string

    """
    assert type(pgpykey) == PGPKey
    keybytes = key_bytes(pgpykey)
    keybase64 = b64encode(keybytes)
    return keybase64


def key_bytes(pgpykey):
    """Key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: key bytes
    :rtype: string

    """
    assert type(pgpykey) == PGPKey
    if sys.version_info >= (3, 0):
        keybytes = bytes(pgpykey)
    else:
        keybytes = pgpykey.__bytes__()
    return keybytes


def cached_property(f):
    # returns a property definition which lazily computes and
    # caches the result of calling f.  The property also allows
    # setting the value (before or after read).
    def get(self):
        propcache = self.__dict__.setdefault("_property_cache", {})
        key = f.__name__
        try:
            return propcache[key]
        except KeyError:
            x = self._property_cache[key] = f(self)
            return x

    def set(self, val):
        propcache = self.__dict__.setdefault("_property_cache", {})
        propcache[f.__name__] = val
    return property(get, set)


class Crypto(object):
    """ GPG operations for Autocrypt using PGPy. """
    # TODO: Write in identity YAML file the keys, so it won't be needed
    # to import/export in different files.

    def __init__(self, homedir=None):
        self.own_pgpykey = None
        self.publicpgpykeys = []
        self.secretpgpykeys = []
        self.secretpgpykr = None
        self.publicpgpykr = None
        self.pgpydir = homedir
        self._ensure_init()

    def __str__(self):
        return "Crypto(homedir={homedir!r})".format(
            homedir=self.pgpydir)

    def _ensure_init(self):
        if self.pgpydir is None:
            return

        if not os.path.exists(self.pgpydir):
            # we create the dir if the basedir exists, otherwise we fail
            os.mkdir(self.pgpydir)
            os.chmod(self.pgpydir, 0o700)

        # self.load_pgpykr()
        # NOTE: this would lose parent and subkeys info.
        # self.load_keys_from_pgpykr()
        self.load_keys_from_pgpyhome()

    def load_pgpykr(self):
        # NOTE: this is not being used
        self.publicpgpykr = PGPKeyring(glob.glob(
                                os.path.join(self.pgpydir, '*.asc')))
        logger.debug('publickr fingerprints %s' %
                     self.publicpgpykr.fingerprints())
        self.secretpgpykr = PGPKeyring(glob.glob(
                                os.path.join(self.pgpydir, '*.key')))
        logger.debug('secretpgpykr fingerprints %s' %
                     self.secretpgpykr.fingerprints())

    def load_keys_from_pgpyhome(self):
        pkpaths = glob.glob(os.path.join(self.pgpydir, '*.asc'))
        for pkpath in pkpaths:
            pk, psubkeys = PGPKey.from_file(pkpath)
            self.publicpgpykeys.append(pk)
        logger.debug('self.publicpgpykeys %s', self.publicpgpykeys)
        skpaths = glob.glob(os.path.join(self.pgpydir, '*.key'))
        for skpath in skpaths:
            sk, ssubkeys = PGPKey.from_file(skpath)
            self.secretpgpykeys.append(sk)
        if self.own_pgpykey is None and self.secretpgpykeys:
            # FIXME: there could be more than 1?
            self.own_pgpykey = self.secretpgpykeys[0]
            logger.debug('self.own_pgpykey.fingerprint.keyid %s',
                         self.own_pgpykey.fingerprint.keyid)
        logger.debug('self.secretpgpykeys %s', self.secretpgpykeys)

    def load_keys_from_pgpykr(self):
        # NOTE: not using this method
        last_primary = None
        last_non_primary = None
        for fp in self.publicpgpykr.fingerprints():
            with self.publicpgpykr.key(fp) as pk:
                if pk.is_primary:
                    last_primary = pk
                    pk.subkeys.append(last_non_primary)
                    last_non_primary = None
                else:
                    last_non_primary = pk
                    pk.parent = last_primary
                    last_primary = None
                    logger.debug('pk.parent', pk.parent)
                self.publicpgpykeys.append(pk)
        self.publicpgpykeys = sorted(self.publicpgpykeys,
                                     key=attrgetter('fingerprint',
                                                    'is_primary'),
                                     reverse=True)
        logger.debug('public keys %s', self.publicpgpykeys)
        last_primary = None
        last_non_primary = None

        for fp in self.secretpgpykr.fingerprints():
            with self.secretpgpykr.key(fp) as sk:
                if sk.is_primary:
                    last_primary = sk
                    sk.subkeys.append(last_non_primary)
                    last_non_primary = None
                    self.own_pgpykey = sk
                else:
                    last_non_primary = sk
                    sk.parent = last_primary
                    last_primary = None
                    logger.debug('pk.parent', pk.parent)
                self.secretpgpykeys.append(sk)
        self.secretpgpykeys = sorted(self.secretpgpykeys,
                                     key=attrgetter('fingerprint',
                                                    'is_primary'),
                                     reverse=True)
        logger.debug('secret keys %s', self.secretpgpykeys)

    def add_key(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey
        if not pgpykey.is_public:
            self.secretpgpykeys.append(pgpykey)
            self.publicpgpykeys.append(pgpykey.pubkey)
        else:
            assert type(pgpykey) == PGPKey
            self.publicpgpykeys.append(pgpykey)
        logger.debug('publicppgpykeys %s', self.publicpgpykeys)
        logger.debug('secretppgpykeys %s', self.secretpgpykeys)

    def gen_secret_key(self,
                       emailadr='alice@testsuite.autocrypt.org',
                       alg_key=PubKeyAlgorithm.RSAEncryptOrSign,
                       alg_subkey=PubKeyAlgorithm.RSAEncryptOrSign,
                       size=2048,
                       add_subkey=True,
                       protected=False,
                       _own=True):
        # RSAEncrypt is deprecated, therefore using RSAEncryptOrSign
        # also for the subkey
        """Generate PGPKey object.

        :param alg_key: algorithm for primary key
        :param alg_subkey: algorithm for subkey
        :param size: key size
        :param emailadr: e-mail address
        :return: key
        :type alg_key: PubKeyAlgorithm
        :type alg_subkey: PubKeyAlgorithm
        :type size: integer
        :type emailadr: string
        :rtype: PGPKey

        """
        # NOTE: default algorithm was decided to be RSA and size 2048.
        skey = PGPKey.new(alg_key, size)
        logger.debug('new pgpkey')
        # NOTE: pgpy implements separate attributes for name and e-mail
        # address. Name is mandatory.
        # Here e-mail address is used for the attribute name .
        # If name attribute would be set to empty string
        # and email to the e-mail address, the uid would be
        # ' <e-mail address>', for instance:
        # " <alice@testsuite.autocrypt.org>" - which we do not want.
        uid = PGPUID.new(emailadr)
        logger.debug('new uid %s', uid)
        # NOTE: it is needed to specify all arguments in current pgpy
        # version.
        # FIXME: see which defaults we would like here
        skey.add_uid(
                uid,
                usage={KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256,
                         SymmetricKeyAlgorithm.AES192,
                         SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB,
                             CompressionAlgorithm.BZ2,
                             CompressionAlgorithm.ZIP,
                             CompressionAlgorithm.Uncompressed])
        logger.debug('uid added')
        if add_subkey is True:
            subkey = PGPKey.new(alg_subkey, size)
            logger.debug('new subkey')
            skey.add_subkey(subkey,
                            usage={KeyFlags.EncryptCommunications,
                                   KeyFlags.EncryptStorage})
            logger.debug('subkey added')
        if protected is True:
            passphrase = getpass.getpass()
            skey.protect(
                             passphrase,
                             SymmetricKeyAlgorithm.AES256,
                             HashAlgorithm.SHA256)
            logger.debug('Key protected')
        # NOTE: this is not needed, as it it signed by default
        # self.sign_own_key()

        # put the key as exported ASCII-armored in ring
        self.export_key(skey)
        logger.debug('exported key')
        self.publicpgpykeys.append(skey.pubkey)
        self.secretpgpykeys.append(skey)
        logger.debug('updated loaded keys')
        logger.debug('self.publicpgpykeys %s', self.publicpgpykeys)
        logger.debug('self.secretpgpykeys %s', self.secretpgpykeys)
        # self.load_pgpykr()
        # self.add_key(skey)
        # self.load_keys_from_pgpykr()
        if _own is True:
            self.own_pgpykey = skey
            self.own_keyhandle = skey.fingerprint.keyid
            logger.debug('longid %s', self.own_keyhandle)
        return skey.fingerprint.keyid

    def supports_eddsa(self):
        # NOTE: PGPy does not currently support it
        return False

    def export_skey(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey
        assert type(pgpykey) == PGPKey
        assert not pgpykey.is_public
        secretkeydata = self.get_secret_keydata(armor=True,
                                                pgpykey=pgpykey)
        skpath = os.path.join(self.pgpydir, pgpykey.fingerprint.keyid
                              + '.key')
        with open(skpath, 'w') as fd:
            fd.write(secretkeydata)
            logger.debug('written %s', skpath)

    def export_pkey(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey.pubkey
        assert type(pgpykey) == PGPKey
        if not pgpykey.is_public:
            pgpykey = pgpykey.pubkey
        publickeydata = self.get_public_keydata(armor=True,
                                                pgpykey=pgpykey)
        pkpath = os.path.join(self.pgpydir, pgpykey.fingerprint.keyid
                              + '.asc')
        with open(pkpath, 'w') as fd:
            fd.write(publickeydata)
            logger.debug('written %s', pkpath)

    def export_key(self, pgpykey=None):
        if pgpykey is None:
            pgpykey = self.own_pgpykey
        assert type(pgpykey) == PGPKey
        if pgpykey.is_public:
            self.export_pkey(pgpykey)
        else:
            self.export_skey(pgpykey)
            self.export_pkey(pgpykey.pubkey)

    def export_keys(self):
        [self.export_pkey(k) for k in self.publicpgpykeys]
        [self.export_skey(k) for k in self.secretgpykeys]
        logger.debug('exported all keys')

    def get_secretkey_from_keyhandle(self, keyhandle):
        for k in self.secretpgpykeys:
            if (k.fingerprint.keyid == keyhandle
                or k.fingerprint.shortid == keyhandle):
                logger.debug('found secret key with keyhandle %s',
                             keyhandle)
                logger.debug('type(k) %s', type(k))
                return k
        logger.debug('not found secret key with keyhandle')
        return None

    def get_publickey_from_kh(self, keyhandle):
        for k in self.publicpgpykeys:
            if (k.fingerprint.keyid == keyhandle
                or k.fingerprint.shortid == keyhandle):
                logger.debug('found public key with keyhandle %s',
                             keyhandle)
                logger.debug('type(k) %s', type(k))
                return k
        logger.debug('not found public key with keyhandle')
        return None

    def get_key_from_keyhandle(self, keyhandle):
        k = self.get_secretkey_from_keyhandle(keyhandle)
        if k is None:
            logger.debug('not found secret key, trying with public one')
            k = self.get_publickey_from_kh(keyhandle)
        return k

    def get_userid_from_keyhandle(self, keyhandle=None):
        if keyhandle is None:
            return self.own_pgpykey.userids[0].name
        uids = [k.userids[0] for k in self.publicpgpykeys
                if (len(k.userids) > 0
                    and k.fingerprint.keyid == keyhandle)]
        if len(uids) > 0:
            return uids[0]
        return None

    def get_public_keydata(self, keyhandle=None, armor=False,
                           b64=False, pgpykey=None):
        if pgpykey is None and keyhandle is None:
            logger.debug('No keyhandle, no key')
            pgpykey = self.own_pgpykey.pubkey
        elif pgpykey is None and keyhandle is not None:
            logger.debug('no key, but keyhandle')
            pgpykey = self.get_publickey_from_kh(keyhandle)
        elif pgpykey is not None and not pgpykey.is_public:
            logger.debug('key, but not public')
            pgpykey = pgpykey.pubkey
        elif pgpykey is not None:
            logger.debug('key')
            pgpykey = pgpykey
        else:
            return None
        assert type(pgpykey) == PGPKey
        logger.debug('pgpykey.fingerprint.longid %s',
                     pgpykey.fingerprint.keyid)
        if armor is True:
            keydata = str(pgpykey)
        else:
            keydata = key_bytes(pgpykey)
        if b64 is True:
            keydata = key_base64(pgpykey)
        return keydata

    def get_secret_keydata(self, keyhandle=None, armor=False,
                           pgpykey=None):
        if pgpykey is None and keyhandle is None:
            logger.debug('No keyhandle, no key')
            pgpykey = self.own_pgpykey
        elif pgpykey is None and keyhandle is not None:
            logger.debug('no key, but keyhandle')
            pgpykey = self.get_secretkey_from_keyhandle(keyhandle)
        elif pgpykey is not None:
            logger.debug('key')
            pgpykey = pgpykey
        else:
            logger.debug('no key')
            return None
        assert not pgpykey.is_public
        if armor is True:
            keydata = str(pgpykey)
        else:
            keydata = key_bytes(pgpykey)
        return keydata

    # def keyuids(self):
    #     return [uid.name for uid in self.own_pgpykey.userids]

    # def keyinfo(self):
    #     ki = (
    #         self.own_pgpykey.key_algorithm.value,
    #         self.own_pgpkey.userids[0].name,
    #         self.own_pgpykey.key_size,
    #         self.own.pgpykey.fingerprint.keyid,
    #         self.own_pgpykey.subkeys.items(),
    #         [uid.name for uid in self.own_pgpykey.userids],
    #         self.own_pgpykey.created
    #     )
    #     return ki

    def list_secret_keyinfos(self, keyhandle=None):
        return self._parse_list(type_public=False)

    def list_public_keyinfos(self, keyhandle=None):
        return self._parse_list()

    def _parse_list(self, type_public=True):
        # NOTE: the subkeys have to be at the end of the list to pass
        # the tests
        keyinfos = []
        if type_public is True:
            keys = self.publicpgpykeys
        else:
            keys = self.secretpgpykeys
        for k in keys:
            if len(k.userids) > 0:
                uid = k.userids[0].name
            else:
                uid = k.parent.userids[0].name
            keyinfos.append(KeyInfo(type=k.key_algorithm.value,
                                    bits=k.key_size,
                                    uid=uid,
                                    id=k.fingerprint.keyid,
                                    date_created=k.created))
            for k in k.subkeys.values():
                keyinfos.append(KeyInfo(type=k.key_algorithm.value,
                                        bits=k.key_size,
                                        uid=uid,
                                        id=k.fingerprint.keyid,
                                        date_created=k.created))

        logger.debug('keyinfos %s', keyinfos)
        return keyinfos

    def _find_keyhandle(self, string,
                        _pattern=re.compile("key (?:ID )?([0-9A-F]+)")):
        # search for string like "key <longid/shortid>"
        m = _pattern.search(string)
        assert m and len(m.groups()) == 1, string
        x = m.groups()[0]
        # now search the fingerprint if we only have a shortid
        if len(x) <= 8:
            keyinfos = self.list_public_keyinfos(x)
            for k in keyinfos:
                if k.match(x):
                    return k.id
            raise ValueError("could not find fingerprint %r in %r" %
                             (x, keyinfos))
        # note that this might be a 16-char fingerprint or a 40-char one
        # (gpg-2.1.18)
        return x

    def encrypt(self, data, recipients):
        # The symmetric cipher should be specified, in case the first
        # preferred cipher is not the same for all recipients public
        # keys.
        # FIXME: is this really needed?
        # cipher = SymmetricKeyAlgorithm.AES256
        # sessionkey = cipher.gen_key()
        enc_msg = PGPMessage.new(data)
        logger.debug('enc_msg.message %s with recipients %s',
                     enc_msg.message, recipients)
        # FIXME: check if the order of encryption/signing matters
        enc_msg |= self.own_pgpykey.sign(enc_msg)
        logger.debug('enc_msg.signers %s', enc_msg.signers)
        logger.debug('recipients %s', recipients)
        for r in recipients:
            # FIXME: check if it is not needed to provide the public
            # subkey for encryption
            # k = self.get_key_from_keyhandle(r)
            k = self.get_publickey_from_kh(r)
            # if not k.is_public:
            #     pk = k.pubkey
            # else:
            #     pk = k
            # psubkey = pk.subkeys.values()[0]
            # logger.debug('psubkey %s', psubkey)
            logger.debug('type(k) %s', type(k))
            logger.debug('about to encrypt with key %s',
                         k.fingerprint.keyid)
            enc_msg = k.encrypt(enc_msg)
            # enc_msg = psubkey.encrypt(enc_msg)
        logger.debug('enc_msg %s', enc_msg)
        logger.debug('type(enc_msg) %s', type(enc_msg))

        # do at least this as soon as possible after encrypting to the
        # final recipient
        # del sessionkey
        return enc_msg

    def sign(self, data, keyhandle=None):
        if (keyhandle is not None and
                self.get_key_from_keyhandle(keyhandle) is not None):
            pgpykey = self.get_key_from_keyhandle(keyhandle)
        else:
            pgpykey = self.own_pgpykey
        sig_data = pgpykey.sign(data)
        logger.debug('data signed by %s', sig_data.signer)
        return sig_data

    def verify(self, data, signature):
        ver = self.own_pgpykey.verify(data, signature)
        gs = ver.good_signatures.next()
        logger.debug('data signed by %s verified %s',
                     gs.by, gs.verified)
        return ver

    def decrypt(self, enc_data):
        logger.debug('enc_data %s', enc_data)
        logger.debug('type(enc_data) %s', type(enc_data))
        if type(enc_data) == str:
            enc_data_pgpy = PGPMessage.from_blob(enc_data)
        else:
            enc_data_pgpy = enc_data
        out = self.own_pgpykey.decrypt(enc_data_pgpy)
        # out = enc_data_pgpy.decrypt(self.own_pgpykey)
        logger.debug('type(out) %s', type(out))
        logger.debug('out %s', out)
        # TODO: extract keyinfos, for instance
        # keyinfos = [('RSA', '2048', 'longid', 'uid', 'created')]
        return out.message, []

    def import_keydata(self, keydata):
        pgpykey, _ = PGPKey.from_blob(keydata)
        logger.debug("imported key %s", pgpykey.fingerprint.keyid)
        self.export_key(pgpykey)
        if pgpykey.is_public:
            self.publicpgpykeys.append(pgpykey)
        else:
            self.secretpgpykeys.append(pgpykey)
            self.publicpgpykeys.append(pgpykey.pubkey)
        return pgpykey.fingerprint.keyid


class KeyInfo:
    def __init__(self, type, bits, id, uid, date_created):
        self.type = type
        self.bits = int(bits)
        self.id = id
        self.uids = [uid] if uid else []
        self.date_created = date_created

    def match(self, other_id):
        i = min(len(other_id), len(self.id))
        return self.id[-i:] == other_id[-i:]

    def __str__(self):
        return "KeyInfo(id={id!r}, uids={uids!r}, bits={bits}, \
                type={type})".format(
            **self.__dict__)

    __repr__ = __str__
