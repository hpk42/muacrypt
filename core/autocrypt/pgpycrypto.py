# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
"""PGPyCrypto implements the OpenPGP operations needed for Autocrypt.
The API is the same as in bingpg.py.
"""

from __future__ import print_function, unicode_literals

import glob
import os
import re
import sys

import six
from pgpy import PGPUID, PGPKey, PGPMessage, PGPKeyring, PGPSignature
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)

# TODO: these two functions should be in a separate file
from .bingpg import KeyInfo, b64encode_u


# NOTE: key size was decided to be 2048
KEY_SIZE = 2048
# TODO: see which defaults we would like here
SKEY_ARGS = {
    'hashes': [HashAlgorithm.SHA512, HashAlgorithm.SHA256],
    'ciphers': [SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192,
                SymmetricKeyAlgorithm.AES128],
    'compression': [CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZ2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.Uncompressed]
}
# RSAEncrypt is deprecated, therefore using RSAEncryptOrSign
# also for the subkey
SKEY_ALG = PubKeyAlgorithm.RSAEncryptOrSign
SKEY_USAGE_SIGN = {KeyFlags.Sign}
SKEY_USAGE_ENC = {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
SKEY_USAGE_ALL = {KeyFlags.Sign, KeyFlags.EncryptCommunications,
                  KeyFlags.EncryptStorage}


def key_bytes(pgpykey):
    """Key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: key bytes
    :rtype: string

    """
    assert isinstance(pgpykey, PGPKey)
    if sys.version_info >= (3, 0):
        keybytes = bytes(pgpykey)
    else:
        keybytes = pgpykey.__bytes__()
    return keybytes


class PGPyCrypto(object):
    """OpenPGP operations for Autocrypt using PGPy.

    PGPy does not currently support file system keyring, therefore
    keys must be imported/exported from/to files or GPG keyring.

    .. todo::
         * instead of storing the keys in files, they could be stored
           in the autocrypt config.json file.
         * it probably would be better to create an abstract class
           as interface from which both BinGPG and PGPyCrypto inherit
           and then implement specific methods for BinGPG and PGPyCrypto.

    .. note::
         * methods not shared with BinGPG API are named as private.
         * some operations are kept for compatibility with BinGPG API,
           but they do not really make sense with PGPy.
    """

    def __init__(self, homedir=None, gpgpath="gpg"):
        """Init PGPyCrypto class.

        :param homedir: home dir
        :type key: str
        :param gpgpath: kept for compatibility with BinGPG API
        :type gpgpath: str

        """
        # NOTE: called as .._pgpy.. to know that is instance of PGPKey
        self.pgpydir = homedir
        self.memkr = PGPKeyring()
        self._ensure_init()

    def __str__(self):
        return "PGPyCrypto(homedir={homedir!r})".format(
            homedir=self.pgpydir)

    def _ensure_init(self):
        if self.pgpydir is None:
            return
        if not os.path.exists(self.pgpydir):
            os.mkdir(self.pgpydir)
            os.chmod(self.pgpydir, 0o700)
        self._loadkr()

    def _loadkr(self):
        keyfiles = glob.glob(os.path.join(self.pgpydir, '*.asc'))
        self.memkr.load(keyfiles)

    def _savekr(self):
        # NOTE: saving secret keys in clear in the filesystem is a secuirty
        # risk, but the generated keys with GPG are not passphrase protected
        # and PGPY does not implement yet filesystem key ring
        for fp in self.memkr.fingerprints():
            with self.memkr.key(fp) as key:
                self._save_key_to_file(key)

    def _key_path(self, key):
        ext = ''
        if key.is_public is False:
            ext = '.sec'
        ext += '.asc'
        keypath = os.path.join(self.pgpydir, key.fingerprint.keyid + ext)
        return keypath

    def _load_key_into_kr(self, key):
        keypath = self._save_key_to_file(key)
        self.memkr.load(keypath)

    def _save_key_to_file(self, key):
        keypath = self._key_path(key)
        with open(keypath, 'wb') as fd:
            fd.write(key_bytes(key))
        return keypath

    def _gen_skey_usage_all(self, emailadr):
        skey = PGPKey.new(SKEY_ALG, KEY_SIZE)
        # NOTE: pgpy implements separate attributes for name and e-mail
        # address. Name is mandatory.
        # Here e-mail address is used for the attribute name,
        # so that the uid is 'e-mail adress'.
        # If name attribute would be set to empty string
        # and email to the e-mail address, the uid would be
        # ' <e-mail address>', which we do not want.
        uid = PGPUID.new(emailadr)
        skey.add_uid(uid, usage=SKEY_USAGE_ALL, **SKEY_ARGS)
        return skey

    def _gen_ssubkey(self):
        # NOTE: the uid for the subkeys can be obtained with .parent,
        # but, unlike keys generated with gpg, it's not printed when imported
        # in gpg keyring and run --fingerprint.
        # in case of adding uid to the subkey, it raises currently some
        # exceptions depending on which are the arguments used, which are not
        # clear from the documentation.
        ssubkey = PGPKey.new(SKEY_ALG, KEY_SIZE)
        return ssubkey

    def _gen_skey_with_subkey(self, emailadr):
        # NOTE: skey should be generated with usage sign, but otherwise
        # encryption does not work currently.
        skey = self._gen_skey_usage_all(emailadr)
        ssubkey = self._gen_ssubkey()
        skey.add_subkey(ssubkey, usage=SKEY_USAGE_ENC)
        return skey

    def gen_secret_key(self, emailadr):
        """Generate PGPKey object.

        :param emailadr: e-mail address
        :return: keyhandle
        :type emailadr: string
        :rtype: string

        """
        skey = self._gen_skey_with_subkey(emailadr)
        self._load_key_into_kr(skey)
        return skey.fingerprint.keyid

    def supports_eddsa(self):
        # NOTE: PGPy does not currently support it
        return False

    def _get_key_from_keyhandle(self, keyhandle):
        # NOTE: this is a bit unefficient, there should be other way to obtain
        # a key from PGPKeyring
        for fp in self.memkr.fingerprints():
            with self.memkr.key(fp) as key:
                if key.fingerprint.keyid == keyhandle:
                    return key
        return None

    def _key_data(self, key, armor=False, b64=False):
        assert isinstance(key, PGPKey)
        if armor is True:
            keydata = str(key)
        else:
            keydata = key_bytes(key)
        return keydata if not b64 else b64encode_u(keydata)

    def get_public_keydata(self, keyhandle=None, armor=False, b64=False):
        key = self._get_key_from_keyhandle(keyhandle)
        if key is not None:
            pkey = key if key.is_public is True else key.pubkey
            return self._key_data(pkey, armor, b64)

    def get_secret_keydata(self, keyhandle=None, armor=False):
        key = self._get_key_from_keyhandle(keyhandle)
        if key is not None:
            skey = key if key.is_public is False else None
            return self._key_data(skey, armor) if skey is not None else None

    def list_secret_keyinfos(self, keyhandle=None):
        args = [keyhandle] if keyhandle is not None else []
        return self._parse_list(args, ("sec", "ssb"))

    def list_public_keyinfos(self, keyhandle=None):
        args = [keyhandle] if keyhandle is not None else []
        return self._parse_list(args, ("pub", "sub"))

    def _parse_list(self, args, types):
        # NOTE: the subkeys have to be at the end of the list to pass
        # the tests
        keyhandle = args[0] if args else None
        keyinfos = []
        # NOTE: public keys with private key are not loaded in memkr, as the
        # public part is in the private, so they have to be obtained from the
        # from the private ones
        keyhalf = 'public' if "pub" in types else 'private'
        primaryfps = self.memkr.fingerprints(keytype='primary')
        subfps = self.memkr.fingerprints(keytype='sub')
        for fp in primaryfps:
            with self.memkr.key(fp) as k:
                if keyhalf is 'public':
                    k = k.pubkey
                if keyhandle is None or keyhandle == k.fingerprint.keyid:
                    uid = k.userids[0].name
                    keyinfos.append(KeyInfo(type=k.key_algorithm.value,
                                            bits=k.key_size,
                                            uid=uid,
                                            id=k.fingerprint.keyid,
                                            date_created=k.created))
        for fp in subfps:
            with self.memkr.key(fp) as k:
                if keyhandle is None or \
                        keyhandle == k.parent.fingerprint.keyid:
                    uid = k.parent.userids[0].name
                    if keyhalf is 'public':
                        k = k.pubkey
                    keyinfos.append(KeyInfo(type=k.key_algorithm.value,
                                            bits=k.key_size,
                                            uid=uid,
                                            id=k.fingerprint.keyid,
                                            date_created=k.created))
        return keyinfos

    def list_packets(self, keydata):
        # NOTE: while is known how to get the packets from PGPKey,
        # use gpg only here
        import subprocess
        key, _ = PGPKey.from_blob(keydata)
        keypath = self._save_key_to_file(key)
        sp = subprocess.Popen(['/usr/bin/gpg', '--list-packets', keypath],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = sp.communicate()
        if sys.version_info >= (3, 0):
            out = out.decode()
        packets = []
        lines = []
        last_package_type = None
        for rawline in out.splitlines():
            line = rawline.strip()
            c = line[0:1]
            if c == "#":
                continue
            if c == ":":
                i = line[1:].find(c)
                if i != -1:
                    ptype = line[1: i + 1]
                    pvalue = line[i + 2:].strip()
                    if last_package_type is not None:
                        packets.append(last_package_type + (lines,))
                        lines = []
                    last_package_type = (ptype, pvalue)
            else:
                assert last_package_type, line
                lines.append(line)
        else:
            packets.append(last_package_type + (lines,))
        return packets

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

    def _encrypt_msg_with_pkey(self, data, key):
        clear_msg = PGPMessage.new(data)
        pkey = key if key.is_public else key.pubkey
        enc_msg = pkey.encrypt(clear_msg)
        return enc_msg

    def encrypt(self, data, recipients):
        assert len(recipients) >= 1
        clear_msg = PGPMessage.new(data)
        # enc_msg |= self.pgpykey.sign(enc_msg)
        if len(recipients) == 1:
            key = self._get_key_from_keyhandle(recipients[0])
            enc_msg = key.pubkey.encrypt(clear_msg)
        else:
            # The symmetric cipher should be specified, in case the first
            # preferred cipher is not the same for all recipients public
            # keys.
            cipher = SymmetricKeyAlgorithm.AES256
            sessionkey = cipher.gen_key()
            enc_msg = clear_msg
            for r in recipients:
                key = self._get_key_from_keyhandle(r)
                enc_msg = key.pubkey.encrypt(enc_msg, cipher=cipher,
                                             sessionkey=sessionkey)
            del sessionkey
        return str(enc_msg)

    def sign(self, data, keyhandle):
        key = self._get_key_from_keyhandle(keyhandle)
        sig_data = key.sign(data)
        return sig_data

    def _skeys(self):
        skeys = []
        secfps = self.memkr(keyhalf="private")
        for fp in secfps:
            with self.memkr.key(fp) as key:
                skeys.append(key)
        return skeys

    def verify(self, data, signature):
        sig = PGPSignature(signature) \
            if isinstance(signature, str) else signature
        keyhandle = sig.signer
        key = self._get_key_from_keyhandle(keyhandle)
        skey = key if key.is_public is False else key.pubkey
        ver = skey.verify(data, signature)
        good = next(ver.good_signatures)
        return good.by

    def decrypt(self, enc_data):
        if isinstance(enc_data, str):
            enc_msg = PGPMessage.from_blob(enc_data)
        else:
            enc_msg = enc_data
        keyhandle = enc_msg.issuers.pop()
        skey = self._get_key_from_keyhandle(keyhandle)
        out = skey.decrypt(enc_msg)
        keyinfos = []
        keyinfos.append(KeyInfo(skey.key_algorithm.name, skey.key_size,
                                skey.fingerprint.keyid, skey.userids[0].name,
                                skey.created))
        return six.b(out.message), keyinfos

    def import_keydata(self, keydata):
        key, _ = PGPKey.from_blob(keydata)
        self._load_key_into_kr(key)
        return key.fingerprint.keyid
