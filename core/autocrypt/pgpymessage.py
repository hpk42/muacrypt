#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Functions to generate and parse encrypted Email following
 Autcrypt technical specifications.
"""

import logging
import logging.config
import random
import re

from base64 import b64decode
from email import policy
from email.mime.text import MIMEText
from email.message import Message
# from email.header import Header
from email.parser import Parser

from emailpgp.mime.multipartpgp import MIMEMultipartPGP

from .acmime import MIMEMultipartACSetup
from .constants import (ADDR, KEYDATA, AC_HEADER, AC_GOSSIP,
                        AC_GOSSIP_HEADER, PE_HEADER_TYPES, NOPREFERENCE,
                        AC_HEADER_PE, PE, AC, AC_PREFER_ENCRYPT_HEADER,
                        AC_PASSPHRASE_LEN, AC_PASSPHRASE_WORD_LEN,
                        AC_PASSPHRASE_NUM_WORDS, AC_PASSPHRASE_FORMAT,
                        AC_PASSPHRASE_BEGIN_LEN, AC_PASSPHRASE_NUM_BLOCKS,
                        AC_PASSPHRASE_BEGIN, AC_SETUP_INTRO)

logger = logging.getLogger(__name__)
parser = Parser(policy=policy.default)


__all__ = ['keydata_wrap', 'keydata_unwrap', 'gen_ac_headers','gen_headers',
           'gen_header_from_dict', 'header_unwrap', 'parse_header',
           'gen_mime_enc_multipart', 'gen_headers_email', 'gen_ac_email',
           'decrypt_mime_enc_email', 'parse_ac_email',
           'ac_header_email_unwrap_keydata', 'gen_ac_gossip_header',
           'gen_ac_gossip_headers', 'parse_ac_gossip_headers',
           'store_gossip_keys',
           'get_skey_from_msg', 'parse_ac_gossip_email',
           'gen_ac_gossip_cleartext_email', 'gen_ac_gossip_email']


def keydata_wrap(value, maxlen=76, indent=" "):
    assert "\n" not in value
    return indent + indent.join([value[0 + i:maxlen + i]
                                 for i in range(0, len(value), maxlen)])


def keydata_unwrap(keydata_wrapped, wrap_char='\n '):
    return keydata_wrapped.replace(wrap_char, '').strip()


def gen_header_from_dict(header_dict):
    return "; ".join(["=".join([k, v]) for k, v in header_dict.items()])


def header_unwrap(header, wrap_char="\n "):
    header_dict = parse_header(header)
    header_dict['keydata'] = keydata_unwrap(header_dict['keydata'], wrap_char)
    return gen_header_from_dict(header_dict)


def header_wrap(header, maxlen=76, indent=" "):
    header_dict = parse_header(header)
    header_dict['keydata'] = keydata_wrap(header_dict['keydata'], maxlen,
                                          indent)
    return gen_header_from_dict(header_dict)


def gen_ac_header_dict(addr, keydata, pe=None, unwrap=False, wrap_char='\n '):
    ac_header = gen_ac_header(addr, keydata, pe, True, '\n')
    return {AC: ac_header}


def gen_ac_header(addr, keydata, pe=None, unwrap=False, wrap_char='\n '):
    """Generate Autocrypt header

    :param key: keydata (base 64 encoded public key)
    :type key: string
    :param addr: e-mail address
    :type addr: string
    :param pe: prefer-encrypt
    :type pe: string
    :return: Autocrypt header
    :rtype: string

    """
    assert keydata
    assert pe in PE_HEADER_TYPES
    if isinstance(keydata, bytes):
        keydata = keydata.decode()
    if unwrap:
        keydata = keydata_unwrap(keydata, wrap_char)
    if pe is None or pe == NOPREFERENCE:
        ac_header = AC_HEADER % {ADDR: addr, KEYDATA: keydata}
    else:
        ac_header = AC_HEADER_PE % {ADDR: addr, "pe": pe,
                                    KEYDATA: keydata}
    return ac_header


def parse_header(header):
    # NOTE: can not just do the following, as keydata may contain "="
    # header_dict = dict([(k.strip(),v.strip()) for k,v in
    #                     [i.split('=') for i in header.split(';')]])
    # NOTE: email.mime splits keywords with '\n '
    header_kv_list = re.split('; |;\n ', header)
    header_dict = dict()
    for kv in header_kv_list:
        if kv.startswith('addr='):
            header_dict[ADDR] = kv.split('addr=')[1].strip()
        elif kv.startswith('prefer-encrypt='):
            header_dict[PE] = kv.split('prefer-encrypt=')[1].strip()
        elif kv.startswith('keydata='):
            header_dict[KEYDATA] = kv.split('keydata=')[1].strip()
    return header_dict


def parse_ac_headers(msg):
    if not isinstance(msg, Message):
        msg = parser.parsestr(msg)
    ac_header_list = [v.strip() for k, v in msg.items() if k == AC]
    return [parse_header(i) for i in ac_header_list]


def gen_mime_enc_multipart(mime_enc_body, boundary=None):
    msg = MIMEMultipartPGP(mime_enc_body, boundary)
    logger.debug('Generated encrypted multipart body.')
    return msg


def gen_headers(msg, sender, recipients, subject, date=None, _dto=False,
                message_id=None, _extra=None):
    if _dto:
        msg["Delivered-To"] = recipients[0]
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    if date:
        msg["Date"] = date
    if message_id:
        msg["Message-ID"] = message_id
    if _extra is not None:
        for name, value in _extra.items():
            msg.add_header(name, value)
    logger.debug('Generated headers.')


def gen_ac_headers(msg, sender, keydata, pe):
    ac_header = gen_ac_header(sender, keydata, pe)
    ac_header_wrapped = header_wrap(ac_header)
    # NOTE: maxlinelen and continuation_ws are set to defaults.
    # They should wrap long lines, but the following code wrap only text
    # from "; "
    # h = Header(ac_header_wrapped, maxlinelen=76, header_name="Autocrypt",
    #            continuation_ws=' ')
    # encode works as expected, but then can not add header with linefeed nor
    # carriage return
    # h_encoded = h.encode(splitchars=' ', maxlinelen=76, linesep='\n ')
    # msg['Autocrypt'] = h_encoded
    msg.add_header("Autocrypt", ac_header_wrapped)
    logger.debug('Generated AC headers.')
    return msg


def gen_ac_email(sender, recipients, p, subject, body, pe=None,
                 keyhandle=None, date=None, _dto=False, message_id=None,
                 boundary=None, _extra=None):
    """."""
    if keyhandle is None:
        keyhandle = p._get_keyhandle_from_addr(sender)
    keydata = p.get_public_keydata(keyhandle, b64=True)

    data = MIMEText(body)
    enc = p.sign_encrypt(data.as_bytes(), keyhandle, recipients)
    msg = gen_mime_enc_multipart(str(enc), boundary)
    msg = gen_headers(msg, sender, recipients, subject, date, _dto,
                      message_id, _extra)
    msg = gen_ac_headers(msg, sender, keydata, pe)
    logger.debug('Generated Autcrypt Email: \n%s', msg)
    return msg


def decrypt_mime_enc_email(msg, p, key=None):
    if not isinstance(msg, Message):
        msg = parser.parsestr(msg)
    assert msg.is_multipart()
    assert msg.get_content_subtype() == "encrypted"
    for payload in msg.get_payload():
        if payload.get_content_type() == 'application/octet-stream':
            enc_text = payload.get_payload()
    logger.debug('RM: key dict %s', key)
    dec, _ = p.decrypt(enc_text, key)
    logger.debug('Decrypted Email.')
    return dec.decode()


def parse_ac_email(msg, p):
    if not isinstance(msg, Message):
        msg = parser.parsestr(msg)
    ac_headers = parse_ac_headers(msg)
    if len(ac_headers) == 1:
        ac_header_dict = ac_headers[0]
    else:
        # TODO: error
        pass
    p.import_keydata(b64decode(ac_header_dict['keydata']))
    logger.debug('Imported keydata from Autcrypt header.')
    key = get_skey_from_msg(msg, p)

    dec = decrypt_mime_enc_email(msg, p, key)
    logger.debug('Parsed Autocrypt Email.')
    return msg, dec


def ac_header_email_unwrap_keydata(text):
    # NOTE: this would not replace the headers, but add new ones
    msg = parser.parsestr(text)
    ac_header = msg.get_all(AC)[0]
    msg[AC] = header_unwrap(ac_header)
    ac_gossip_headers = msg.get_all(AC_GOSSIP)
    if ac_gossip_headers is not None:
        for g in ac_gossip_headers:
            msg[AC_GOSSIP] = header_unwrap(g)
    return msg.as_string()


def gen_ac_gossip_header(addr, keydata):
    return AC_GOSSIP_HEADER % {ADDR: addr, KEYDATA: keydata}


def gen_ac_gossip_headers(recipients, p):
    gossip_list = []
    for r in recipients:
        logger.debug('Generating Gossip header for recipient:\n%s', r)
        keyhandle = p._get_keyhandle_from_addr(r)
        keydata = p.get_public_keydata(keyhandle, b64=True)
        g = gen_ac_gossip_header(r, keydata)
        gossip_list.append(g)
    return gossip_list


def parse_ac_gossip_headers(text):
    if not isinstance(text, Message):
        msg = parser.parsestr(text)
    else:
        msg = text
    # when
    gossip_list = [v.strip() for k, v in msg.items() if k == AC_GOSSIP]
    return gossip_list


def store_gossip_keys(gossip_list, p):
    for g in gossip_list:
        g_dict = parse_header(g)
        k = g_dict['keydata']
        logger.debug('Import keydata from Gossip header.')
        p.import_keydata(b64decode(k))


def get_skey_from_msg(text, p):
    if isinstance(text, str):
        msg = parser.parsestr(text)
    else:
        msg = text

    for recipient in msg['To'].split(', '):
        key = p._get_key_from_addr(recipient)
        if key is not None:
            if key.is_public:
                key = p._get_key_from_keyhandle(key.fingerprint.keyid)
                if key is not None:
                    logger.debug('Found private key for recipient %s',
                                 recipient)
                    return key
            else:
                return key
    return None


def parse_ac_gossip_email(msg, p):
    if isinstance(msg, str):
        msg = parser.parsestr(msg)
    ac_headers = parse_ac_headers(msg)
    if len(ac_headers) == 1:
        ac_header_dict = ac_headers[0]
    else:
        # TODO: error
        ac_header_dict = ac_headers[0]
    p.import_keydata(b64decode(ac_header_dict['keydata']))
    logger.debug('Imported keydata from Autocrypt header.')

    key = get_skey_from_msg(msg, p)
    dec_text = decrypt_mime_enc_email(msg, p, key)
    # NOTE: hacky workaround, because "\n" is added after "; ""
    dec_text = dec_text.replace(";\n keydata|;\r keydata|;\r\n keydata|;\n\r keydata", "; keydata")
    open('foo', 'w').write(dec_text)
    dec_msg = parser.parsestr(dec_text)
    logger.debug('dec_msg %s', dec_msg)
    gossip_list = parse_ac_gossip_headers(dec_msg)
    logger.debug('gossip_list %s', gossip_list)
    store_gossip_keys(gossip_list, p)

    return msg, dec_msg, gossip_list


def gen_ac_gossip_cleartext_email(recipients, body, p):
    gossip_headers = gen_ac_gossip_headers(recipients, p)
    logger.debug('gossip headers %s', gossip_headers)
    msg = MIMEText(body)
    for g in gossip_headers:
        msg[AC_GOSSIP] = g
    return msg


def gen_ac_gossip_email(sender, recipients, p, subject, body, pe=None,
                        keyhandle=None, date=None, _dto=False, message_id=None,
                        boundary=None, _extra=None):
    """."""
    if keyhandle is None:
        keyhandle = p._get_keyhandle_from_addr(sender)
    keydata = p.get_public_keydata(keyhandle, b64=True)

    msg_clear = gen_ac_gossip_cleartext_email(recipients, body, p)

    enc = p.sign_encrypt(msg_clear.as_bytes(), keyhandle, recipients)
    msg = gen_mime_enc_multipart(str(enc), boundary)
    logger.debug(msg)
    msg = gen_headers_email(msg, sender, recipients, keydata, subject, pe,
                            keyhandle, date, _dto, message_id, _extra)
    return msg


def gen_ac_setup_seckey(sender, pe, p, keyhandle=None):
    if keyhandle is None:
        keyhandle = p._get_keyhandle_from_addr(sender)
    seckey = p.get_secret_keydata(keyhandle, armor=True)
    ac_setup_seckey = "\n".join(seckey.split('\n').
                                insert(2, AC_PREFER_ENCRYPT_HEADER + pe))
    return ac_setup_seckey


def gen_ac_setup_passphrase():
    numbers = [random.randrange(0, 9) for i in range(0, AC_PASSPHRASE_LEN)]
    passphrase = "-".join(["".join(numbers[0+i:AC_PASSPHRASE_WORD_LEN+i])
                           for i in range(0, AC_PASSPHRASE_NUM_WORDS)])
    len_block = len(passphrase) + 1 / AC_PASSPHRASE_NUM_BLOCKS
    passphrase_blocks = "\n".join([passphrase[0+i:len_block+i]
                                   for i in range(0, len(passphrase),
                                                  len_block)])
    logger.info(passphrase_blocks)
    return passphrase_blocks


def gen_ac_setup_enc_seckey(ac_setup_seckey, passphrase, p):
    encmsg = p.sym_encrypt(ac_setup_seckey, passphrase)

    ac_setup_enctext = "\n".join(str(encmsg).split('\n').
                                 insert(2, AC_PASSPHRASE_FORMAT + "\n" +
                                        AC_PASSPHRASE_BEGIN +
                                        passphrase[:AC_PASSPHRASE_BEGIN_LEN]))
    return AC_SETUP_INTRO + "\n" + ac_setup_enctext


def gen_ac_setup_email(sender, p, subject, body, pe,
                       keyhandle=None, date=None, _dto=False, message_id=None,
                       boundary=None, _extra=None):
    passphrase = gen_ac_setup_passphrase()
    ac_setup_seckey = gen_ac_setup_seckey(sender, pe, p, keyhandle)
    ac_setup_enc_seckey = gen_ac_setup_enc_seckey(ac_setup_seckey,
                                                  passphrase, p)
    msg = MIMEMultipartACSetup(ac_setup_enc_seckey, boundary)
    logger.debug('Generated multipart AC Setup body.')
    return msg
