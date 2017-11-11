#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Functions to generate and parse encrypted Email following
 Autcrypt technical specifications.
"""

import logging
import logging.config
import re

from base64 import b64decode
from email import policy
from email.encoders import encode_noop
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
# from email.header import Header
from email.parser import Parser

from .constants import (ADDR, KEYDATA, AC_HEADER, AC_GOSSIP,
                        AC_GOSSIP_HEADER, PE_HEADER_TYPES, NOPREFERENCE,
                        AC_HEADER_PE, PE, AC)

logger = logging.getLogger(__name__)
parser = Parser(policy=policy.default)


__all__ = ['keydata_wrap', 'keydata_unwrap', 'gen_ac_header',
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
    return "; ".join(["=".join([k,v]) for k, v in header_dict.items()])


def header_unwrap(header, wrap_char="\n "):
    header_dict = parse_header(header)
    header_dict['keydata'] = keydata_unwrap(header_dict['keydata'], wrap_char)
    return gen_header_from_dict(header_dict)


def header_wrap(header, maxlen=76, indent=" "):
    header_dict = parse_header(header)
    header_dict['keydata'] = keydata_wrap(header_dict['keydata'], maxlen,
                                          indent)
    return gen_header_from_dict(header_dict)


def gen_ac_header(addr, keydata, pe=None):
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
    assert isinstance(keydata, str)
    assert pe in PE_HEADER_TYPES
    # keydata_wrapped = keydata_wrap(keydata)
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
    desc = MIMEApplication("Version: 1\n", _subtype='pgp-encrypted',
                           _encoder=encode_noop)
    desc["Content-Description"] = "PGP/MIME version identification"
    payload = MIMEApplication(mime_enc_body,
                              _subtype='octet-stream; name="encrypted.asc"',
                              _encoder=encode_noop)
    payload["Content-Description"] = "OpenPGP encrypted message"
    payload["Content-Disposition"] = 'inline; filename="encrypted.asc"'

    msg = MIMEMultipart(_subtype="encrypted", boundary=boundary,
                        _subparts=[desc, payload],
                        policy=policy.default,
                        protocol="application/pgp-encrypted")
    logger.debug('Generated encrypted multipart body.')
    return msg


def gen_headers_email(msg, sender, recipients, keydata, subject, pe,
                      keyhandle, date=None, _dto=False, message_id=None,
                      _extra=None):
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
    logger.debug('Generated headers.')
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
    msg = gen_headers_email(msg, sender, recipients, keydata, subject, pe,
                            keyhandle, date, _dto, message_id, _extra)
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
