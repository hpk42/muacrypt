# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Functions to test pgpymessage."""

from __future__ import unicode_literals
import logging

from autocrypt.conflog import LOGGING
from autocrypt.examples_data import (ALICE, BOB, RECIPIENTS, ALICE_KEYDATA,
                                     BOB_KEYDATA, BOB_GOSSIP, ALICE_AC,
                                     SUBJECT_GOSSIP, BODY_GOSSIP,
                                     BOB_KEYDATA_WRAPPED, CLEARTEXT_GOSSIP)

from autocrypt.constants import MUTUAL
from autocrypt.pgpymessage import (keydata_wrap, header_unwrap, gen_ac_header,
                                   parse_ac_gossip_email,
                                   gen_ac_gossip_header, gen_ac_gossip_headers,
                                   parse_ac_gossip_headers,
                                   gen_ac_gossip_cleartext_email,
                                   gen_ac_gossip_email, )

logging.config.dictConfig(LOGGING)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def test_keydata_wrap():
    keydata_wrapped = keydata_wrap(BOB_KEYDATA, indent='\n ')
    assert keydata_wrapped == BOB_KEYDATA_WRAPPED


def test_ac_header_wrap():
    pass


def test_gen_ac_header():
    h = gen_ac_header(ALICE, ALICE_KEYDATA, MUTUAL)
    assert h == header_unwrap(ALICE_AC)


def test_gen_ac_gossip_header():
    h = gen_ac_gossip_header(BOB, BOB_KEYDATA)
    assert h == header_unwrap(BOB_GOSSIP)


def test_parse_ac_gossip_header(pgpycrypto, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    gossip_list = parse_ac_gossip_headers(text)
    headers = gen_ac_gossip_headers(RECIPIENTS, pgpycrypto)
    assert headers == gossip_list


def test_gen_ac_gossip_cleartext_email(pgpycrypto, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    msg = gen_ac_gossip_cleartext_email(RECIPIENTS, BODY_GOSSIP, pgpycrypto)
    assert msg.as_string() == CLEARTEXT_GOSSIP


def test_gen_ac_gossip_email(pgpycrypto, datadir):
    msg = gen_ac_gossip_email(ALICE, RECIPIENTS, pgpycrypto,
                              SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                              '71DBC5657FDE65A7',
                              'Tue, 07 Nov 2017 14:56:25 +0100',
                              True,
                              '<gossip-example@autocrypt.example>',
                              'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')
    # NOTE: taking only first 25 lines as the encrypted blob is different
    # every time
    assert msg.as_string().split()[:25] == \
        datadir.read('example-gossip_pyac.eml').split()[:25]


def test_parse_ac_gossip_email(pgpycrypto, datadir):
    text = datadir.read('example-gossip_pyac.eml')
    msg, dec_msg, gossip = parse_ac_gossip_email(text, pgpycrypto)
    assert dec_msg.as_string() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()


def test_gen_parse_ac_gossip_email(pgpycrypto, datadir):
    msg = gen_ac_gossip_email(ALICE, RECIPIENTS, pgpycrypto,
                              SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                              '71DBC5657FDE65A7',
                              'Tue, 07 Nov 2017 14:56:25 +0100',
                              True,
                              '<gossip-example@autocrypt.example>',
                              'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')

    msg, dec_msg, gossip = parse_ac_gossip_email(msg.as_string(),
                                                 pgpycrypto)
    assert dec_msg.as_string() + '\n' == \
        datadir.read('example-gossip-cleartext_pyac.eml')
