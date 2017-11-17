#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Example script to generate and parse encrypted Email following
 Autcrypt technical specifications.
 """

import argparse
import logging
import logging.config
import os.path

from .conflog import LOGGING
from .constants import BASE_DIR, MUTUAL
from .examples_data import BODY_GOSSIP, SUBJECT_GOSSIP
from .pgpycrypto import PGPyCrypto
from .pgpymessage import (gen_ac_email, gen_ac_gossip_email, parse_ac_email,
                          parse_ac_gossip_email)

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        help='Set logging level to debug',
                        action='store_true')
    parser.add_argument('-f', '--sender',
                        help='Email sender address and OpenPGP UID',
                        default='alice@autocrypt.example')
    parser.add_argument('-t', '--recipient',
                        help='Email recipient address',
                        default='bob@autocrypt.example')
    parser.add_argument('-g', '--gen',
                        help='Generate a OpenPGP key pair',
                        action='store_true')
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    logger.debug('args %s', args)

    if args.gen is True:
        keyhandle = p.gen_secret_key(emailadr=args.sender)
        # TODO: use this key
    else:
        pass

    p = PGPyCrypto(os.path.join(BASE_DIR, 'tests', 'data', 'pgphome'))

    msg = gen_ac_email(args.sender, [args.recipient], p,
                       subject='test', body='test body')
    msg, dec = parse_ac_email(msg.as_string(), p)
    recipients = [args.recipient, 'carol@autocrypt.example']
    msg = gen_ac_gossip_email(args.sender, recipients, p,
                              SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                              '71DBC5657FDE65A7',
                              'Tue, 07 Nov 2017 14:56:25 +0100',
                              True,
                              '<gossip-example@autocrypt.example>',
                              'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')
    logger.info(msg.as_string())
    msg, dec, gossip_list = parse_ac_gossip_email(msg.as_string(), p)
    logger.info('Msg: %s', msg.items())
    logger.info('Encrypted part: %s', dec)
    logger.info('List gossip keys %s', gossip_list)


if __name__ == '__main__':
    main()
