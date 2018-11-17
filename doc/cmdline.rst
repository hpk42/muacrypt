
muacrypt command line docs
===========================

.. note::

    While the command line tool and its code is automatically tested
    against gpg, gpg2, python2 and python3, the sub commands are subject
    to change during the ``0.x`` releases.

The ``muacrypt`` command line tool helps to manage Autocrypt information
for incoming and outgoing mails for one or more accounts.  It follows
and implements the `Autocrypt spec <autocryptspec>`_ which defines
header interpretation.


.. contents::

getting started, playing around
-------------------------------

After :ref:`installation` let's see what sub commands we have::

    $ muacrypt
    Usage: muacrypt [OPTIONS] COMMAND [ARGS]...
    
      access and manage Autocrypt keys, options, headers.
    
    Options:
      --basedir PATH  directory where muacrypt state is stored
      --version       Show the version and exit.
      -h, --help      Show this message and exit.
    
    Commands:
      status             print account info and status.
      add-account        add named account for set of e-mail...
      mod-account        modify properties of an existing account.
      del-account        delete an account, its keys and all state.
      find-account       print matching account for an e-mail address.
      process-incoming   parse Autocrypt info from stdin message if it...
      scandir-incoming   scan directory for new incoming messages and...
      import-public-key  import public key data as an Autocrypt key.
      peerstate          print current autocrypt state information...
      recommend          print Autocrypt UI recommendation for target...
      process-outgoing   add Autocrypt header for outgoing mail if the...
      sendmail           as process-outgoing but submit to sendmail...
      make-header        print Autocrypt header for an emailadr.
      export-public-key  print public key of own or peer account.
      export-secret-key  print secret key of own account.
      bot-reply          reply to stdin mail as a bot.
      destroy-all        destroy all muacrypt state.

For getting started we need to add a new Account::

    $ muacrypt add-account
    account added: 'default'
    account: 'default'
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/default]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   C40A50563C73AD76
      ^^ uid:           <6403c471d4d440cc83e568e6e4a245b7@random.muacrypt.org>

This created a default account which contains a new secret key and a few settings.

.. note::

    If you rather want muacrypt to use your system keyring so that all own
    and all incoming keys will be stored there, see syskeyring_.

Let's check out account info again with the ``status`` subcommand::

    $ muacrypt status
    account-dir: /tmp/home/.config/muacrypt
    account: 'default'
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/default]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   C40A50563C73AD76
      ^^ uid:           <6403c471d4d440cc83e568e6e4a245b7@random.muacrypt.org>
    

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      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
      vaqA8jX+X6sHJwL2UnDD2jGgSQq9Y=

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1
    
    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
    =RI6m
    -----END PGP PUBLIC KEY BLOCK-----
    

.. _syskeyring:

Using a key from the gpg keyring
---------------------------------------

If you want to use autocrypt with an existing mail setup you
can initialize by specifying an existing key in your system
gpg or gpg2 key ring.  To present a fully self-contained example
let's create a standard autocrypt key with gpg::

    # content of autocrypt_key.spec

    Key-Type: RSA
    Key-Length: 3072
    Key-Usage: sign
    Subkey-Type: RSA
    Subkey-Length: 3072
    Subkey-Usage: encrypt
    Name-Email: test@autocrypt.org
    Expire-Date: 0

Let's run gpg to create this Autocrypt type 1 key::

    $ gpg --batch --gen-key autocrypt_key.spec
    gpg: keyring `/tmp/home/.gnupg/secring.gpg' created
    gpg: keyring `/tmp/home/.gnupg/pubring.gpg' created
    ......+++++
    .....+++++
    .+++++
    .+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key 2436BADE marked as ultimately trusted

We now have a key generated in the system key ring and
can initialize autocrypt using this key.  First, for our
playing purposes, we delete the current ``default`` account::

    $ muacrypt del-account
    account deleted: 'default'
    account-dir: /tmp/home/.config/muacrypt
    no accounts configured

and then we add a new default account tied to the key we want to use from the system keyring::

    $ muacrypt add-account --use-system-keyring --use-key test@autocrypt.org
    account added: 'default'
    account: 'default'
      email_regex:     .*
      gpgmode:         system
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   DD1E25BE2436BADE
      ^^ uid:           <test@autocrypt.org>

Success! We have an initialized autocrypt account with an identity
which keeps both our secret and the Autocrypt keys from incoming mails in
the system key ring. Note that we created a identity which matches
all mail address (``.*``) you might receive mail for or from which you might
send mail out.  If you rather use aliases or read different accounts
from the same folder you may want to look ingo accounts_.


.. _accounts:

Using separate accounts
-----------------------

You may want to create separate accounts:

- if you receive mails to alias email addresses in the same folder
  and want to keep them separate, unlinkable for people who read your mails

- if you read mails from multiple sources in the same folder
  and want to have Autocrypt help you manage identity separation
  instead of tweaking your Mail program's config to deal with different
  Autocrypt accounts.

You can manage accounts in a fine-grained manner. Each account:

- is defined by a name, a regular expression for matching mail addresses
  and an encryption private/public key pair and prefer-encrypt settings.

- updates Autocrypt peer state from incoming mails
  if its regex matches the ``Delivered-To`` address.

- adds Autocrypt headers to outgoing mails if its regex matches
  the "From" header.

In order to manage an account in a fine grained manner let's
start from scratch and delete all ``muacrypt`` state::

    $ muacrypt destroy-all --yes
    deleting directory: /tmp/home/.config/muacrypt

Let's add a new "home" account::

    $ muacrypt add-account -a home --email-regex '(alice|wonder)@testsuite.autocrypt.org'
    account added: 'home'
    account: 'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   51581EF4DD1A3DC1
      ^^ uid:           <151aaad143584c91b29a8b4b3aaf3377@random.muacrypt.org>

This creates an decryption/encryption key pair and ties it to the name
``home`` and a regular expression which matches both
``alice@testsuite.autocrypt.org`` and ``wonder@testsuite.autocrypt.org``.

And now let's create an ``office`` account::

    $ muacrypt add-account -a office --email-regex='alice@office.example.org'
    account added: 'office'
    account: 'office'
      email_regex:     alice@office.example.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/office]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   054E04470D75CE6E
      ^^ uid:           <49fb9c1db86f4b7ea2c23a1fd5f03fbf@random.muacrypt.org>

We have now configured two accounts.  Let's test if muacrypt matches
our ``office`` address correctly::

    $ muacrypt find-account alice@office.example.org
    office

and let's check if muacrypt matches our ``home`` address as well::

    $ muacrypt find-account wonder@testsuite.autocrypt.org
    home

Looks good. Let's modify our ``home`` account to signal to our peers
that we prefer receiving encrypted mails::

    $ muacrypt mod-account -a home --prefer-encrypt=mutual
    account modified: 'home'
    account: 'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  mutual
      own-keyhandle:   51581EF4DD1A3DC1
      ^^ uid:           <151aaad143584c91b29a8b4b3aaf3377@random.muacrypt.org>

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; prefer-encrypt=mutual; keydata=
      mQGNBFvwXFoBDACulxiA0CAOqxTb0h+hME/hgrXd6jZnA/A8f55F2Qw+q8surWZb/tPqpKepOXI3S+
      V0V8zht/08AGcQNdAG3xR7W87GVyZpxF6vAvQAn96s8jNJ8KiG/UNrIwIJ6rAb9Anj5ouHFaq1Wbn1
      HF/1sqUQnbiw1rztOE2wgmc8ld5aG3WFsDVvf9eefQK0ryIC34Irh5/KsCCRTNPqkPQIVp5uBqJc3y
      KlHCArVoyEQLv3g4D1gNQzXF4VVtOMb6WYqR5dTdpqrfm8Karq+lv5jl4szynj9YUL8P7QHWJNr2Om
      AnVdix9Ju/G0pctlsntlO4k1t4TZM4M4WRg91PeiJN1IhghleCMh8A1VAFkP89uiWzIBucEyZedHY0
      2AnN3Q9hbBNphFzntetQg+Hby3R61cRE2tDAs0i1QzdV7EJEYAphvBcxYx1Dd3X2KxTljTaPUTbicj
      ChcNh8aMv49wVU+TfunGQKFLAxuoBsbKHrVdgpgDHM8txHaMjyPJiVoUyPEAEQEAAbQ3IDwxNTFhYW
      FkMTQzNTg0YzkxYjI5YThiNGIzYWFmMzM3N0ByYW5kb20ubXVhY3J5cHQub3JnPokBuAQTAQIAIgUC
      W/BcWgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQUVge9N0aPcEF4wv/TbgwfNbhbjNk6i
      ivbbDRAohW3XERUodvOuCwAj2PvxrDI6Rd5h7JpO6YebpciMw9I+K8iKig7OUwSyygbB2zZlNqotQX
      mroYG1tv9i54a6J14SXf6eW5glNOc7RgrDCWneK/yoSo0pLIrFGjpnc1RzRlNTAnaSlyKct1UbWCUp
      R4jj0CAL0xMKT///Q3VcLracsbogYOYI0V5Cf1ih6d4fjfd72zB7a1k2UvQifKut1ZQUPUtf8P2S6V
      Re8RbaZSp7OI5iknZqVjpV3bXPTauI1dLpAd+n2qoAzhbsFHX7hxYfUdHyALkU5r3xaixYA+bZojh6
      rpcLF0MjUTexWubuj32u3GShUOJA+2XetIRPz/Yqp0hTsDsMMUpMAYaIqtSXcCnzcFNK92Xy5ro80j
      ESBcWztz2iBvmLVj83VaEe56oupROtff9Cyh0QDELZ3trHs/s3x0cWSkbG2sQ5disgDjH4pOVR6wrt
      wGeYZDW/uAeM+gUknG29sC9WdknyGLuQGNBFvwXFoBDADZPQFBDP2qyPyoq1HhUK/oTjylDR05Slrf
      JE7VvQkKfejwQk52oolsCX82ixh6fuEA9sHmv++8IL/JpfHZuP0teYHSfgeWC41v9atyEj2ZF1soHn
      uDwxgvy7CGwHx9nw/zYBaigPGSd1Q1gAZz4XAU8tc37GLa7eRwQKkMh6YH5spUZid5qtPlRSJ/SU5s
      x/J2Q0/7kExLB90F2h+j//ataCQNLnLk2ypFbre9rJwXLgLwL8Bcgt0y5oEMgBqFG57iwj9iZberYK
      DX/qx5Xm92A/JszUNJOSDODOrkThILhcizlxFtEnaTK1A3mL5dQlKaoO9kHbUiCSzihTVJgkFrbi+E
      /otooTIDDeqFLx+mRsPEFyRP4r5GiqkUJnduxJsC5W78XtphlEyX71avZQfgK/MFL1i4v3i8geFtBA
      hrlNdqTJH6o/3OuBxt6wfKV6BIWmdHxL+doRkj4TLlDJ8h9rVJILoIxsjNrkMvI28kPw4euXcWA+XJ
      C6lTyCzWNBEAEQEAAYkBnwQYAQIACQUCW/BcWgIbDAAKCRBRWB703Ro9wbXgDACWxBRljSpPH36C1F
      J+K0IGRn1x0ZTw3rAacSKa0hf0goaOl9/pXAwc1LUOW9c9Mwxcv5HYHTi8E3ENQEqakQIsAnsPoRne
      ubgQP8oLGzQJqQ5Y1iC3YRSAYwvhBxLXgWRp429llzEOVw+beXpzrreQ6Wxag6IdOAT/PDQkARnQ8u
      qN59X62WxH2dAM/vQMO8IiXp5FbAZWVtYU6aDLtgrJAFxbifiUEqnaSAcr4otZ3oUEVzmY7oPsAUkr
      cRAM7fEX3sxckeL20K+Q9ddLFPG/Uazwz0ZhNb8o8GcwsmK766QQOx/BL/7R20lD2D9uDdBCF8jQM2
      oSET5uSsd0Fu7JQT5QigAlQ6s6ntTYhkk6N7+gMm2XIsKYN7sJfANv2QVwt2+dT35I/wjCumA6PQTn
      H7MY7QNR6BGRwUOn4uHmEbSzdV+ZS4yLcda2V09uKoy0y/osDLacYhmygzH8Vo/FcGVZsycyMHjOTE
      3q7l0UHBVGfAwx+uT1W8vkOafaFKg=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand then it will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
the resulting mail to be delivered via the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
