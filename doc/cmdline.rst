
Autocrypt command line docs
===========================

.. note::

    While the command line tool and its code is automatically tested
    against gpg, gpg2, python2 and python3, the sub commands are subject
    to change during the ``0.x`` releases.

The py-autocrypt command line tool helps to manage Autocrypt information
for incoming and outgoing mails.  It follows and implements the `Autocrypt
spec <autocryptspec>`_ and some additional means to make working with it
convenient.


.. contents::

getting started, playing around
-------------------------------

After :ref:`installation` let's see what sub commands we have::

    $ autocrypt
    Usage: autocrypt [OPTIONS] COMMAND [ARGS]...

      access and manage Autocrypt keys, options, headers.

    Options:
      --basedir PATH  directory where autocrypt account state is stored
      --version       Show the version and exit.
      -h, --help      Show this message and exit.

    Commands:
      init               init autocrypt account state.
      status             print account and identity info.
      add-identity       add an identity to this account.
      mod-identity       modify properties of an existing identity.
      del-identity       delete an identity, its keys and all state.
      process-incoming   parse autocrypt headers from stdin mail.
      process-outgoing   add autocrypt header for outgoing mail.
      sendmail           as process-outgoing but submit to sendmail...
      test-email         test which identity an email belongs to.
      make-header        print autocrypt header for an emailadr.
      export-public-key  print public key of own or peer account.
      export-secret-key  print secret key of own autocrypt account.
      bot-reply          reply to stdin mail as a bot.

For getting started we only need a few commands, first of all we will initialize
our Autocrypt account.  By default Autocrypt only creates and modifies files and state
in its own directory::

    $ autocrypt init
    account directory initialized: /tmp/home/.config/autocrypt
    account-dir: /tmp/home/.config/autocrypt

    identity: 'default' uuid 64ee038effa649f8a82c22e4d2ec15a4
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/autocrypt/id/default/gpghome]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   D67E0166618D4146
      ^^ uid:           <64ee038effa649f8a82c22e4d2ec15a4@uuid.autocrypt.org>
      ---- no peers registered -----

This created a default identity: a new secret key and a UUID and a few settings.
If you rather like autocrypt to use your system keyring so that all incoming
keys are available there, see syskeyring_ but this will modify state on
your existing keyring.

Let's check out account info again with the ``status`` subcommand::

    $ autocrypt status
    account-dir: /tmp/home/.config/autocrypt

    identity: 'default' uuid 64ee038effa649f8a82c22e4d2ec15a4
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/autocrypt/id/default/gpghome]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   D67E0166618D4146
      ^^ uid:           <64ee038effa649f8a82c22e4d2ec15a4@uuid.autocrypt.org>
      ---- no peers registered -----

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ autocrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      mQENBFlLz1UBCADM2iM+Nqm8YtHEJYPXBhACycBOalFJAqZzMYUA46xGTop/jBddwgRvNh+ClhQL7H
      xHE+bpfAE0Y1GBfw3PEI/rQGSyY7VhhH6nt7vTHCCYIRP64nfkK/PyRzGGT0AtS40fHc2DZ3kQxG7c
      9krprbmx5fPwudgYzXDY+da7PwNxu9lJyPAjHIfnEsEsxPvTpcChhUs5euifT2sIzJF82UAs0oXqoA
      Ak4G8JF2nZqCILQgkoKlAuEJhw1IjRkOQr19J5UkLKgucNQoOnjJ4HvPdmEt02uqzNXrmUMWl+4Ytb
      XjmaZ3dME6KiH1KbUdTPIhIIVREUnoywslTc+pt5jDEnABEBAAG0NiA8NjRlZTAzOGVmZmE2NDlmOG
      E4MmMyMmU0ZDJlYzE1YTRAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIAIgUCWUvPVQIbAwYLCQgH
      AwIGFQgCCQoLBBYCAwECHgECF4AACgkQ1n4BZmGNQUZlRQgAr4ZK+0hZ6v65AHu+lw5xa5fIMpSCn6
      anI59VetBur7PbZBIlW5z0jbWW13d+OsS0VW7Uuo07XXzWqc+rpsREpsBa+daWQdi7p/ahLiyd6mhN
      z8WdI+dod/NLmZuDEGllypjveHmbmRreaqIevf5rW6UHhNMReGU91+xHZcbhsqNDYBO/jiUK6EglRt
      zGJJuiJcE3+C/Kqu352OkJQdLDXngkmN2JQsosOmMqIrtPZtVsDHdhljMOOXumbH+G0nJoNNJX25Jv
      iTKdAgaYIcJI5ncEEGVZ6cffN1hPZeM++MvHgnuZ15aWq1cNUXGah27rn/u6pSyKqP0Zq/7RVde+/r
      kBDQRZS89VAQgA5m0ZWf8entimetIOwWj78FZxZldLcZnNKbPiM5sIztTcC2l3my0pfIzDxs9/PIj3
      EE/+u1xPMKWjmU0rh4KRqM1/V7TRbRNOCQhc68OQ3f0yQmeu/B971XHxcslfRm5iV14RFNxbDjyx5O
      IUDSjNy4QBfmMlp1RL81l03Bgv2kalSOPCradEV1eXCE1KSHFu89D6kDjZCZCyd4C+45+T8HdrNfF9
      txy2Lu9quqiiklJDQ3R08ct4WAxMdf5cP/rTdAjRS1ikNR9GwwsHDHnfjVTlz5nknsPl9bTtfIRmRR
      1ijUQaqONRMESYyY9Aq8f0kuhJOdD4y5CccaKBrxti9QARAQABiQEfBBgBAgAJBQJZS89VAhsMAAoJ
      ENZ+AWZhjUFGyfEH/AiFHmaU8XqDJFTkPJX2cfNf8QDPHYio7M++Z15w9y5bp9OU5Amrh8N0Lp+rgv
      262KqED/7FhvMCAljCIF9tk42y/b7jS1hg/qzXfN3wdEbwx1PVqmyZap4PEUXCL97JAjjY+J7D3Yd7
      LQMEN10GdehnWJzuACndx5q2pmkh8u2oHu3Y+XnRUXHm8LMCIrQFx3VTzH0BaWm9kwqVHeAqWpD1tO
      I0kKZx3MVaCcDI7N1JdBwNNqmgBdNhESGUwYd6nHb6tN9c3kGlNfxdNs1v0yXh8B1PwJsTBZPbkC3C
      lx2Sv8FtIICO+e/2pc0PtAtdFARraeeYWgowzzQKZLe/rWc=

Getting our own public encryption key in armored format::

    $ autocrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    mQENBFlLz1UBCADM2iM+Nqm8YtHEJYPXBhACycBOalFJAqZzMYUA46xGTop/jBdd
    wgRvNh+ClhQL7HxHE+bpfAE0Y1GBfw3PEI/rQGSyY7VhhH6nt7vTHCCYIRP64nfk
    K/PyRzGGT0AtS40fHc2DZ3kQxG7c9krprbmx5fPwudgYzXDY+da7PwNxu9lJyPAj
    HIfnEsEsxPvTpcChhUs5euifT2sIzJF82UAs0oXqoAAk4G8JF2nZqCILQgkoKlAu
    EJhw1IjRkOQr19J5UkLKgucNQoOnjJ4HvPdmEt02uqzNXrmUMWl+4YtbXjmaZ3dM
    E6KiH1KbUdTPIhIIVREUnoywslTc+pt5jDEnABEBAAG0NiA8NjRlZTAzOGVmZmE2
    NDlmOGE4MmMyMmU0ZDJlYzE1YTRAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIA
    IgUCWUvPVQIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ1n4BZmGNQUZl
    RQgAr4ZK+0hZ6v65AHu+lw5xa5fIMpSCn6anI59VetBur7PbZBIlW5z0jbWW13d+
    OsS0VW7Uuo07XXzWqc+rpsREpsBa+daWQdi7p/ahLiyd6mhNz8WdI+dod/NLmZuD
    EGllypjveHmbmRreaqIevf5rW6UHhNMReGU91+xHZcbhsqNDYBO/jiUK6EglRtzG
    JJuiJcE3+C/Kqu352OkJQdLDXngkmN2JQsosOmMqIrtPZtVsDHdhljMOOXumbH+G
    0nJoNNJX25JviTKdAgaYIcJI5ncEEGVZ6cffN1hPZeM++MvHgnuZ15aWq1cNUXGa
    h27rn/u6pSyKqP0Zq/7RVde+/rkBDQRZS89VAQgA5m0ZWf8entimetIOwWj78FZx
    ZldLcZnNKbPiM5sIztTcC2l3my0pfIzDxs9/PIj3EE/+u1xPMKWjmU0rh4KRqM1/
    V7TRbRNOCQhc68OQ3f0yQmeu/B971XHxcslfRm5iV14RFNxbDjyx5OIUDSjNy4QB
    fmMlp1RL81l03Bgv2kalSOPCradEV1eXCE1KSHFu89D6kDjZCZCyd4C+45+T8Hdr
    NfF9txy2Lu9quqiiklJDQ3R08ct4WAxMdf5cP/rTdAjRS1ikNR9GwwsHDHnfjVTl
    z5nknsPl9bTtfIRmRR1ijUQaqONRMESYyY9Aq8f0kuhJOdD4y5CccaKBrxti9QAR
    AQABiQEfBBgBAgAJBQJZS89VAhsMAAoJENZ+AWZhjUFGyfEH/AiFHmaU8XqDJFTk
    PJX2cfNf8QDPHYio7M++Z15w9y5bp9OU5Amrh8N0Lp+rgv262KqED/7FhvMCAljC
    IF9tk42y/b7jS1hg/qzXfN3wdEbwx1PVqmyZap4PEUXCL97JAjjY+J7D3Yd7LQME
    N10GdehnWJzuACndx5q2pmkh8u2oHu3Y+XnRUXHm8LMCIrQFx3VTzH0BaWm9kwqV
    HeAqWpD1tOI0kKZx3MVaCcDI7N1JdBwNNqmgBdNhESGUwYd6nHb6tN9c3kGlNfxd
    Ns1v0yXh8B1PwJsTBZPbkC3Clx2Sv8FtIICO+e/2pc0PtAtdFARraeeYWgowzzQK
    ZLe/rWc=
    =RDVW
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
    Key-Length: 2048
    Key-Usage: sign
    Subkey-Type: RSA
    Subkey-Length: 2048
    Subkey-Usage: encrypt
    Name-Email: test@autocrypt.org
    Expire-Date: 0

Let's run gpg to create this Autocrypt type 1 key::

    $ gpg --batch --gen-key autocrypt_key.spec
    gpg: keyring `/tmp/home/.gnupg/secring.gpg' created
    gpg: keyring `/tmp/home/.gnupg/pubring.gpg' created
    ..+++++
    ..........+++++
    ...+++++
    ...+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key 4415EEF7 marked as ultimately trusted

We now have a key generated in the system key ring and
can initialize autocrypt using this key.  First, for our
playing purposes, we recreate the account directory and
make sure no default identity is generated::

    $ autocrypt init --no-identity --replace
    deleting account directory: /tmp/home/.config/autocrypt
    account directory initialized: /tmp/home/.config/autocrypt
    account-dir: /tmp/home/.config/autocrypt
    no identities configured

and then we add a default identity tied to the key we want to use from the system keyring::

    $ autocrypt add-identity default --use-system-keyring --use-key test@autocrypt.org
    identity added: 'default'

    identity: 'default' uuid 969736e569dc442ab92597fd05e8373c
      email_regex:     .*
      gpgmode:         system
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   F81E1B474415EEF7
      ^^ uid:           <test@autocrypt.org>
      ---- no peers registered -----

Success! We have an initialized autocrypt account with an identity
which keeps both our secret and the Autocrypt keys from incoming mails in
the system key ring. Note that we created a identity which matches
all mail address (``.*``) you might receive mail for or from which you might
send mail out.  If you rather use aliases or read different accounts
from the same folder you may want to look ingo identities_.


.. _identities:

Using separate identities
-------------------------

You may want to create separate identities with your account:

- if you receive mails to alias email addresses in the same folder
  and want to keep them separate, unlinkable for people who read your mails

- if you read mails from multiple sources in the same folder
  and want to have Autocrypt help you manage identity separation
  instead of tweaking your Mail program's config to deal with different
  Autocrypt accounts.

With py-autocrypt you can manage identities in a fine-grained manner. Each identity:

- keeps its autocrypt state in a directory under the account directory.

- is defined by a name, a regular expression for matching mail addresses
  and an encryption private/public key pair and prefer-encrypt settings.

- stores Autocrypt header information from incoming mails
  if its regex matches the ``Delivered-To`` address.

- adds Autocrypt headers to outgoing mails if its regex matches
  the "From" header.

In order to manage identities in a fine grained manner you need
to delete the default identity or to re-initialize your Autocrypt
account::

    $ autocrypt init --no-identity --replace
    deleting account directory: /tmp/home/.config/autocrypt
    account directory initialized: /tmp/home/.config/autocrypt
    account-dir: /tmp/home/.config/autocrypt
    no identities configured

You can then add an example identity::

    $ autocrypt add-identity home --email-regex '(alice|wonder)@testsuite.autocrypt.org'
    identity added: 'home'

    identity: 'home' uuid 1d3bb960f1b347bda83dc3773211a791
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/autocrypt/id/home/gpghome]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   23117137B89DE0FB
      ^^ uid:           <1d3bb960f1b347bda83dc3773211a791@uuid.autocrypt.org>
      ---- no peers registered -----

This creates an decryption/encryption key pair and ties it to the name
``home`` and a regular expression which matches both
``alice@testsuite.autocrypt.org`` and ``wonder@testsuite.autocrypt.org``.

And now let's create another identity::

    $ autocrypt add-identity wonder --email-regex='alice@wunderland.example.org'
    identity added: 'wonder'

    identity: 'wonder' uuid abebb96743964765af8706f45a4cae76
      email_regex:     alice@wunderland.example.org
      gpgmode:         own [home: /tmp/home/.config/autocrypt/id/wonder/gpghome]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   20367F911DD2CA72
      ^^ uid:           <abebb96743964765af8706f45a4cae76@uuid.autocrypt.org>
      ---- no peers registered -----

We have now configured our Autocrypt account with two identities.
Let's test if Autocrypt matches our ``wonder`` address correctly::

    $ autocrypt test-email alice@wunderland.example.org
    wonder

then one of our ``home`` ones::

    $ autocrypt test-email wonder@testsuite.autocrypt.org
    home

Looks good. Let's modify our ``home`` identity to signal to its peers
that it prefers receiving encrypted mails::

    $ autocrypt mod-identity home --prefer-encrypt=mutual
    Usage: autocrypt mod-identity [OPTIONS] IDENTITY_NAME

    Error: Invalid value for "--prefer-encrypt": invalid choice: yes. (choose from nopreference, mutual)

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ autocrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; keydata=
      mQENBFlLz1kBCADd4K43W/x/im2sASRoURw9Pxa2uz+aiebGQnuz6+fOJMmcJl2MRIsQVh6vKpPuOh
      qE9JLGqgxbgv9oaC97RgY00JCeabXHAsE0OY9AXsyaGmur1BLp0kV4IE+sqHZWtqudT/F+7FDxdkMN
      +Zsv4Ek5w6iLBkNleD3XJB58pFJNelhOrUaJEgVcxwvblx05tXerC2nIgjSclirND8EfXGV499E+lF
      jcmmDMt+OvLSg5U/dB4u9k3seThlWItT+zqHjl+m1sSK0rKq7p+lfMkqFNIAlGVcU/TG+QbgfhfoLC
      r28M1+M36ydmDZMHmvf1wunKd02rF8deVc5Nl8PxBDCpABEBAAG0NiA8MWQzYmI5NjBmMWIzNDdiZG
      E4M2RjMzc3MzIxMWE3OTFAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIAIgUCWUvPWQIbAwYLCQgH
      AwIGFQgCCQoLBBYCAwECHgECF4AACgkQIxFxN7id4PuIUAf/aJEJQcBTnpwYkT57NjM74LUTGEmE8E
      lvclRpj+b/+SBbECMMyLbUgklk3do8K2mmWdei12tJtsBSXvFy1ZB0JWZ5PXSLcy8CAAJGtp2GShvC
      3z4x7WDfgMX/HJgMfexUIL8Q+kUwPuRVo5CU+Po0l3E/huSpmRoGEJMeZGAtI07F9OxffYBcEsKI4q
      fzug3ID9wDZQoX2zNZB/9998BhZI1d0e2/acnux7aedDsMxu3sAj/kVd8WRifPxW2//L+oqhP6/s+H
      8vo1jHIOUFyFMfNLzeU1+puyKmRMNM13tFjC9gCJ/pskieI1DMtMVA4LNdNF9fRGbEg1lSrg6zaZ5r
      kBDQRZS89ZAQgAtmeWmxdYh8O1kkgp/wJL/GGKKPHMxJnuXO+rFecW4j/S3u1dmU84Z5Iz1o31Py9b
      aOM2xv3ylbqTnLINNqf+2BjXbVRyTf3vuXIOxwbsMRcZmI+tOdc+CDIjceq5Hr7jWCTT9diBiMSCmE
      fSLyWykAZpBINbmgmXTk53wRsn6WoiU6CGGs1fOn5gcKQWgzHDPX7764XEOM9ShJgGMYLYfESyrJbK
      /c3f49mh2TN4u+6l27KHxCWt/bC+FcADYeS+b/YvVz0vNlmgx+0SCXDq0V9VA4tWPDhewDTK/E5itU
      iH2UUJg0WYZRT3yWwleQuKu+ctQnrOEYIUOeWwkEzicwARAQABiQEfBBgBAgAJBQJZS89ZAhsMAAoJ
      ECMRcTe4neD7e8IIAJQh5oNB0CkYnMn6uSBp2ePF9hId8SIIflSX6vHCbLt394VByb3VNeQgfZ3oRk
      1ZzPHAPnEw7OoV5momM5JoR8lset3vt5LJamUcNCuQsjgZwD5pfhrJO5qgfARaKskTtAX8/2oKDznI
      HDFFtAhAd45cegE4UL5fkNQzQat0z84jAiSk+F6cCdGpFPaLApMoQTOLmnGfk9KSIORu/7fsvw3m9f
      76m1/UKCwJRPGaIwIOgTaXfhzUM/pyXFp/JoHJchKaLBbbJimfwNvzUj3YkUm4O57qnHF07tXnojSN
      rCGPzrHYIP092Sm2w1V54VV3q0aVpF/P6UCna7SNWDzxiEg=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
piping the resulting mail to the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
