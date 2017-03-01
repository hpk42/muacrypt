
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

For getting started we only need a few commands, first of all we will initialize
our Autocrypt account.  By default Autocrypt only creates and modifies files and state
in its own directory::

    $ autocrypt init
    account directory initialized: /tmp/home/.config/autocrypt
    account-dir: /tmp/home/.config/autocrypt

    identity: 'default' uuid 52cf820841e24b3e897553798bd1e4d4
      email_regex: .*
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/default/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: D9B9AFCB3D87687D
               -uid:  <52cf820841e24b3e897553798bd1e4d4@uuid.autocrypt.org>
      ---- no peers registered -----

This created a default identity: a new secret key and a UUID and a few settings.
If you rather like autocrypt to use your system keyring so that all incoming
keys are available there, see syskeyring_ but this will modify state on
your existing keyring.

Let's check out account info again with the ``status`` subcommand::

    $ autocrypt status
    account-dir: /tmp/home/.config/autocrypt

    identity: 'default' uuid 52cf820841e24b3e897553798bd1e4d4
      email_regex: .*
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/default/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: D9B9AFCB3D87687D
               -uid:  <52cf820841e24b3e897553798bd1e4d4@uuid.autocrypt.org>
      ---- no peers registered -----

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ autocrypt make-header a@example.org
    Autocrypt: to=a@example.org; key=
      mQENBFi2mC4BCADIL61Q2DWF90hr0rONzDSCBG9ZCe8S94EaLOUMou2AI0NU3uqc41N/fab9onwCuL
      GK56+O4IbrLDBjUxiWK9C75PqvE05ETo2kXQ2AllLfXJYisqFZKX2+kXW5NhNH3z2CI2zMc1JbVb3n
      XXPlzbxOd8BXGmMSAjy9+o/bw7ZZap/Y71WvXNAQKusoUeZ1LwtZEkrt9B7zXNEAo8u9TGfphfw7wU
      5h9CzIKPoyjV2zxaaPE5vs9+VCgmwih13kiMMXOW/xK3HjtnX4lCX/vkEORti+mjBNZuZ+ru4V/6jU
      /dCQBqpKWZhQP90RpKXrPQ6w7GNy69TSfaK7r0Iv3vDnABEBAAG0NiA8NTJjZjgyMDg0MWUyNGIzZT
      g5NzU1Mzc5OGJkMWU0ZDRAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIAIgUCWLaYLgIbAwYLCQgH
      AwIGFQgCCQoLBBYCAwECHgECF4AACgkQ2bmvyz2HaH3+EQgArH6IPGCJeLKxCzWh69oRHGtquiUUbP
      VhGKVY+QiPFNEG8Kc6AInI7HDbkzCX4L/0pLJ8Ef2gd2kBqfMUxyyJSo1i5v+JmVjtaVfl90soqHZL
      ixCdaQVywwm7ahohKFsICRY0sBWG8lxL/wIMuqPrEMEffoK0eWhhE104Yef0YhZJLRUilyNfA8UzIs
      bwom4T0eH1Kou+jt3P/314ATxPyafEIGxnlXYPArCNpCHAZ0BczxvPpUxcHjyDAdPWDcgpDl/J8eg0
      wYuI279Yl0SAK4+dQQPFy+40jHyHn4FZKOINgwUipYTRLfQFCinkg1UBVdM9SgfVVH6d6jxGypdwVr
      kBDQRYtpguAQgAw0+PaMygm2lPYqquzpinWUFDzLAGC2cbxrwTNlpLf9aWck4IEtXgEGVVwOx3zkN1
      wqUcUmSeWSzRrSWzoyk/mEAOi6qczecH0nfBqCjoh0kSfaHecTRI9nvNfwqZzi3W08nvdlTV6lhoZi
      7voCwRoHC5mw7JjSCsvTj5uoLdSEeH5U9bJ28c1VLmzmkPdYluCRQee72DQMKrwcM73ElWNywzlXSU
      0Mtbk3ZiSpFP1m+opUUc3Tbh8Yj4mPFVpxoWq9NS7W5pSpG2vTv7iIT/M98yuPR5Zfvxx22VKacq8N
      aetJtlYBSH6QUPi4XSVncnZfrMVtnHfqT+BhjcY2MPaQARAQABiQEfBBgBAgAJBQJYtpguAhsMAAoJ
      ENm5r8s9h2h9ULsH/18t5tTEG5GTecqL8h7onTdhLn52GiZVQBnnVNzedK1l1h3ccoF4V0/NaNTD/2
      GjoliQJekFp5dS/8DJDJDys/pjLyhzX027N45gsbfxOkjAtHWow146z6riqQUu9XgdYf7MMa0ufMDh
      ekNkl0qGIn1FAtGGLvnAGUX/elpvNHVU21wWk6lAkBsD6GbYnUkYfMw6I+mTbWUnnIJazdNMbFSajs
      3DPNZweQ2LJwpffA28VsWBm+qq9i0frY/1xmnQkU9xeGJbnngeT+J/aB29abpzWdQ3QRTqnm0eLpvq
      LaeApbjQtiJyQfgkz+8J3w6HBoT1BBXQH4qTPI0uGcpYigk=

Getting our own public encryption key in armored format::

    $ autocrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    mQENBFi2mC4BCADIL61Q2DWF90hr0rONzDSCBG9ZCe8S94EaLOUMou2AI0NU3uqc
    41N/fab9onwCuLGK56+O4IbrLDBjUxiWK9C75PqvE05ETo2kXQ2AllLfXJYisqFZ
    KX2+kXW5NhNH3z2CI2zMc1JbVb3nXXPlzbxOd8BXGmMSAjy9+o/bw7ZZap/Y71Wv
    XNAQKusoUeZ1LwtZEkrt9B7zXNEAo8u9TGfphfw7wU5h9CzIKPoyjV2zxaaPE5vs
    9+VCgmwih13kiMMXOW/xK3HjtnX4lCX/vkEORti+mjBNZuZ+ru4V/6jU/dCQBqpK
    WZhQP90RpKXrPQ6w7GNy69TSfaK7r0Iv3vDnABEBAAG0NiA8NTJjZjgyMDg0MWUy
    NGIzZTg5NzU1Mzc5OGJkMWU0ZDRAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIA
    IgUCWLaYLgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ2bmvyz2HaH3+
    EQgArH6IPGCJeLKxCzWh69oRHGtquiUUbPVhGKVY+QiPFNEG8Kc6AInI7HDbkzCX
    4L/0pLJ8Ef2gd2kBqfMUxyyJSo1i5v+JmVjtaVfl90soqHZLixCdaQVywwm7ahoh
    KFsICRY0sBWG8lxL/wIMuqPrEMEffoK0eWhhE104Yef0YhZJLRUilyNfA8UzIsbw
    om4T0eH1Kou+jt3P/314ATxPyafEIGxnlXYPArCNpCHAZ0BczxvPpUxcHjyDAdPW
    DcgpDl/J8eg0wYuI279Yl0SAK4+dQQPFy+40jHyHn4FZKOINgwUipYTRLfQFCink
    g1UBVdM9SgfVVH6d6jxGypdwVrkBDQRYtpguAQgAw0+PaMygm2lPYqquzpinWUFD
    zLAGC2cbxrwTNlpLf9aWck4IEtXgEGVVwOx3zkN1wqUcUmSeWSzRrSWzoyk/mEAO
    i6qczecH0nfBqCjoh0kSfaHecTRI9nvNfwqZzi3W08nvdlTV6lhoZi7voCwRoHC5
    mw7JjSCsvTj5uoLdSEeH5U9bJ28c1VLmzmkPdYluCRQee72DQMKrwcM73ElWNywz
    lXSU0Mtbk3ZiSpFP1m+opUUc3Tbh8Yj4mPFVpxoWq9NS7W5pSpG2vTv7iIT/M98y
    uPR5Zfvxx22VKacq8NaetJtlYBSH6QUPi4XSVncnZfrMVtnHfqT+BhjcY2MPaQAR
    AQABiQEfBBgBAgAJBQJYtpguAhsMAAoJENm5r8s9h2h9ULsH/18t5tTEG5GTecqL
    8h7onTdhLn52GiZVQBnnVNzedK1l1h3ccoF4V0/NaNTD/2GjoliQJekFp5dS/8DJ
    DJDys/pjLyhzX027N45gsbfxOkjAtHWow146z6riqQUu9XgdYf7MMa0ufMDhekNk
    l0qGIn1FAtGGLvnAGUX/elpvNHVU21wWk6lAkBsD6GbYnUkYfMw6I+mTbWUnnIJa
    zdNMbFSajs3DPNZweQ2LJwpffA28VsWBm+qq9i0frY/1xmnQkU9xeGJbnngeT+J/
    aB29abpzWdQ3QRTqnm0eLpvqLaeApbjQtiJyQfgkz+8J3w6HBoT1BBXQH4qTPI0u
    GcpYigk=
    =VSpT
    -----END PGP PUBLIC KEY BLOCK-----


.. _syskeyring:

initializing with using system key ring
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

Let's run gpg to create the key which happens to be a standard ``type=p``
Autocrypt key::

    $ gpg --batch --gen-key autocrypt_key.spec
    gpg: keyring `/tmp/home/.gnupg/secring.gpg' created
    gpg: keyring `/tmp/home/.gnupg/pubring.gpg' created
    ...+++++
    .+++++
    +++++
    ....+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key C15420C5 marked as ultimately trusted

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

    $ autocrypt add-identity default --use-system-keyring --use-existing-key test@autocrypt.org
    identity added: 'default'

    identity: 'default' uuid cdba346dbf0f4c39bfc24f5ceaab1cdf
      email_regex: .*
      gpgmode: system
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 5751FFB5C15420C5
               -uid:  <test@autocrypt.org>
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

    identity: 'home' uuid 4bf3623301154e288663eeff90b3f391
      email_regex: (alice|wonder)@testsuite.autocrypt.org
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/home/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 1F55238A33CFFF40
               -uid:  <4bf3623301154e288663eeff90b3f391@uuid.autocrypt.org>
      ---- no peers registered -----

This creates an decryption/encryption key pair and ties it to the name
``home`` and a regular expression which matches both
``alice@testsuite.autocrypt.org`` and ``wonder@testsuite.autocrypt.org``.

And now let's create another identity::

    $ autocrypt add-identity wonder --email-regex='alice@wunderland.example.org'
    identity added: 'wonder'

    identity: 'wonder' uuid a1e07d522074452eb32b45e28e70ccab
      email_regex: alice@wunderland.example.org
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/wonder/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 01819DD83EA09A45
               -uid:  <a1e07d522074452eb32b45e28e70ccab@uuid.autocrypt.org>
      ---- no peers registered -----

We have now configured our Autocrypt account with two identities.
Let's test if Autocrypt matches email addresses correctly::

    $ autocrypt test-email alice@wunderland.example.org
    wonder
    $ autocrypt test-email wonder@testsuite.autocrypt.org
    home

Looks good. Let's modify our ``home`` identity to signal to its peers
that it prefers receiving encrypted mails::

    $ autocrypt mod-identity home --prefer-encrypt=yes
    identity modified: 'home'

    identity: 'home' uuid 4bf3623301154e288663eeff90b3f391
      email_regex: (alice|wonder)@testsuite.autocrypt.org
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/home/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: yes
      own-keyhandle: 1F55238A33CFFF40
               -uid:  <4bf3623301154e288663eeff90b3f391@uuid.autocrypt.org>
      ---- no peers registered -----

This new ``prefer-encrypt: yes`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if possible.  We can check this with the
`make-header`_ subcommand::

    $ autocrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: to=wonder@testsuite.autocrypt.org; prefer-encrypt=yes; key=
      mQENBFi2mDEBCACu1g3KqY+smTrOKOp60wjKgUZq83LajFIn5IeM/ktpZQmpnPIzcDGewzBOZsquiY
      q4Knv3o6RrOd0SY9XAqLmWA6ZVet+FYbkczNE97pPzpwcb4xlSwefhMOa1TQr5GJ2uU3/CV5wGD60z
      L/C04KtlVCUXB4VAlBK9ZCE3TKWew6xc5eKzdIKxks/NekauqEBcJXUGU4ANBm4MpL7CwZPHevzXcW
      AtFxCCFVpsLB0gauRmCLxMa9gFXZeg2lUX+0ig8uGNlPGwJJbLYjdkzuBDFwCcEU6bPk9BiZdhAYLh
      Lep5qQ0Y9/MjeVIuIbv+Rs1i82w2TG5M5Rrr+C2eeVyLABEBAAG0NiA8NGJmMzYyMzMwMTE1NGUyOD
      g2NjNlZWZmOTBiM2YzOTFAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIAIgUCWLaYMQIbAwYLCQgH
      AwIGFQgCCQoLBBYCAwECHgECF4AACgkQH1UjijPP/0CHKwf9FuGJGgwdhv5+bkMrx22SyAszxtsWPe
      EQx+/yaKk5MOfPhpUtAkepntz5+ojGcnMs31QSI4QaALC57LDYR4L2bev14rBAupym4491XfReNOK2
      7mk+ppIXq8fzeqg87LDaZDvZEdaGwktefCg5LInPCw2dp7UZgGJBy20e5d9VDyycuNWiukCFIH6tLR
      EsYRxbelL+hdmPLoLPFXj6T5ra8o7ynmMAU+PJtE15Fr4lVeNHOTbaWSzAobvEGQ+n9g3D8L/mCwb1
      1/yeekgbF4vwo4n5BTr4vrIBGz38acnflu3at5WOR3BxN7YAJzMnVvjpQPZv3i0vVOfitefCm6PSOr
      kBDQRYtpgxAQgAuEzajCk4WIb5Ot/NdNljqSAKaU7X+ZnvF5SDvwtVQzWtcaj+glBMM7BMVvILFw3e
      7+8IYKfbSRVrQogWr/H7reIRy3cNO8thjuzftFau3C5YOKwwMckUmO0TwxkTlcZwHz1ZbKgExnicI/
      4Butg+P5Xg8xDhdwhx3jB/SZju0is8RhQkithjWSCZsQouXkXDoQQu/4mAPmHS6OkAglRpPqLIYX7v
      H0qwB5NCc8Ox3GOi8wL2DLIg33gkSGi+GnBs/8XSz7g6yigU4XOmPaE0dbPL5BqdN5fLP3+qf9DyGm
      +AsPD75Fr8LiQT6DWWwZl0ox/Qp+Mqab1LX6w/CtkukwARAQABiQEfBBgBAgAJBQJYtpgxAhsMAAoJ
      EB9VI4ozz/9APWYIAJsYr4rfc22jwoYevU6T9/0j4XtxIaKkMo8OTbjgoR98uGN47tCC48jljJfsMg
      fszqyUNvpNcsm1m8ZYhsPADsLQWEROGXVo5/QHPhVPDF9VfIpW8DmENL1ATxCSBGHyWMLBUY76fUL/
      xOfPJymIX1ERKCmve2WKU/2UBhXP0lrPafJT5HCUgYyH3+SgGIMT3qRrfcB4j68fB8D0xZLCbVdKXa
      gLtNIlGL4bRxupk+0LlCIXHXa2Gzg/pbVYOKYkBNMwGomWulVUNFqr5NLU2kXh5KRlNE8s/wFpdMIn
      i0uC1Gwt+Jom2HZXVJ2zpd+3C8JtHlZfgTnbvSEwsxPQLjA=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
piping the resulting mail to the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
