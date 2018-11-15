
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
      add-account        add a named account.
      mod-account        modify properties of an existing account.
      del-account        delete an account, its keys and all state.
      process-incoming   parse Autocrypt headers from stdin-read mime...
      process-outgoing   add Autocrypt header for outgoing mail if the...
      sendmail           as process-outgoing but submit to sendmail...
      test-email         test which account an email belongs to.
      recommend          print AC Level 1 recommendation for sending...
      make-header        print Autocrypt header for an emailadr.
      import-public-key  import public key data as an Autocrypt key.
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
      own-keyhandle:   3D53B13D13FDC548
      ^^ uid:           <3d4b41edc903471bb35c3a56e317414c@random.muacrypt.org>

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
      own-keyhandle:   3D53B13D13FDC548
      ^^ uid:           <3d4b41edc903471bb35c3a56e317414c@random.muacrypt.org>
    

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      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
      XLILdQjEMCO+Bz2Gr7ULnOx/rXzYs=

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1
    
    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
    =4lBF
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
    +++++
    +++++
    +++++
    .................+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key 02B86ADC marked as ultimately trusted

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
      own-keyhandle:   27253D5502B86ADC
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
      own-keyhandle:   CF446F02B1B74825
      ^^ uid:           <63ad32ec66cb4d8fa2a9723dd81ceb91@random.muacrypt.org>

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
      own-keyhandle:   81EC54BB603FDDB7
      ^^ uid:           <5f0406b1a2aa475487121c3fe736b608@random.muacrypt.org>

We have now configured two accounts.  Let's test if muacrypt matches
our ``office`` address correctly::

    $ muacrypt test-email alice@office.example.org
    office

and let's check if muacrypt matches our ``home`` address as well::

    $ muacrypt test-email wonder@testsuite.autocrypt.org
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
      own-keyhandle:   CF446F02B1B74825
      ^^ uid:           <63ad32ec66cb4d8fa2a9723dd81ceb91@random.muacrypt.org>

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; prefer-encrypt=mutual; keydata=
      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
      14LoauJrbHAZT7+msO4CJ2uZ6O3G0=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand then it will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
the resulting mail to be delivered via the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
