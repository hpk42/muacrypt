
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
      find-account       print matching account for an e-mail address.
      process-incoming   parse Autocrypt headers from stdin-read mime...
      process-outgoing   add Autocrypt header for outgoing mail if the...
      sendmail           as process-outgoing but submit to sendmail...
      peerstate          print current autocrypt state information...
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
      own-keyhandle:   01A32BDA8EA38132
      ^^ uid:           <6e12e7e42e2343f799c26ed8a47f8d39@random.muacrypt.org>

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
      own-keyhandle:   01A32BDA8EA38132
      ^^ uid:           <6e12e7e42e2343f799c26ed8a47f8d39@random.muacrypt.org>


This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      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
      TM/xQtCU0f24xBEAK6WDKQ/EcJbj8=

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    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
    =TXX6
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
    .+++++
    .........................+++++
    .....+++++
    .+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key CAFB2F3F marked as ultimately trusted

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
      own-keyhandle:   004A8CF1CAFB2F3F
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
      own-keyhandle:   954B47B609BE3EA4
      ^^ uid:           <85c3d293297b4cfb953177fb84bfc9f4@random.muacrypt.org>

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
      own-keyhandle:   6B339AC6D92E0052
      ^^ uid:           <fbbce8c869f34f7d90a27a5989f1e26a@random.muacrypt.org>

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
      own-keyhandle:   954B47B609BE3EA4
      ^^ uid:           <85c3d293297b4cfb953177fb84bfc9f4@random.muacrypt.org>

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; prefer-encrypt=mutual; keydata=
      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
      TmRlCYwKiKFcboIguiM5YACR+KlVw=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand then it will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
the resulting mail to be delivered via the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
