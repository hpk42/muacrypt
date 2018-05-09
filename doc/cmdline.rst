
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
      --basedir PATH  directory where muacrypt state is statesd
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
      export-public-key  print public key of own or peer account.
      export-secret-key  print secret key of own account.
      bot-reply          reply to stdin mail as a bot.
      destroy-all        destroy all muacrypt state.

For getting started we need to add a new Account::

    $ muacrypt add-account default
    account added: 'default'
    account: u'default'
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/default]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   7F11A102B709D0E2
      ^^ uid:           <b9720e2f438b48c9be6865899cc4ff82@random.muacrypt.org>
      ---- no peers registered -----

This created a default account which contains a new secret key and a few settings.

.. note::

    If you rather want muacrypt to use your system keyring so that all own
    and all incoming keys will be stored there, see syskeyring_.

Let's check out account info again with the ``status`` subcommand::

    $ muacrypt status
    account-dir: /tmp/home/.config/muacrypt
    account: u'default'
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/default]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   7F11A102B709D0E2
      ^^ uid:           <b9720e2f438b48c9be6865899cc4ff82@random.muacrypt.org>
      ---- no peers registered -----
    

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      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
      MGLAaueL40RjrDdTwnk3FMQXfjA/E=

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1
    
    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
    =GCYm
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
    .....+++++
    .......+++++
    +++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key 179645AB marked as ultimately trusted

We now have a key generated in the system key ring and
can initialize autocrypt using this key.  First, for our
playing purposes, we delete the current ``default`` account::

    $ muacrypt del-account default
    account deleted: u'default'
    account-dir: /tmp/home/.config/muacrypt
    no accounts configured

and then we add a new default account tied to the key we want to use from the system keyring::

    $ muacrypt add-account default --use-system-keyring --use-key test@autocrypt.org
    account added: 'default'
    account: u'default'
      email_regex:     .*
      gpgmode:         system
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   C4D9D25C179645AB
      ^^ uid:           <test@autocrypt.org>
      ---- no peers registered -----

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

    $ muacrypt add-account home --email-regex '(alice|wonder)@testsuite.autocrypt.org'
    account added: 'home'
    account: u'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   8FB95124DA7300F4
      ^^ uid:           <d4322ddd08b44615b9f5c6bdc3c61124@random.muacrypt.org>
      ---- no peers registered -----

This creates an decryption/encryption key pair and ties it to the name
``home`` and a regular expression which matches both
``alice@testsuite.autocrypt.org`` and ``wonder@testsuite.autocrypt.org``.

And now let's create an ``office`` account::

    $ muacrypt add-account office --email-regex='alice@office.example.org'
    account added: 'office'
    account: u'office'
      email_regex:     alice@office.example.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/office]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   2C240E5B11CDC79C
      ^^ uid:           <b8eca84a5af84863921c3e9a7a177b45@random.muacrypt.org>
      ---- no peers registered -----

We have now configured two accounts.  Let's test if muacrypt matches
our ``office`` address correctly::

    $ muacrypt test-email alice@office.example.org
    office

and let's check if muacrypt matches our ``home`` address as well::

    $ muacrypt test-email wonder@testsuite.autocrypt.org
    home

Looks good. Let's modify our ``home`` account to signal to our peers
that we prefer receiving encrypted mails::

    $ muacrypt mod-account home --prefer-encrypt=mutual
    account modified: 'home'
    account: u'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  mutual
      own-keyhandle:   8FB95124DA7300F4
      ^^ uid:           <d4322ddd08b44615b9f5c6bdc3c61124@random.muacrypt.org>
      ---- no peers registered -----

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; prefer-encrypt=mutual; keydata=
      mQGNBFrvJvYBDACXxxvna8khhi3iGwCaX52sh8H11k1EbR4ipol+qRYCAzMhUdH/QLqwXgTythApH/
      bMKTkw7DZbnGjH3sZyK2Vdu68yQKYtlg3DEE9N2NMihYuSWo7BaXalchtsqY10oTVn30QpVnG7jLvF
      NyjsG+H/zwjZcS7iWmG4J7CXtnisy4qNKKnw1XUo04CvNL9yhkZAwabeKFIYmHQkKjvwJhmdbXEzmq
      SwaJURm9u1jaCtylgi58jK34G21UqDtSZksQvjoArBLX8aKgRpZfkYLQGaoTSQ8agje5sPH93fi7wp
      7/dPC1/zPKPjKewkZFzRxZyzXm+ygVCi5jNlvU2TVh6CCvvI/hkoElTZgznTbm5TtfZ9QP+Z5YW48w
      xF9RvRwoOMIYUsQqscNJEt1Z9GimGjOQJmyGCAwI8JDkaF7QNni/IhHt/l8upDGPqJ8c4oiWBUgnYf
      tfp0sNQZcXg4ojnmuA3d9ULfZWXBuSPq4na2LLCNM9mmRKw0gteah35I7t8AEQEAAbQ3IDxkNDMyMm
      RkZDA4YjQ0NjE1YjlmNWM2YmRjM2M2MTEyNEByYW5kb20ubXVhY3J5cHQub3JnPokBuAQTAQIAIgUC
      Wu8m9gIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQj7lRJNpzAPTgggwAhyXk8SPh7QkEVf
      e3fBJTb+kJjZAcPo8odZvSGc7k0kFVIvrteS7rWvGjsV4Ifgwxx23qE7L/iUbWscLqby35WbfW6jbB
      wf4gE+6nwzOR0iAZmKgLKex7m+7pjRD3hEhoK9x8G8MPPbXF9L7X0z5ujqvJr3PGO1weje+bjmtTC2
      CExjXHcmclkCSwaW2BCkCWZkZgj/GuWn8SvfAEH9Yx91CjAool3cObLQ6rYwmJBG1r8znWXC9kmV8G
      ATqwSZZNE2Ru2z4HiCx1uLNFgj8iEqp30XPaazoD9+pSUF4HV6UwHQ6stFNlgNz1i1Ofspi/1tOavt
      FS86b0+mSDPPtpkp1lE/bKOj0Wf/vIK6wTdswMhfg3j2d5RNBIzouglnce/xPFB6tsB3CWfpRECWKR
      SPbUOwLwb20awFigEqpMh5dx0/T/pQx3SCjpdTw4fAjApirh0rAhOCtCA/pmRmv+vQlbdeqrKUguzS
      TTYndG62Z9zj+kr849S7siXKMq5io4uQGNBFrvJvYBDADSbQQL/n3lo3OE7RCynOjgCFfXNCF8RyjW
      oENBpd4NrhQYjwKd2upCHpzYEQ9nr7agjm1yUVPH4sBzZH6yAWBXb6spFfLYH3oEb6H1Xwtb8Lt/Ep
      8yJ0dFSfKDQdYNNyU2cqeSarJYucjFuaU2/xavxAmLUd/CRDNhqrKnQk/m33176El5khpaRkMhFXXH
      wB4cme9B7rNaGaZ/bjV2CVLrSC5ceCETIOtNAWlfQ1fyVYMvQQobbDSZeMwv/OWwSDV8PbQnsLyb1f
      T324g8gStGSqqOvX4eqfGK+9u2AsPTg4aTeMQ44pZfh/3/adZd2vd6Y7Uy9c0EC7RsAkEcnTRGWlTw
      +0uLk2nmWvdPblFM/KGUlzawc/0tgM1ssrdQDOu+F5BSnfCnPA6VF8IRezjSIg+H3nzF8vW7xxDWWr
      gdB6vXHI3rYHPeORm6g6Zvd17B+9h/3bHG98sqepXed9/J+0I1HxURqhMchu/46yEknP1EDbc/0FMp
      DtLz5eoWaTcAEQEAAYkBnwQYAQIACQUCWu8m9gIbDAAKCRCPuVEk2nMA9J1ZC/4ssuG4OK82qNyRYE
      avajfBte8SumT46EIpVlzfV1tOTYcGyomeKqYdg3+V0aqt/Nsn1tXFzct9Xkk1lXoPkuo4MMStTOJ0
      1j8BeJHWOrvD/3zDvXWtej55eXT4RnysXUgHPlo7Z4OrIW63OMkPDonqQoX8D5xOPhmDBXcj40aA3t
      s6AQUjQr8cFG/WZS+0tZC4EsygAJnTO8akUiBkZ2NcuBkFBQxgD2nMVYzJvhayY6vzzORC0V9bksfE
      KStEnpgYpFuoJCXuwDDGmOkqT8d2rODVEZ199J/chjko9fAJhUXEacLJxh6Uc8Yp7GtHGbylmTezdZ
      HmINqbRaDOi+mCrZBqMsk3WuaYXzOJBjs6+qIZSKLvR23tw8/o2gEzYCW31u31xqPlqjYHLEvMUGto
      zuzBYI//HAMXJDN9k7mFaHNNIvquVGzhIdh04IlBf+U3Z5yWqfXYJ9an4HobunycaqcHuYUiLK/I47
      OVWiEMeA2OgCiEqNda+DWjwfnlbSQ=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand then it will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
the resulting mail to be delivered via the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
