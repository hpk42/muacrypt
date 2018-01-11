
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
      init               init muacrypt state.
      status             print account info and status.
      add-account        add an account to this account.
      mod-account        modify properties of an existing account.
      del-account        delete an account, its keys and all state.
      process-incoming   parse Autocrypt headers from stdin mail.
      process-outgoing   add Autocrypt header for outgoing mail.
      sendmail           as process-outgoing but submit to sendmail...
      test-email         test which account an email belongs to.
      make-header        print Autocrypt header for an emailadr.
      export-public-key  print public key of own or peer account.
      export-secret-key  print secret key of own account.
      bot-reply          reply to stdin mail as a bot.

For getting started we only need a few commands, first of all we will initialize
our Autocrypt account.  By default Autocrypt only creates and modifies files and state
in its own directory::

    $ muacrypt init
    account directory initialized: /tmp/home/.config/muacrypt
    account-dir: /tmp/home/.config/muacrypt
    account: u'default'
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/default]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   393C404CF381342D
      ^^ uid:           <c641519ea4894b6389fdad807beb1f92@random.muacrypt.org>
      ---- no peers registered -----


This created a default identity: a new secret key and a few settings.
If you rather like autocrypt to use your system keyring so that all incoming
keys are available there, see syskeyring_ but this will modify state on
your existing keyring.

Let's check out account info again with the ``status`` subcommand::

    $ muacrypt status
    account-dir: /tmp/home/.config/muacrypt
    account: u'default'
      email_regex:     .*
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/default]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   393C404CF381342D
      ^^ uid:           <c641519ea4894b6389fdad807beb1f92@random.muacrypt.org>
      ---- no peers registered -----


This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      mQENBFpXV2YBCADLgPVMJyLhR+49OEQnHoU40rlJPth6R6dMI+QQPrhSlyM9MeUTdVpL+Bl+HTF7eA
      lX9glii0fQJpWW0zEahtT2pMxLnJoexSlc23OLOaHqXjlpcljcz4FbOdx/kxU2qEcMUAcNuc28eSVm
      cnIiSG7DIyKxh7/ExM5tlCC8D52uWXnyRetkNryEyMag3CVmQAmz3wi03yGczFFG7Lh9eUaBuKH1iu
      dRoDnICdfF9565rfss8IppudOAGPHXlrDyStcz1P/Sx5XVjNWEQa3keGPtL+dD4B4Vhe2VfCaelZL/
      Vq1jQvCYQuls5nGmbJxoxWGv7HawlGHe4fn4yA7MYV5RABEBAAG0NyA8YzY0MTUxOWVhNDg5NGI2Mz
      g5ZmRhZDgwN2JlYjFmOTJAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwECACIFAlpXV2YCGwMGCwkI
      BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEDk8QEzzgTQt2HEIAK4pi2u4Rbni6x0LQaAT06a+pGDPe3
      taIyMmapa4GU43Jk2mKzbMzJtqh6kPS4fh9hoPqnopsRxBSTT+aMVcMSNFihDwbJwQ9GAbZL6O4C3M
      hdXAsQXq8l1R1WGKcaQHnknLKTUTMrzPg2yJ3UlUI0Pijt19Sy94F8+N23TjiG2Q9tDLDjsvGNAf5K
      66JPlTVF30OYhj+03cHApV4ysavCQuuQ+4gmCe9LsETr6S7qWqG6L0lYNMFWqQZ6/RmvRx8gWua+6Q
      pEBhhdo9cF5WiIOAPCd29Xhbq5eIZVXVIBo9dXdAH+rNaUodzs4qva+SlunjD/bKIlDDLi4YOwfIqN
      65AQ0EWldXZgEIALKRMzCY8XnBn2uMijo2FKKfmzl8J9t79pXVL//UnrJUT9DSbtY2pDIxWiDxg3CJ
      4yQkupBwLdPPExqSStAqrtyQ8sdpKO27pocwYUTaqB7Uf4o/LngkY6JhuivezmUA03+f9ymfwFtTfT
      y2naA5rXxWGpaaPVGcNjj5a/dXULBF2Iuhzdp3xoQ/4zL/B8oo9FS/YfU2Z56fUTgNC/jCtsWlneHJ
      OeV1iD1DILl64rVVxyk/+W6CbtEPxUtvbsfHadyqpeNcsyYvbSzyKFLTUakF2OPpsXn6g3SEamCSis
      o5EMjFqo2/EQETPQ6M84dsIpwzuVLy6HohJ8UeYCwL9/EAEQEAAYkBHwQYAQIACQUCWldXZgIbDAAK
      CRA5PEBM84E0LRMCB/9W/ZiOe7cKTGupm6VYVztZ2zaNoVA17vVuMq8CU8xF91l1HyO+EtHBO9ahbg
      l0UEVXzu2KqXL+7QiVI697NwAo/PMlNlJOSfUiLKTj5EjOhY9M/crk1y7b0S+9+mHjOrSW4MLzeNXG
      ZFx2AEnaMhoJ1iyi85jOKzxU4bXbnLHDWOnxI5TZBnyyIgrKhOznTrlHQ8F9BaIV+ji05O4sUtKnps
      LPeFG9Wnk58FUrTH0ZRsfjzRqjvcYe11B5MPsZK/2HlcOk9wbmHy6OaM+YS2RfRbz/CiYeg+JFivY5
      qkwyZMz8NeB+YuLcH/g8fsnCnEY4YZLfXpIbED0FPYnvvRLl

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    mQENBFpXV2YBCADLgPVMJyLhR+49OEQnHoU40rlJPth6R6dMI+QQPrhSlyM9MeUT
    dVpL+Bl+HTF7eAlX9glii0fQJpWW0zEahtT2pMxLnJoexSlc23OLOaHqXjlpcljc
    z4FbOdx/kxU2qEcMUAcNuc28eSVmcnIiSG7DIyKxh7/ExM5tlCC8D52uWXnyRetk
    NryEyMag3CVmQAmz3wi03yGczFFG7Lh9eUaBuKH1iudRoDnICdfF9565rfss8Ipp
    udOAGPHXlrDyStcz1P/Sx5XVjNWEQa3keGPtL+dD4B4Vhe2VfCaelZL/Vq1jQvCY
    Quls5nGmbJxoxWGv7HawlGHe4fn4yA7MYV5RABEBAAG0NyA8YzY0MTUxOWVhNDg5
    NGI2Mzg5ZmRhZDgwN2JlYjFmOTJAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwEC
    ACIFAlpXV2YCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEDk8QEzzgTQt
    2HEIAK4pi2u4Rbni6x0LQaAT06a+pGDPe3taIyMmapa4GU43Jk2mKzbMzJtqh6kP
    S4fh9hoPqnopsRxBSTT+aMVcMSNFihDwbJwQ9GAbZL6O4C3MhdXAsQXq8l1R1WGK
    caQHnknLKTUTMrzPg2yJ3UlUI0Pijt19Sy94F8+N23TjiG2Q9tDLDjsvGNAf5K66
    JPlTVF30OYhj+03cHApV4ysavCQuuQ+4gmCe9LsETr6S7qWqG6L0lYNMFWqQZ6/R
    mvRx8gWua+6QpEBhhdo9cF5WiIOAPCd29Xhbq5eIZVXVIBo9dXdAH+rNaUodzs4q
    va+SlunjD/bKIlDDLi4YOwfIqN65AQ0EWldXZgEIALKRMzCY8XnBn2uMijo2FKKf
    mzl8J9t79pXVL//UnrJUT9DSbtY2pDIxWiDxg3CJ4yQkupBwLdPPExqSStAqrtyQ
    8sdpKO27pocwYUTaqB7Uf4o/LngkY6JhuivezmUA03+f9ymfwFtTfTy2naA5rXxW
    GpaaPVGcNjj5a/dXULBF2Iuhzdp3xoQ/4zL/B8oo9FS/YfU2Z56fUTgNC/jCtsWl
    neHJOeV1iD1DILl64rVVxyk/+W6CbtEPxUtvbsfHadyqpeNcsyYvbSzyKFLTUakF
    2OPpsXn6g3SEamCSiso5EMjFqo2/EQETPQ6M84dsIpwzuVLy6HohJ8UeYCwL9/EA
    EQEAAYkBHwQYAQIACQUCWldXZgIbDAAKCRA5PEBM84E0LRMCB/9W/ZiOe7cKTGup
    m6VYVztZ2zaNoVA17vVuMq8CU8xF91l1HyO+EtHBO9ahbgl0UEVXzu2KqXL+7QiV
    I697NwAo/PMlNlJOSfUiLKTj5EjOhY9M/crk1y7b0S+9+mHjOrSW4MLzeNXGZFx2
    AEnaMhoJ1iyi85jOKzxU4bXbnLHDWOnxI5TZBnyyIgrKhOznTrlHQ8F9BaIV+ji0
    5O4sUtKnpsLPeFG9Wnk58FUrTH0ZRsfjzRqjvcYe11B5MPsZK/2HlcOk9wbmHy6O
    aM+YS2RfRbz/CiYeg+JFivY5qkwyZMz8NeB+YuLcH/g8fsnCnEY4YZLfXpIbED0F
    PYnvvRLl
    =baOj
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
    .+++++
    ...+++++
    ....+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key 8930A133 marked as ultimately trusted

We now have a key generated in the system key ring and
can initialize autocrypt using this key.  First, for our
playing purposes, we recreate the account directory and
make sure no default identity is generated::

    $ muacrypt init --no-account --replace
    deleting account directory: /tmp/home/.config/muacrypt
    account directory initialized: /tmp/home/.config/muacrypt
    account-dir: /tmp/home/.config/muacrypt
    no accounts configured

and then we add a default identity tied to the key we want to use from the system keyring::

    $ muacrypt add-account default --use-system-keyring --use-key test@autocrypt.org
    account added: 'default'
    account: u'default'
      email_regex:     .*
      gpgmode:         system
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   283388AA8930A133
      ^^ uid:           <test@autocrypt.org>
      ---- no peers registered -----

Success! We have an initialized autocrypt account with an identity
which keeps both our secret and the Autocrypt keys from incoming mails in
the system key ring. Note that we created a identity which matches
all mail address (``.*``) you might receive mail for or from which you might
send mail out.  If you rather use aliases or read different accounts
from the same folder you may want to look ingo identities_.


.. _identities:

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

- keeps its autocrypt state in a directory under the account directory.

- is defined by a name, a regular expression for matching mail addresses
  and an encryption private/public key pair and prefer-encrypt settings.

- updates Autocrypt peer state from incoming mails
  if its regex matches the ``Delivered-To`` address.

- adds Autocrypt headers to outgoing mails if its regex matches
  the "From" header.

In order to manage account in a fine grained manner you need
to delete the default identity or to re-initialize your Autocrypt
account::

    $ muacrypt init --no-account --replace
    deleting account directory: /tmp/home/.config/muacrypt
    account directory initialized: /tmp/home/.config/muacrypt
    account-dir: /tmp/home/.config/muacrypt
    no accounts configured

You can then add a "home" account::

    $ muacrypt add-account home --email-regex '(alice|wonder)@testsuite.autocrypt.org'
    account added: 'home'
    account: u'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   226C3BA0386BD352
      ^^ uid:           <5bba2196129a4efa83aa247e65aee998@random.muacrypt.org>
      ---- no peers registered -----

This creates an decryption/encryption key pair and ties it to the name
``home`` and a regular expression which matches both
``alice@testsuite.autocrypt.org`` and ``wonder@testsuite.autocrypt.org``.

And now let's create another identity::

    $ muacrypt add-account wonder --email-regex='alice@wunderland.example.org'
    account added: 'wonder'
    account: u'wonder'
      email_regex:     alice@wunderland.example.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/wonder]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   594AD32DA5286DF8
      ^^ uid:           <effeae17649b4b1282e73285be4126d9@random.muacrypt.org>
      ---- no peers registered -----

We have now configured our Autocrypt account with two identities.
Let's test if Autocrypt matches our ``wonder`` address correctly::

    $ muacrypt test-email alice@wunderland.example.org
    wonder

then one of our ``home`` ones::

    $ muacrypt test-email wonder@testsuite.autocrypt.org
    home

Looks good. Let's modify our ``home`` identity to signal to its peers
that it prefers receiving encrypted mails::

    $ muacrypt mod-account home --prefer-encrypt=mutual
    account modified: 'home'
    account: u'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  mutual
      own-keyhandle:   226C3BA0386BD352
      ^^ uid:           <5bba2196129a4efa83aa247e65aee998@random.muacrypt.org>
      ---- no peers registered -----

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; prefer-encrypt=mutual; keydata=
      mQENBFpXV2kBCACyUMe98nKWShAptfPg+IhNH2htwR84lNFy3nFnCwD0G0oqUSfyAoyaAsGxTnXM+i
      +t8WL3o1hk5IT5Iza0MkDH1c5J99STIcQWC+fkwBKHNhl19lpU/aMDA3075vN5l0cjxPtDn01vosPA
      Z5cOMqCvuF09erI9pG0uBwL2mVD9Wr4Cctnt8D4LRRIzrfett1TVu93rtAIxAuasTJAWLB+0j+L3MQ
      86uQgSc9FM7JNOFDd7W394m2Vq27guCpMw9jO6dZyqdssHr45fLW9mQK8OEuFbcLKU0kAkXxIdJzZN
      tABwyF3m3jY6ksQa7oKNA5PrQcB0JVHy8rXcoriNGiehABEBAAG0NyA8NWJiYTIxOTYxMjlhNGVmYT
      gzYWEyNDdlNjVhZWU5OThAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwECACIFAlpXV2kCGwMGCwkI
      BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJECJsO6A4a9NSnpEIAJdo3ah+2M/eAjzlosCEnJeLvBdGzn
      fl6WOPjpP5MndG5l/IQo4BSCEYlpS6I6WzpglA2ut7FiTfcwvnP6Cy0b4uTKDfYPBEDa83ogcyllFG
      xdzCvzhQTzwzX3i9Pc6OOOaIvLlr7owMySpXI+Fy5JcFUAI59oEpcGWFsMgzS5iaVE0Yd5RjQWtm/C
      Yl21t/5h+eBdz8XOjeiNAs9H4jbKYqxNdCoF5+z0X83hTnnUckPgaeTfJX5nK7NJJ2ruUuk2Y1XtMl
      pOwJStKhjEs2YcpVl3cDjvM+Ur+EBvxw/vdF7ppTkX0XzABDVUeEfQF487Ika8pM4hNOldz+9/und5
      a5AQ0EWldXaQEIAOCHrgB/AMvL9tY5w96/zw7+XiTNwQejx5ySIeU/52NwkBQ5rAc+Zy+H2xwyBL9L
      IZZ3yI6CKHQKkd5H4dVgsxeOQc7nQArHYuDqZKUyWas3VMWE0mT53fMbGCPmYiYfqSCAi1KD50Zu3p
      ts0oJzTvEmVEPnahDW/rDbq4uTZKT1lticR27KsiemFzbH3h317NaTGfv8E8/2RH8wftIlcS7Pca3s
      e3TOM0Bysj7cOkCcTNtj5OgllmY/pAb22O+wR6v97GLnVwQhu0tazf31IVgjmii1M+sS8sChYbpp2E
      l4V+Pdc5sqwWSB4G5uKmJoEmzKzV4ebRgcdENpiw3beh8AEQEAAYkBHwQYAQIACQUCWldXaQIbDAAK
      CRAibDugOGvTUo21B/9DFffXzROonKSmQlOU80fwmSqsqHef9YsTHWPeYnIMI0yF4UNaueFrVbQmZ8
      Kkp6P1E4RavrUQ/4uwtJ+haGER9DIw2zTJvh55eGmcwH9M85bIzsd4MLgmSsT3xL7mcRObxt2qzhhe
      dsY/IxtyaoZ6O/f+5nA4sKHvfAX3bJV8+IVI46U5yvSOASNGG36rrmX/Z5mORWtwPyjlXmo1R4poM7
      wHy/MycS6EEkogGCmsq50TdS5+R/Qlu+zVdbq7WmMxmZVZbJzkBA/duN4LNuEY+WKrhJYfdbrYfhJa
      7FGQgGD7eNtetEUFXpuRmiIvh+2dWZTP3kHoMj1ob/fOj2+D

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
piping the resulting mail to the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
