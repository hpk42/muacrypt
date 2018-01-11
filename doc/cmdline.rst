
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
      process-incoming   parse Autocrypt headers from stdin mail.
      process-outgoing   add Autocrypt header for outgoing mail.
      sendmail           as process-outgoing but submit to sendmail...
      test-email         test which account an email belongs to.
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
      own-keyhandle:   27ED178D3807DD22
      ^^ uid:           <bbb32634107c4e29aec3d920c62b91fc@random.muacrypt.org>
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
      own-keyhandle:   27ED178D3807DD22
      ^^ uid:           <bbb32634107c4e29aec3d920c62b91fc@random.muacrypt.org>
      ---- no peers registered -----
    

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      mQENBFpXYJUBCADEd/EWFAL3gUvJm59ndZP9udMb8/22UJbOvNMhFXtu1MGZPcl7+aGcM/kel3YVrJ
      Nva/UapZ68zLg7CJYviLo26HndoyjXr5e3Pev4CyNr2i4wAt3YPDTngDpJL4w8GY4TYUbtaBkteiix
      Ewb7r/8ynvNzFZDSAcuq7Iz7trbAezSCfb6hpPmsAFJz//cTnjJzlQQnvCIOjm1l2g1bmztnwqz8V5
      sWB/sUaF6hwsWcnex0801PGgE44OF4z/qj8DHd5a+FXk2fmVVKAjsz/YK8J4Q8Ca4Pmz/xIgz3mjM/
      JISk3z1nmjO6nJ/KHm8kr9oKkvNmGnIcVQBRUBAzhbQhABEBAAG0NyA8YmJiMzI2MzQxMDdjNGUyOW
      FlYzNkOTIwYzYyYjkxZmNAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwECACIFAlpXYJUCGwMGCwkI
      BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJECftF404B90i2FYH/iIj859i9jX+NtnF440t6H3ZcNybsB
      iLSNWVz6NY55x+Dh7a3EUXq9Ni0dF8rtkYMzAHNjKgKXlAhnvKNiTr3b1JDuQprLZI3Ws/C0/acSSa
      e+6flqtDpXQcdart3CU4C3m5rfrGoqE7ZaC/J37KpYQHa5eWfu/hUlZyb3qmMvf4HgJAEba3pCiJui
      WgS7g1kVt3zZucnEwRuWy3fKwXZoEmAJW9XAcrATLAOLfW48s0/IeQkJGo2ih6M+Q52U3zqBXHR8r5
      IiqnPX6cW5zs1nXaL5359F2r9zmRikQ58BT/mdZPmmjQuKqpkycVbibdr5J2n09keIA/VMk4Ab3w+p
      i5AQ0EWldglQEIAMA6od2SvrpzrAN0ZCJWjPmdegwz27QvQB9/nuL67KsFjkuOWk88g+9VbSCxu7i/
      3nZONctuGfIut6tnBRdDfhEt5wWKuNWy+MIq4JHaRJ9+cJks5+9ZJzDDQU2MRGUpzztGER1nXeCcY2
      9OfIhUjyO6EZ9cwZt3iP98W7laSlZRZ0yskZQ8AcMHJM5V31ZC9FTRdj0U2c2V7e3teur1mJGXQcuj
      tSfYmdHrV5sFafej8j1eAb94FwkuC30QQRrT6NNe9q5ch/y3AwxztKUOQ1fWukRvmaiKBge9tomarP
      +R+4R6+KKE7CCW/jM5Z+1w0+0nLE3woLt/27sAVg0t9nkAEQEAAYkBHwQYAQIACQUCWldglQIbDAAK
      CRAn7ReNOAfdIu6hCACtgecVFB0cUDVernKoaevDGJ0nvD01hDrC0ODDF8537JIPmAITG+6ad4Vu8L
      brX5vGHWrQO4bKXX3XJap/FZQbBMPJiCsxTTuws9q92qiDBoRpvu3hORbVh/AkP0rmypDvirQ+4zZu
      rZP5W2afvWV253jVfIPFOsL5n70R/Llh289m5Lj2Hi95GPxeDknJlCU5SexVeIwHHRUxC84Pml+Esl
      chuxyS3GlB/YO+h+LJhIT9YxOYN+PGio9qhHcQ/fj/HbliMLu7O7R/6E6pUrYxxVDdiG3b5SUVnbl/
      wyrYPY3L9gtY0hVdcYFkPQFdBdgYzwCqHIYMi6AZhSgWkaGg

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1
    
    mQENBFpXYJUBCADEd/EWFAL3gUvJm59ndZP9udMb8/22UJbOvNMhFXtu1MGZPcl7
    +aGcM/kel3YVrJNva/UapZ68zLg7CJYviLo26HndoyjXr5e3Pev4CyNr2i4wAt3Y
    PDTngDpJL4w8GY4TYUbtaBkteiixEwb7r/8ynvNzFZDSAcuq7Iz7trbAezSCfb6h
    pPmsAFJz//cTnjJzlQQnvCIOjm1l2g1bmztnwqz8V5sWB/sUaF6hwsWcnex0801P
    GgE44OF4z/qj8DHd5a+FXk2fmVVKAjsz/YK8J4Q8Ca4Pmz/xIgz3mjM/JISk3z1n
    mjO6nJ/KHm8kr9oKkvNmGnIcVQBRUBAzhbQhABEBAAG0NyA8YmJiMzI2MzQxMDdj
    NGUyOWFlYzNkOTIwYzYyYjkxZmNAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwEC
    ACIFAlpXYJUCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJECftF404B90i
    2FYH/iIj859i9jX+NtnF440t6H3ZcNybsBiLSNWVz6NY55x+Dh7a3EUXq9Ni0dF8
    rtkYMzAHNjKgKXlAhnvKNiTr3b1JDuQprLZI3Ws/C0/acSSae+6flqtDpXQcdart
    3CU4C3m5rfrGoqE7ZaC/J37KpYQHa5eWfu/hUlZyb3qmMvf4HgJAEba3pCiJuiWg
    S7g1kVt3zZucnEwRuWy3fKwXZoEmAJW9XAcrATLAOLfW48s0/IeQkJGo2ih6M+Q5
    2U3zqBXHR8r5IiqnPX6cW5zs1nXaL5359F2r9zmRikQ58BT/mdZPmmjQuKqpkycV
    bibdr5J2n09keIA/VMk4Ab3w+pi5AQ0EWldglQEIAMA6od2SvrpzrAN0ZCJWjPmd
    egwz27QvQB9/nuL67KsFjkuOWk88g+9VbSCxu7i/3nZONctuGfIut6tnBRdDfhEt
    5wWKuNWy+MIq4JHaRJ9+cJks5+9ZJzDDQU2MRGUpzztGER1nXeCcY29OfIhUjyO6
    EZ9cwZt3iP98W7laSlZRZ0yskZQ8AcMHJM5V31ZC9FTRdj0U2c2V7e3teur1mJGX
    QcujtSfYmdHrV5sFafej8j1eAb94FwkuC30QQRrT6NNe9q5ch/y3AwxztKUOQ1fW
    ukRvmaiKBge9tomarP+R+4R6+KKE7CCW/jM5Z+1w0+0nLE3woLt/27sAVg0t9nkA
    EQEAAYkBHwQYAQIACQUCWldglQIbDAAKCRAn7ReNOAfdIu6hCACtgecVFB0cUDVe
    rnKoaevDGJ0nvD01hDrC0ODDF8537JIPmAITG+6ad4Vu8LbrX5vGHWrQO4bKXX3X
    Jap/FZQbBMPJiCsxTTuws9q92qiDBoRpvu3hORbVh/AkP0rmypDvirQ+4zZurZP5
    W2afvWV253jVfIPFOsL5n70R/Llh289m5Lj2Hi95GPxeDknJlCU5SexVeIwHHRUx
    C84Pml+EslchuxyS3GlB/YO+h+LJhIT9YxOYN+PGio9qhHcQ/fj/HbliMLu7O7R/
    6E6pUrYxxVDdiG3b5SUVnbl/wyrYPY3L9gtY0hVdcYFkPQFdBdgYzwCqHIYMi6AZ
    hSgWkaGg
    =t8Lz
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
    ....+++++
    ............+++++
    +++++
    +++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key 51FE6564 marked as ultimately trusted

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
      own-keyhandle:   3EE866A051FE6564
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
    Usage: muacrypt [OPTIONS] COMMAND [ARGS]...
    
    Error: No such command "init".

You can then add a "home" account::

    $ muacrypt add-account home --email-regex '(alice|wonder)@testsuite.autocrypt.org'
    account added: 'home'
    account: u'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  nopreference
      own-keyhandle:   43D8DAA4DE83D083
      ^^ uid:           <78057a63f2224984b6df831617b53eb5@random.muacrypt.org>
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
      own-keyhandle:   29818A6AAC392131
      ^^ uid:           <089840f7995e4c9b8c7a47a0ed8441dd@random.muacrypt.org>
      ---- no peers registered -----

We have now configured two accounts.  Let's test if muacrypt matches
our ``wonder`` address correctly::

    $ muacrypt test-email alice@wunderland.example.org
    default

and let's check if muacrypt matches our ``home`` address as well::

    $ muacrypt test-email wonder@testsuite.autocrypt.org
    default

Looks good. Let's modify our ``home`` account to signal to our peers
that we prefer receiving encrypted mails::

    $ muacrypt mod-account home --prefer-encrypt=mutual
    account modified: 'home'
    account: u'home'
      email_regex:     (alice|wonder)@testsuite.autocrypt.org
      gpgmode:         own [home: /tmp/home/.config/muacrypt/gpg/home]
      gpgbin:          gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt:  mutual
      own-keyhandle:   43D8DAA4DE83D083
      ^^ uid:           <78057a63f2224984b6df831617b53eb5@random.muacrypt.org>
      ---- no peers registered -----

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; keydata=
      mQENBFpXYJcBCADAGMUK+DsAi0Hw/QmOQwpK+btSrWwyO/nD7oNxPpxeazDLsPQ7R7sUbZEPojdWky
      GjfAX2rjtDV47Qyl81ccE6uyyE7HhjPi7qSldKFO39/QAXqj2Fl56w0UmAzHhl/2PzeFCUjXGvpFTq
      KI8xG2e/aiLItgTeHCTnr37nJGdK28WO4rSm4izcKhHZUwz6vQeIad0ZzfzuDmP0yz8p3IstYy8H6N
      sfs0AHPHxFXWGEs2IvCiPtZVpH2u+NHOPeWijDB9yYWkH1zJ2Eqk77DtTC1o1jng9wNzcuDhTZu3LI
      uGBPHlOFxQZu8P/UMEhH7e3rM+xG2MfXsTtAi/V/WpZfABEBAAG0FSA8dGVzdEBhdXRvY3J5cHQub3
      JnPokBOAQTAQIAIgUCWldglwIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQPuhmoFH+ZWSv
      0gf/Xv4hLYvryLgKwsnGVzfyywdDgEy7v6S90ypDbT+NVg8Q/g4VCv1YsHd6r5Y6CEFlmeL12qNMKo
      fIAWn9Cr9TcHH0IrIduWard5i7f88QdDYbCjJdHdbw2p4Ll1cvZGq64I9XiKABO8Kgs66UjIxj/4vp
      DLqKxOEnqdcZaBjqJohg4xWsi51RCWU+LG17rmMM7cwaEc25/8Yy9wvClr47MR5juodI2r5CNsmFis
      WsHUMpgueSs5Wd6aZgn+hI+jAH2fCAmc0u9y7o6lZCiIwb6oLhAylkAv47NQP+WFY4f0MPJ/YYQvbZ
      l3WCF5dlVTHC/Rxnxd6nyU8pIb0Zvfr84LkBDQRaV2CXAQgAxUOQgPBtDyyjn5bvixiHVsKvJtGvYP
      4VU2+Mhx+r/kHtXbMO89xIFPrGKWYPdYx1GbKtZNSAftDIXPGFpUneTkXNgLqUh34wAmf1XjaOptPX
      Bz+4dqsKvZMbZXhqOx8hjFg+8u0oZHYRTQ4BVfV7oKUOnK2WQVmzmCKxI2Y9ylM2VgXWrRc9WZ1Il3
      KpysE//HDm6nDjhkxl3ojigRkF6kyiE11VlU2h5KxHOQ94npRjj5pX8GUiOtfpOzgm3P5XQGrxyaxJ
      TcuTqv7JuPUiXunpbhsTPnnFReFQ4tzDz16O448xN615X/cMPQo8axyb9IUw+xdDj5sfiL78TGjJ2Q
      ARAQABiQEfBBgBAgAJBQJaV2CXAhsMAAoJED7oZqBR/mVkGr4H/RddbqcZQ6RYFMEu/Ww9PmiSRz0e
      FbFyNEKjUoi+FDHDYOd1zFwcU32VulX3lK1hz2XaMjqd/7eZTvi50QE+bzclj4kkJ3t3IQ1MjKbx6L
      CNp1T7eVaauM72TachJq/OINdkrJfDK4HI4IVorwJcBcuaL4EyoElFQq7I0xyMzLm81OMxC6A6RsWj
      B7nBYUck0pUWof+hdwWGNOmlJBjTxA1XE2HooeZZR+6rRGXTGTnAvTzD5KrZXmeR9O3bQ6bBzkZd5p
      nv/5a3qHzw5+Glh8A9TAxCWcKi+etJTqThB1XxbKcvtf3tPN/Tv7nytZQslW5RZwoNTL9ZdECm+562
      rKw=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
piping the resulting mail to the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
