
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

    identity: 'default' uuid 36638a7257a04605aeec21ae0469f3f5
      email_regex: .*
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/default/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 943CAD804AFE02A9
               -uid:  <36638a7257a04605aeec21ae0469f3f5@uuid.autocrypt.org>
      ---- no peers registered -----

This created a default identity: a new secret key and a UUID and a few settings.
If you rather like autocrypt to use your system keyring so that all incoming
keys are available there, see syskeyring_ but this will modify state on
your existing keyring.

Let's check out account info again with the ``status`` subcommand::

    $ autocrypt status
    account-dir: /tmp/home/.config/autocrypt

    identity: 'default' uuid 36638a7257a04605aeec21ae0469f3f5
      email_regex: .*
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/default/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 943CAD804AFE02A9
               -uid:  <36638a7257a04605aeec21ae0469f3f5@uuid.autocrypt.org>
      ---- no peers registered -----

This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ autocrypt make-header a@example.org
    Autocrypt: to=a@example.org; key=
      mQENBFi2tTkBCADmS/YDZE2FQ9GvLt2e+Ctv4sy8nG9kF026IgOIleH24wBv8U/0G0wkgIJjfTv/Kd
      Qj0cie+yXHkFb19rtoB0myVeMdxTnW/a7Uorh/C3jqgdNUJ4V9g8JFMaEyuUVQD8NBlNbHR/XrTP5D
      MsEgMCLHRnknsfSYruOzkK4XVGBZmogHusoSEJrjrxl+JsdUSf+I5PXmRyaXeArQ8HbdJgTe8DolBl
      +gDYzLxuHweKB6kUeMB+JLifk54kQFFSmpExuSFwwv9qXICjpveQEwpguWlllCOI0DeBO6SSH2ifWt
      G/ZwTBkpPqkaJUvzoVbeP3lLTyEtGQjwVZx6d6UAGR3BABEBAAG0NiA8MzY2MzhhNzI1N2EwNDYwNW
      FlZWMyMWFlMDQ2OWYzZjVAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIAIgUCWLa1OQIbAwYLCQgH
      AwIGFQgCCQoLBBYCAwECHgECF4AACgkQlDytgEr+Aqkg5wf/YnttxUJCDdJf8XRM0HgRJgOLoSBkgf
      TG5/agTPB71DV6jy4lZzwBkrx9dQZ8YhA7eLsB+NEt9PZOZmvLT8MIqTBVlWCii144EKfujqwpIlkT
      MoBaMcYq9A7UKB9GR/q6xdPx15sIeoh5WV7CN4biDBCDcg5JvjXgR2I9fqocia0mHyT7SBpZWVxBqe
      BEz9KF3EO/h1AOCamgszz/GEDBYAUS+i5NAEHnubrhX2FABmduTmhFqmoMdn1MbVYdpsOT3DEBDa84
      aUbcxS5UD444EwLHYqU3qJljVZE7ILRH9h0dCfjnCVb/A/i9eByureZ+eNqYz3XHfYIB0iZlsZatqL
      kBDQRYtrU5AQgAwESiZ4qQ7bpN2XsME6nQgNTnvkjmqnByONV0A6HI3Ohu52EjrO8tFZsAKAOhSXcQ
      FgRNXbo6wja17saTlSJS97bl5TJXAUwHoTzwW++ckN7Ob+w8yHfr2B7uJVQTSCLZe1ODyIgptaqzaY
      lReycA5e4S0pXrHN2hY9n8voPPAF8Ac6GMKdc2iA+Yv2vZLY3q/ciauGIWzbzQS1ORiXFfjmTW0aQa
      L4e44/AJEcpu81JhqRBGyK8X89H8Qw91eDzKS+wkg2O+7UuLXMzJlyPBkbpQMkT8Jfi+GSpjgPrHS8
      sfyrdetG/JQeMoELfyxpxL86cnMKKs0RcmpYYhozEybwARAQABiQEfBBgBAgAJBQJYtrU5AhsMAAoJ
      EJQ8rYBK/gKp3RQH+QEL3HtUTuwzO9kwV2kmJBKYMcD1aqNRpmmip2/V0yYYwinIJl6IGl0xc/AqZ8
      5O0YeWyaULj59v45dhP0rhhsCTFlGyIe3jUTejG8D+JQfK0IT2Dn27k/iVPE3Tmf+33PXTQEPqpSz1
      f+GhktGEBbppToFQlsw4lBPYi1UcmQIlmc5uY9gnCYXUteVqPJc7kvXyZRvgnxszh8Oah4ZuHc/KcA
      mae0EILtaa0Px/aGbc8ynoI0lLLJI6asVI3MoPdnXAwflc3lnkKdD2ViYMUESxBMZs6hLG9YOMNTFT
      y5BDTEPf3961vGjHCyxQsh5Ndn2/zRGG20wkvRBMb2xF8d4=

Getting our own public encryption key in armored format::

    $ autocrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    mQENBFi2tTkBCADmS/YDZE2FQ9GvLt2e+Ctv4sy8nG9kF026IgOIleH24wBv8U/0
    G0wkgIJjfTv/KdQj0cie+yXHkFb19rtoB0myVeMdxTnW/a7Uorh/C3jqgdNUJ4V9
    g8JFMaEyuUVQD8NBlNbHR/XrTP5DMsEgMCLHRnknsfSYruOzkK4XVGBZmogHusoS
    EJrjrxl+JsdUSf+I5PXmRyaXeArQ8HbdJgTe8DolBl+gDYzLxuHweKB6kUeMB+JL
    ifk54kQFFSmpExuSFwwv9qXICjpveQEwpguWlllCOI0DeBO6SSH2ifWtG/ZwTBkp
    PqkaJUvzoVbeP3lLTyEtGQjwVZx6d6UAGR3BABEBAAG0NiA8MzY2MzhhNzI1N2Ew
    NDYwNWFlZWMyMWFlMDQ2OWYzZjVAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIA
    IgUCWLa1OQIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQlDytgEr+Aqkg
    5wf/YnttxUJCDdJf8XRM0HgRJgOLoSBkgfTG5/agTPB71DV6jy4lZzwBkrx9dQZ8
    YhA7eLsB+NEt9PZOZmvLT8MIqTBVlWCii144EKfujqwpIlkTMoBaMcYq9A7UKB9G
    R/q6xdPx15sIeoh5WV7CN4biDBCDcg5JvjXgR2I9fqocia0mHyT7SBpZWVxBqeBE
    z9KF3EO/h1AOCamgszz/GEDBYAUS+i5NAEHnubrhX2FABmduTmhFqmoMdn1MbVYd
    psOT3DEBDa84aUbcxS5UD444EwLHYqU3qJljVZE7ILRH9h0dCfjnCVb/A/i9eByu
    reZ+eNqYz3XHfYIB0iZlsZatqLkBDQRYtrU5AQgAwESiZ4qQ7bpN2XsME6nQgNTn
    vkjmqnByONV0A6HI3Ohu52EjrO8tFZsAKAOhSXcQFgRNXbo6wja17saTlSJS97bl
    5TJXAUwHoTzwW++ckN7Ob+w8yHfr2B7uJVQTSCLZe1ODyIgptaqzaYlReycA5e4S
    0pXrHN2hY9n8voPPAF8Ac6GMKdc2iA+Yv2vZLY3q/ciauGIWzbzQS1ORiXFfjmTW
    0aQaL4e44/AJEcpu81JhqRBGyK8X89H8Qw91eDzKS+wkg2O+7UuLXMzJlyPBkbpQ
    MkT8Jfi+GSpjgPrHS8sfyrdetG/JQeMoELfyxpxL86cnMKKs0RcmpYYhozEybwAR
    AQABiQEfBBgBAgAJBQJYtrU5AhsMAAoJEJQ8rYBK/gKp3RQH+QEL3HtUTuwzO9kw
    V2kmJBKYMcD1aqNRpmmip2/V0yYYwinIJl6IGl0xc/AqZ85O0YeWyaULj59v45dh
    P0rhhsCTFlGyIe3jUTejG8D+JQfK0IT2Dn27k/iVPE3Tmf+33PXTQEPqpSz1f+Gh
    ktGEBbppToFQlsw4lBPYi1UcmQIlmc5uY9gnCYXUteVqPJc7kvXyZRvgnxszh8Oa
    h4ZuHc/KcAmae0EILtaa0Px/aGbc8ynoI0lLLJI6asVI3MoPdnXAwflc3lnkKdD2
    ViYMUESxBMZs6hLG9YOMNTFTy5BDTEPf3961vGjHCyxQsh5Ndn2/zRGG20wkvRBM
    b2xF8d4=
    =S06F
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
    .........+++++
    ....+++++
    +++++
    ...+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key AFF0C9AA marked as ultimately trusted

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

    identity: 'default' uuid 4f72b7c6522d4584afbf21910883d399
      email_regex: .*
      gpgmode: system
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 0B55C419AFF0C9AA
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

    identity: 'home' uuid 7c2e35c43feb412d90b343e3db857d5d
      email_regex: (alice|wonder)@testsuite.autocrypt.org
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/home/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 5FF1012CD32FDAAA
               -uid:  <7c2e35c43feb412d90b343e3db857d5d@uuid.autocrypt.org>
      ---- no peers registered -----

This creates an decryption/encryption key pair and ties it to the name
``home`` and a regular expression which matches both
``alice@testsuite.autocrypt.org`` and ``wonder@testsuite.autocrypt.org``.

And now let's create another identity::

    $ autocrypt add-identity wonder --email-regex='alice@wunderland.example.org'
    identity added: 'wonder'

    identity: 'wonder' uuid 23a5de92cb8f4eca8ad2af0dcf474cce
      email_regex: alice@wunderland.example.org
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/wonder/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: notset
      own-keyhandle: 1C8E56D48EE8B770
               -uid:  <23a5de92cb8f4eca8ad2af0dcf474cce@uuid.autocrypt.org>
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

    $ autocrypt mod-identity home --prefer-encrypt=yes
    identity modified: 'home'

    identity: 'home' uuid 7c2e35c43feb412d90b343e3db857d5d
      email_regex: (alice|wonder)@testsuite.autocrypt.org
      gpgmode: own [home: /tmp/home/.config/autocrypt/id/home/gpghome]
      gpgbin: gpg [currently resolves to: /usr/bin/gpg]
      prefer-encrypt: yes
      own-keyhandle: 5FF1012CD32FDAAA
               -uid:  <7c2e35c43feb412d90b343e3db857d5d@uuid.autocrypt.org>
      ---- no peers registered -----

This new ``prefer-encrypt: yes`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if possible.  We can check this with the
`make-header`_ subcommand::

    $ autocrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: to=wonder@testsuite.autocrypt.org; prefer-encrypt=yes; key=
      mQENBFi2tT0BCACbCtoKwwAjLXpUMaUJOO6L4Kj9nvjQ4QrXSLovNoFw8V7zio4ZZTawmkm7puFCo8
      uyEh9A9kqkaPReUcc2TUNh28X1xlvMcuMNkKzxEtis32ealsql/vKFbLAAmEDgt54pMLQoQ6Lxv4dg
      Fj0lqtVsqPU35kPFCYPz8S2rdnfpsgByq7+Yl1iECgeAct01tHWZUA0hGojeu01kxSCqHTR2/b1kCY
      19RM9EXofzrhbHgy6quhvnanhOZ4pYvi6mzp511e4Eq8o3gFodJpuSSD3XtE5XPfxllqYpqqYRTLAG
      HsIvRPBiTKq9u0m3DrA2oCOt0qa/o+ZcP/QS+RllVhURABEBAAG0NiA8N2MyZTM1YzQzZmViNDEyZD
      kwYjM0M2UzZGI4NTdkNWRAdXVpZC5hdXRvY3J5cHQub3JnPokBOAQTAQIAIgUCWLa1PQIbAwYLCQgH
      AwIGFQgCCQoLBBYCAwECHgECF4AACgkQX/EBLNMv2qq6vQf+IM95jXQmuyAF1cx/8AkpQYG2kWgggv
      pyEa8mw2MatRiXbllvxWDstzKYMlC1v1PsQeXqMh8JPRhRKNPIN1UlrIei9muhME08SxZE11dbsfG2
      l5ZJ1iCOHdaD9bnBFJnuRMTsMDdS7AONn/KjjRl+UJfg8jIJc7ZN3hjNx9bglred+kyL6ctel4l8HE
      r3fS/MxX3kEHazYe1eCloPOzfkogtRMEsiVvUdSMOGPgd0A0AharufX2A5K+t3/Ty5myYoKtqVqjtr
      FSn2SDYleZWcC2Up/WmCT8GYT9449oqdb98JJaIQRLHboI+FNfIKUb/M2yUlBSQKHbcJy9WFsgbQkb
      kBDQRYtrU9AQgArHwSh/r31vu+yK7TqdRUPZstpedhltMqgtmSnFqGE1oz8ceiCrvJs40kvvCuSltm
      781GUrYskiSknjZImV3FaEb9MOvyfuC5B7icfrPUsUPYVdSOrO9v/iyAy53xZU/e9k+KJextYoLSIF
      Mmhmrnamo7pbLpIbodW1CKhHke6My/e5xevcurza0KdLgPH+F/aPdETIXVVEq08LkMBUxNR3Gym8+C
      wQQQpYsOe+1WAcbzgGi2rN9OxoK3HE30ZxBMkXN2DaV9l40T/dzlV+P38LXCKDzgLk1eMuuYA8pEQy
      CPALyhbvhgTJF4vgqc7XjLuNAiKeEPQ04IX32lrpgOswARAQABiQEfBBgBAgAJBQJYtrU9AhsMAAoJ
      EF/xASzTL9qq5LIH/A6kv79N59j7hvS0p+Qyv+8aR7ExjQEAYPERqv/zPJQgPClmnwxNh6xOqkVD1O
      naUN6Ao5+ouKvTJfegt9ldR8TVfnzJRFOL+sE7sgywKlqwy316W+Qc9FxEYr5591HqzK569boqKLT6
      gedi45RaJulmAS1Nak9RiYdGrmuesn4IJqMuL5sIqoxC/YK9uc08oSxUfrrGAL7cfLtqR6Jnifm+dI
      ZlhQDouIGkAPv4eaLKZtez8y8Omnr+Cium0JqCwVgwRDRoh8pf+dTmogMWuJRh+5/MTG3ZwAwp2Pju
      byufLrIbebcvUrSGt7uJSfOHftJTtuMIOPhuMbhqAMXcVAE=

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
piping the resulting mail to the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
