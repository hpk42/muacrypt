
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
      own-keyhandle:   234D174CD35B01FD
      ^^ uid:           <3a649810c7754f6682f8208ba1af023e@random.muacrypt.org>
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
      own-keyhandle:   234D174CD35B01FD
      ^^ uid:           <3a649810c7754f6682f8208ba1af023e@random.muacrypt.org>
      ---- no peers registered -----


This shows our own keyhandle of our Autocrypt OpenPGP key.

Let's generate a static email Autocrypt header which
you could add to your email configuration (substitute
``a@example.org`` with your email address)::

    $ muacrypt make-header a@example.org
    Autocrypt: addr=a@example.org; keydata=
      mQENBFpXm7UBCADKWE+prMRM9MvrZup6cOsVQPem6kbXDLobJjYjD2whgiiHvU0vV9Zy7MR6J/VrRx
      ZrwDDJvkqKih/t0IFC24ntb4JI1snVPJCKikPUUk/rkhv6ZhMtmZAE5E76VSGSjqTeVptQHKQbyLNS
      +y1viqWX+kkQhf3moGMD9a/ZcjWyplOa5gnB1hUElckBax66NTIC0fcTuvYw9pLDpVZ+XuU7Qrka6r
      CxqiLoCRDxlpttZLL1pWXplHZYTjicaiUiCSAIPGbFrGg57NqPbTsvXy9gW46uzL8cv+gE4Lm65imt
      vHHR+QiFFmHRN/o3jdaQ9W5TtInSIKOxPnBS5KbsXykZABEBAAG0NyA8M2E2NDk4MTBjNzc1NGY2Nj
      gyZjgyMDhiYTFhZjAyM2VAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwECACIFAlpXm7UCGwMGCwkI
      BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJECNNF0zTWwH9tv0H/2VdCCEYrqSDIJlbu4Yq+chBmAeCsj
      NDd5L0aAAHxDTMOLavYCcoWEgPT/eFnWMU4N4tLE9/sW81hQHbbfewoX4zYWO8les/bIjtbNhCRfrE
      80losuHG8YT71fqREMuUkqYQL/kJ2RAetV6SMTq1Thi2aljz8Ap1AP9bOpG2Y7R6aXR45pbjCPjb5D
      EuHNT0M52cTNXV4blPaArOIzDk2Utxax6AGlsu3SV3TSfPF2K1K7666qGnjXCFU/lMP4cpe8VQufaq
      emOwygOSu3698ltcqVXtMBA8QIJjJKodzyuAUKcmr0CaVCjcUYYGGvFv+aFp59zSR7LMHMqQR9lTjn
      e5AQ0EWlebtQEIAOF0OeEE/i7Kc1XVd8vGVYM82lDWvn2Y88499KmFcqHf9oIPxtHQZUlYG4SIkl7a
      21dFxD0Cv+J0Aq+8UG1qmX7OHFOzUNB4OmcfLU64DpYQ/8FcWwMTNbp6RKCLu5MyiRvxfc3rby2aHB
      Ec69vQk7MvbzMzEdCM3Vj/+NlpsFs0hVmPZfJ3ZpcdmVwHT0szwqtUb4Mf5KrncFRoUPQKnc/fcRPF
      Ca95dChLEwMqWTk0N25uHGy58C5iuC5pb515n2u/PVYC5UIvH04YT3H7ldDPczZbFod9mafGb1Re/K
      j+eEpSXnkmpS1hnTYD3rkc45W8a3cvq9/59/HlYB16moMAEQEAAYkBHwQYAQIACQUCWlebtQIbDAAK
      CRAjTRdM01sB/UCzB/0bY8Gc+AkPLGzI+FohC6z2Zz8eul1ZN7gK8KEkxNSFSUR36H6tFKJFOM3CvV
      /P8siuR+8C8OreDapmfUdhJjAJVpUMOmlUldezcjV+EX3zHRi3fYvbilYXhA9Hx/rU/tzxJ0td/4+S
      pcTPcJvzA4+gs00xeAl8s+9x5kkOiSfontFuKTyunOMI0iCmI+mY8A7asAyk380sDZTPnsaGxyjYgc
      Zzk6T1rMvML1q5IsIFQTAyO16JsY+W39dKxSoUFlOda+8hPvtL1b1wb69wgj1aahWdf5dhjP56Gmnz
      t1sJQkUvhpECXXiMZajuAkRF9egTLZaUAkJ3XLOWr6VZJJQr

Getting our own public encryption key in armored format::

    $ muacrypt export-public-key
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1

    mQENBFpXm7UBCADKWE+prMRM9MvrZup6cOsVQPem6kbXDLobJjYjD2whgiiHvU0v
    V9Zy7MR6J/VrRxZrwDDJvkqKih/t0IFC24ntb4JI1snVPJCKikPUUk/rkhv6ZhMt
    mZAE5E76VSGSjqTeVptQHKQbyLNS+y1viqWX+kkQhf3moGMD9a/ZcjWyplOa5gnB
    1hUElckBax66NTIC0fcTuvYw9pLDpVZ+XuU7Qrka6rCxqiLoCRDxlpttZLL1pWXp
    lHZYTjicaiUiCSAIPGbFrGg57NqPbTsvXy9gW46uzL8cv+gE4Lm65imtvHHR+QiF
    FmHRN/o3jdaQ9W5TtInSIKOxPnBS5KbsXykZABEBAAG0NyA8M2E2NDk4MTBjNzc1
    NGY2NjgyZjgyMDhiYTFhZjAyM2VAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwEC
    ACIFAlpXm7UCGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJECNNF0zTWwH9
    tv0H/2VdCCEYrqSDIJlbu4Yq+chBmAeCsjNDd5L0aAAHxDTMOLavYCcoWEgPT/eF
    nWMU4N4tLE9/sW81hQHbbfewoX4zYWO8les/bIjtbNhCRfrE80losuHG8YT71fqR
    EMuUkqYQL/kJ2RAetV6SMTq1Thi2aljz8Ap1AP9bOpG2Y7R6aXR45pbjCPjb5DEu
    HNT0M52cTNXV4blPaArOIzDk2Utxax6AGlsu3SV3TSfPF2K1K7666qGnjXCFU/lM
    P4cpe8VQufaqemOwygOSu3698ltcqVXtMBA8QIJjJKodzyuAUKcmr0CaVCjcUYYG
    GvFv+aFp59zSR7LMHMqQR9lTjne5AQ0EWlebtQEIAOF0OeEE/i7Kc1XVd8vGVYM8
    2lDWvn2Y88499KmFcqHf9oIPxtHQZUlYG4SIkl7a21dFxD0Cv+J0Aq+8UG1qmX7O
    HFOzUNB4OmcfLU64DpYQ/8FcWwMTNbp6RKCLu5MyiRvxfc3rby2aHBEc69vQk7Mv
    bzMzEdCM3Vj/+NlpsFs0hVmPZfJ3ZpcdmVwHT0szwqtUb4Mf5KrncFRoUPQKnc/f
    cRPFCa95dChLEwMqWTk0N25uHGy58C5iuC5pb515n2u/PVYC5UIvH04YT3H7ldDP
    czZbFod9mafGb1Re/Kj+eEpSXnkmpS1hnTYD3rkc45W8a3cvq9/59/HlYB16moMA
    EQEAAYkBHwQYAQIACQUCWlebtQIbDAAKCRAjTRdM01sB/UCzB/0bY8Gc+AkPLGzI
    +FohC6z2Zz8eul1ZN7gK8KEkxNSFSUR36H6tFKJFOM3CvV/P8siuR+8C8OreDapm
    fUdhJjAJVpUMOmlUldezcjV+EX3zHRi3fYvbilYXhA9Hx/rU/tzxJ0td/4+SpcTP
    cJvzA4+gs00xeAl8s+9x5kkOiSfontFuKTyunOMI0iCmI+mY8A7asAyk380sDZTP
    nsaGxyjYgcZzk6T1rMvML1q5IsIFQTAyO16JsY+W39dKxSoUFlOda+8hPvtL1b1w
    b69wgj1aahWdf5dhjP56Gmnzt1sJQkUvhpECXXiMZajuAkRF9egTLZaUAkJ3XLOW
    r6VZJJQr
    =0dOZ
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
    +++++
    ....+++++
    .+++++
    ..+++++
    gpg: /tmp/home/.gnupg/trustdb.gpg: trustdb created
    gpg: key F9C77680 marked as ultimately trusted

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
      own-keyhandle:   66459704F9C77680
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
      own-keyhandle:   D08197FB89A6F19D
      ^^ uid:           <693ffd87aa804cc795565da24971f099@random.muacrypt.org>
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
      own-keyhandle:   35B7EFDCE0A62C6E
      ^^ uid:           <22ead00fddde435fbe483ac63cf4315d@random.muacrypt.org>
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
      own-keyhandle:   D08197FB89A6F19D
      ^^ uid:           <693ffd87aa804cc795565da24971f099@random.muacrypt.org>
      ---- no peers registered -----

This new ``prefer-encrypt: mutual`` setting tells our peers that we prefer
to receive encrypted mails.  This setting will cause processing of
outgoing mails from the home address to add a header indicating that we
want to receive encrypted mails if the other side also wants encrypted mails.
We can check the setting works with the `make-header`_ subcommand::

    $ muacrypt make-header wonder@testsuite.autocrypt.org
    Autocrypt: addr=wonder@testsuite.autocrypt.org; prefer-encrypt=mutual; keydata=
      mQENBFpXm7kBCACiVUitD9jSIcaxrdbc6tPltnKVLLiS+/Sx9ZMyzIoz+m+N3ToJ1gS3g/8F0/x6bN
      nFi3LxQWGZXVzmTJiCDyJAQ2gJ3h8paht80rPexWcRMsB8jThBP+TlRyUJpi5PRC4zmA7PwVgHU0ir
      Owj3bT/btBvDdrSqJHaObROL/xJZSqQSv2qfBzXUHviiyb6GyILYXXZSuiSS8gZG2Q2B0RrvmCUvIj
      8O1KV7q94FVW4nWwnQlrgDxZ+QW2xZGjwfIDFvxoyhdK9pJ6co+6j/RWiZNvJUnMxfYTqsOJrKrwlk
      GSwAkWTyPlFNAqCK1eackkMTpr6kin/e3rSpAY3+8ye5ABEBAAG0NyA8NjkzZmZkODdhYTgwNGNjNz
      k1NTY1ZGEyNDk3MWYwOTlAcmFuZG9tLm11YWNyeXB0Lm9yZz6JATgEEwECACIFAlpXm7kCGwMGCwkI
      BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJENCBl/uJpvGdSnQH/0n4qb87Y6SuOjNYzRgY6JYh82og3d
      zvmm14djWg1Ys8Zwxs/SV+aXVdZxBgttB3usTzC6xoj+gm9CTnbO4xmIro2RY2DPZGA/QPUrFx7K0w
      ENi8zbok32pHVLCFjiRVHaFXPLwkeYeylts+3vVI93rSugGS6zZHTASdzAGav2ez/P5N1UoIk8iDjP
      Ith/i1PiqcxWhpIl7cuJaMSngv5bXV77xGsYH9gg2E5eQ2p0MEmgQKu1d9yRTEP9TRWKXrhOk56Doq
      wh6rNyC+wzXr2orpf8BETF0ypTvnxBmnENMSfxJp1ioZzxwRURdfUFlqUtSJNJuus4jVnRftK8yFR8
      q5AQ0EWlebuQEIAMVMf74nZMuMRg0iAdpifMAYXMR1T7VL4yvl+VKYhBdZkbYYsBfUaFencZhjWgir
      85ILScE72Ra5nKEaKn4cFTnzilGxNimhQ1V1kx9xfEI+jwjBbuu7ZBCKWICpL7oM+f00nYnc+3ireE
      Whu5IIT9+rbuR8SVaiY0Kgx7TNHPZOkDw8iAwhlllj71H8vZ70yhZUywIBQXMvOf4N20Ndp7hN1qf3
      UdyyDkm6B6UvSXz4XtTD4ng53qZ9ReFmTtQS2o11lsIDosqbavCEBylegcZsW6ebRtcZZONaX1uzLC
      aZmXoZI7XXOZkDTfWPlpUhFb68I6+ugdGjiqKdUBcrBzUAEQEAAYkBHwQYAQIACQUCWlebuQIbDAAK
      CRDQgZf7iabxnSuhB/97nGOZhHVGGjw5tjJrbSQ+kw/9OOLTPtp+Gbftkc5KkxJZMx9zn2ghtxTsz+
      TVeVQzcTvLQARlZx9xe33AqJxm0Dnty+4DfQte0cwtz+IZ9F8dn2vpoxrrQsJcyjqDHdMbjAaokCSb
      hcBuE21t+NYyx76ouzlYn2XAnNrUElLXSP4S1xsMOjKR1h5F6kCoGus3l26BD75El4R48vPCchcea7
      qjt4az14+Z22Qk3Iwms5q08CVRcJmsSKMb8iOXviKlI8kEFWi2wzqTpfbSZL77iQ4BP2fj27uFEo2Z
      7GYL4v/l1Nf7MdNCLdj7G7/2uqOauOMH9C+0cw8W2A0NlRRx

When you pipe a message with a From-address matching Alice's home addresses into
the `process-outgoing`_ subcommand then it will add this header. By using the sendmail_
subcommand (as a substitute for unix's sendmail program) you can cause
the resulting mail to be delivered via the ``/usr/sbin/sendmail`` program.

.. _cmdref:

.. include:: cmdref.inc
