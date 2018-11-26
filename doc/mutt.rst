
mutt integration with muacrypt
==============================

.. note::
   The below mutt/muacrypt integration is a first effort at integration.
   It may contain errors or rough edges. Please help to refine
   the integration by making PRs against https://github.com/hpk42/muacrypt
   and the "doc/mutt.rst" file in particular. Thanks!

``muacrypt`` can be used in conjunction with mutt which allows
to turn otherwise cleartext mail into encrypted mail.
The muacrypt/mutt integration manages PGP keys automatically according to
the `Autocrypt Level 1 specification <https://autocrypt.org/level1.html>`_.
**You don't need to import keys or make decisions about them**.

Apart from `installing muacrypt <install>`_ you will need to
create a muacrypt account and configure the processing of incoming
and outgoing mail with your particular mutt/mail setup. The
example mutt/muacrypt integration below assumes that you already
have a way of synchronizing remote imap folders to a local directory.

We also assume you have a working config for mutt/pgp already and
are able to send/receive PGP-encrypted messages.
The proposed setup here does not require you to use
the PGP- and key-selection menus available
from mutt's compose screens.  That's exactly what
you won't need to care about with the muacrypt/mutt setup.
You may also mix your current mutt/PGP usage with Autocrypt usage
because muacrypt will leave already encrypted outgoing messages alone.

.. contents::

Creating an muacrypt account
----------------------------

First, you need to add a new muacrypt Account. All muacrypt
state is typically kept in ``$HOME/.config/muacrypt``.
Because we are working with your existing mutt/pgp integration
for being able to decrypt messages it's a good idea to not use
muacrypt's default account-creation because this would happen
in a separate non-system keyring.  Instead we recommend to use a key
from your system keyring when creating the account::

    muacrypt add-account --use-system-keyring --use-key MY_EMAIL_ADDRESS_OR_KEY_HANDLE

You may generate a new dedicated Autocrypt key ("gpg --gen-key")
and then reference it for use by mutt/muacrypt instead of
re-using an already existing key.

.. note::

    muacrypt does not support secret keys using passphrases.
    See also Autocrypt's take on it:
    https://autocrypt.org/level1.html#secret-key-protection-at-rest


Processing outgoing mail / sendmail pipelining
----------------------------------------------

The ``muacrypt sendmail`` command:

- adds Autocrypt headers for outgoing mail from your own address,

- potentially and transparently encrypts outgoing cleartext messages according to the
  `Autocrypt UI recommendation <https://autocrypt.org/level1.html#provide-a-recommendation-for-message-encryption>`_,

- passes on the modified/amended mail to the ``sendmail`` command.

In your ``.muttrc`` you need to add something like the following::

    set sendmail="/path/to/muacrypt sendmail -oem -oi"

    # avoid mutt/pgp making decisions about keys now that muacrypt looks
    # at each outgoing mail and will itself encrypt if recommended by Autocrypt
    set crypt_autoencrypt=no
    set crypt_replyencrypt=no
    set crypt_replysignencrypted=no

The idea here is that that in the composing-mail window you don't work with the
mutt/pgp menus at all and let ``muacrypt sendmail`` do its job of selecting the correct last-seen
keys for your recipients.  This will also add "Gossip" headers in the
encrypted part of outgoing mails so that each of your recipients,
if they are using an Autocrypt compliant Mail app, can safely
group-reply and maintain encryption.

.. TODO::

    currently, ``muacrypt sendmail`` is not respecting if a mail
    is a reply to an encrypted mail -- Autocrypt recommends to
    keep replies encrypted in such cases.


Controlling encryption through the ENCRYPT header
-------------------------------------------------

Both the ``muacrypt sendmail`` and ``muacrypt process-outgoing`` sub commands
check for the ``ENCRYPT`` header in each mail they are processing.
The ``ENCRYPT`` header is only used for internal mutt/muacrypt communication
and controls how muacrypt is to treat outgoing messages. The ``ENCRYPT`` header
can have one of three different values:

- ``opportunistic`` (also the assumed default value if no env-var is present):
  uses the ui-recommendation of Autocrypt to determine
  if a mail should be encrypted.

- ``yes``: force encrypted mails and fail if encryption is not available
  for the recipients. Note that forcing encryption can be annoying
  to **your peer's mail experience** because they might receive mail
  they can not read in their current situation (webmail/device without secret key).

- ``no``: force cleartext even if encryption is recommended.

Note that ``muacrypt sendmail`` will remove the ``ENCRYPT`` header after
it has processed it and acted accordingly.

It's probably possible to configure mutt keystrokes to set the ``ENCRYPT``
header during compose but there is no way to show the ``ENCRYPT``
header in mutt's "compose screen". Therefore the current recommended way
for being able to modify/set the ENCRYPT header is::

    # put into your .muttrc if you want to be able to
    # modify the ENCRYPT header for each outgoing mail
    my_hdr ENCRYPT: opportunistic
    set edit_headers=yes

With these settings, when you compose/edit a message you will be able
to set the "ENCRYPT" header to one of the above values.
However, you don't need to use ``edit_headers=yes`` -- just operating in
opportunistic mode without forcing encryption/cleartext will make use
of Autocrypt's refined automatic "recommendation" procedures which
try to replace cleartext with encrypted mail but only if it is likely
that it doesn't get in the way of users.

Processing incoming mail from maildirs
----------------------------------------

::

    $ muacrypt scandir-incoming -h
    Usage: muacrypt scandir-incoming [OPTIONS] DIRECTORY

      scan directory for new incoming messages and process Autocrypt and
      Autocrypt-gossip headers from them.

    Options:
      -h, --help  Show this message and exit.

It is crucial to pipe each new (non-spam) incoming mail to
the ``muacrypt process-incoming`` subcommand,
because incoming mails may contain Autocrypt headers
both in the cleartext part and the encrypted part of a message.

Unfortunately, mutt's ``display_filter`` can not be used for
calling into ``process-incoming`` because this hook strips headers
that muacrypt needs to see. In the absence of a fitting mutt hook
(please suggest one if you know one!) you may use, outside of mutt,
a helper command to scan directories for incoming mail::

    muacrypt scan-incoming-dir /some/path/to/maildir/

All files in the ``/some/path/to/maildir`` directory will be scanned.
If you actually use the Maildir format for your local e-mail copies,
it's recommended to only scan mails in the "new" folder::

    muacrypt scan-incoming-dir /some/path/to/maildir/new

In any case, you need to make sure that ``muacrypt scan-incoming-dir``
is invoked every time you have re-synced your local folder from the
remote IMAP one.  Note that ``scan-incoming-dir`` is just a helper
which eventually pipes each found mail/file into ``muacrypt process-incoming``.
If you have other ways of piping new incoming messages through
``muacrypt process-incoming`` then, by all means, do it and
please file a PR against this documentation if it could be of use
to other people.


Importing existing keys as Autocrypt keys
-----------------------------------------

If you are already using PGP you might already
have keys or get new keys through mail attachments.
You can pipe existing keys to muacrypt like this::

    gpg -a --export SOME_HANDLE_OR_EMAILADR | muacrypt import-public-key

Or you can just pipe an attachment from mutt's message-view
usually by typing ``| muacrypt import-public-key`` and you
might assign this to a key.  Note that the default
``muacrypt import-public-key`` command will:

- associate all of the email addresses contained
  in the UIDs with the imported PGP key

- set a prefer-encrypt setting to ``mutual`` by default.

Please refer to the help for more info on how to change the defaults::

    $ muacrypt import-public-key -h
    Usage: muacrypt import-public-key [OPTIONS]

      import public key data as an Autocrypt key.

      This commands reads from stdin an ascii-armored public PGP key. By default
      all e-mail addresses contained in the UIDs will be associated with the
      key. Use options to change these default behaviours.

    Options:
      -a, --account name              use this account name
      --prefer-encrypt [nopreference|mutual]
                                      prefer-encrypt setting for imported key
      --email TEXT                    associate key with this e-mail address
      -h, --help                      Show this message and exit.
