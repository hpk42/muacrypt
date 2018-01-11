
subcommand reference |version|
------------------------------

.. _`init`:

init subcommand
+++++++++++++++

::

  Usage: muacrypt init [OPTIONS]
  
    init muacrypt state.
  
    By default this command creates account(s) state in a directory with a
    default "catch-all" account which matches all email addresses and uses
    default settings.  If you want to have more fine-grained control (which
    gpg binary to use, which existing key to use, if to use an existing system
    key ring ...) specify "--no-account".
  
  Options:
    --replace     delete muacrypt state directory before attempting init
    --no-account  initializing without creating a default account
    -h, --help    Show this message and exit.

.. _`status`:

status subcommand
+++++++++++++++++

::

  Usage: muacrypt status [OPTIONS] [ACCOUNT_NAME]
  
    print account info and status.
  
  Options:
    -h, --help  Show this message and exit.

.. _`add-account`:

add-account subcommand
++++++++++++++++++++++

::

  Usage: muacrypt add-account [OPTIONS] ACCOUNT_NAME
  
    add a named account.
  
    An account requires an account_name which is used to show, modify and
    delete it.
  
    Of primary importance is the "email_regex" which you typically set to a
    plain email address.   It is used when incoming or outgoing mails need to
    be associated with this account.
  
    Instead of generating an Autocrypt-compliant key (the default operation)
    you may specify an existing key with --use-key=keyhandle where keyhandle
    may be something for which gpg finds it with 'gpg --list-secret-keys
    keyhandle'. Typically you will then also specify --use-system-keyring to
    make use of your existing keys.  All incoming muacrypt keys will thus be
    statesd in the system key ring instead of an own keyring.
  
  Options:
    --use-key KEYHANDLE   use specified secret key which must be findable
                          through the specified keyhandle (e.g. email, keyid,
                          fingerprint)
    --use-system-keyring  use system keyring for all secret/public keys instead
                          of storing keyring state inside our account directory.
    --gpgbin FILENAME     use specified gpg filename. If it is a simple name it
                          is looked up on demand through the system's PATH.
    --email-regex TEXT    regex for matching all email addresses belonging to
                          this account.
    -h, --help            Show this message and exit.

.. _`mod-account`:

mod-account subcommand
++++++++++++++++++++++

::

  Usage: muacrypt mod-account [OPTIONS] ACCOUNT_NAME
  
    modify properties of an existing account.
  
    Any specified option replaces the existing one.
  
  Options:
    --use-key KEYHANDLE             use specified secret key which must be
                                    findable through the specified keyhandle
                                    (e.g. email, keyid, fingerprint)
    --gpgbin FILENAME               use specified gpg filename. If it is a
                                    simple name it is looked up on demand
                                    through the system's PATH.
    --email-regex TEXT              regex for matching all email addresses
                                    belonging to this account.
    --prefer-encrypt                ]
                                    modify prefer-encrypt setting, default is to
                                    not change it.
    -h, --help                      Show this message and exit.

.. _`del-account`:

del-account subcommand
++++++++++++++++++++++

::

  Usage: muacrypt del-account [OPTIONS] ACCOUNT_NAME
  
    delete an account, its keys and all state.
  
    Make sure you have a backup of your whole account directory first.
  
  Options:
    -h, --help  Show this message and exit.

.. _`process-incoming`:

process-incoming subcommand
+++++++++++++++++++++++++++

::

  Usage: muacrypt process-incoming [OPTIONS]
  
    parse Autocrypt headers from stdin mail.
  
  Options:
    -h, --help  Show this message and exit.

.. _`process-outgoing`:

process-outgoing subcommand
+++++++++++++++++++++++++++

::

  Usage: muacrypt process-outgoing [OPTIONS]
  
    add Autocrypt header for outgoing mail.
  
    We process mail from stdin by adding an Autocrypt header and send the
    resulting message to stdout. If the mail from stdin contains an Autocrypt
    header we keep it for the outgoing message and do not add one.
  
  Options:
    -h, --help  Show this message and exit.

.. _`sendmail`:

sendmail subcommand
+++++++++++++++++++

::

  Usage: muacrypt sendmail [OPTIONS] [ARGS]...
  
    as process-outgoing but submit to sendmail binary.
  
    Processes mail from stdin by adding an Autocrypt header and pipes the
    resulting message to the "sendmail" program. If the mail from stdin
    contains an Autocrypt header we use it for the outgoing message and do not
    add one.
  
    Note that unknown options and all arguments are passed through to the
    "sendmail" program.
  
  Options:
    -h, --help  Show this message and exit.

.. _`test-email`:

test-email subcommand
+++++++++++++++++++++

::

  Usage: muacrypt test-email [OPTIONS] EMAILADR
  
    test which account an email belongs to.
  
    Fail if no account matches.
  
  Options:
    -h, --help  Show this message and exit.

.. _`make-header`:

make-header subcommand
++++++++++++++++++++++

::

  Usage: muacrypt make-header [OPTIONS] EMAILADR
  
    print Autocrypt header for an emailadr.
  
  Options:
    -h, --help  Show this message and exit.

.. _`export-public-key`:

export-public-key subcommand
++++++++++++++++++++++++++++

::

  Usage: muacrypt export-public-key [OPTIONS] [KEYHANDLE_OR_EMAIL]
  
    print public key of own or peer account.
  
  Options:
    -a, --account name  perform lookup through this account
    -h, --help          Show this message and exit.

.. _`export-secret-key`:

export-secret-key subcommand
++++++++++++++++++++++++++++

::

  Usage: muacrypt export-secret-key [OPTIONS]
  
    print secret key of own account.
  
  Options:
    -a, --account name  perform lookup through this account
    -h, --help          Show this message and exit.

.. _`bot-reply`:

bot-reply subcommand
++++++++++++++++++++

::

  Usage: muacrypt bot-reply [OPTIONS]
  
    reply to stdin mail as a bot.
  
    This command will generate a reply message and send it to stdout by
    default. The reply message contains an Autocrypt header and details of
    what was found and understood from the incoming mail.
  
  Options:
    --smtp host,port         host and port where the reply should be instead of
                             to stdout.
    --fallback-delivto TEXT  assume delivery to the specified email address if
                             no delivered-to header is found.
    -h, --help               Show this message and exit.

