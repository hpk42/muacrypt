
subcommand reference |version|
------------------------------

.. _`init`:

init subcommand
+++++++++++++++

**init**:

  Usage: autocrypt init [OPTIONS]
  
    init autocrypt account state.
  
    By default this command creates account state in a directory with a
    default "catch-all" identity which matches all email addresses and uses
    default settings.  If you want to have more fine-grained control (which
    gpg binary to use, which existing key to use, if to use an existing system
    key ring ...) specify "--no-identity".
  
  Options:
    --replace      delete autocrypt account directory before attempting init
    --no-identity  initializing without creating a default identity
    -h, --help     Show this message and exit.

.. _`status`:

status subcommand
+++++++++++++++++

**status**:

  Usage: autocrypt status [OPTIONS]
  
    print account and identity info.
  
  Options:
    -h, --help  Show this message and exit.

.. _`add-identity`:

add-identity subcommand
+++++++++++++++++++++++

**add-identity**:

  Usage: autocrypt add-identity [OPTIONS] IDENTITY_NAME
  
    add an identity to this account.
  
    An identity requires an identity_name which is used to show, modify and
    delete it.
  
    Of primary importance is the "email_regex" which you typically set to a
    plain email address.   It is used when incoming or outgoing mails need to
    be associated with this identity.
  
    Instead of generating a key (the default operation) you may specify an
    existing key with --use-existing-key=keyhandle where keyhandle may be
    something for which gpg finds it with 'gpg --list-secret-keys keyhandle'.
    Typically you will then also specify --use-system-keyring to make use of
    your existing keys.  All incoming autocrypt keys will thus be stored in
    the system key ring instead of an own keyring.
  
  Options:
    --use-existing-key TEXT  use specified secret key which must be findable
                             through the specified keyhandle (e.g. email, keyid,
                             fingerprint)
    --use-system-keyring     use system keyring for all secret/public keys
                             instead of storing keyring state inside our account
                             identity directory.
    --gpgbin TEXT            use specified gpg binary. if it is a simple name it
                             is looked up on demand through the system's PATH.
    --email-regex TEXT       regex for matching all email addresses belonging to
                             this identity.
    -h, --help               Show this message and exit.

.. _`mod-identity`:

mod-identity subcommand
+++++++++++++++++++++++

**mod-identity**:

  Usage: autocrypt mod-identity [OPTIONS] IDENTITY_NAME
  
    modify properties of an existing identity.
  
    An identity requires an identity_name which is used to show, modify and
    delete it.
  
    Any specified email_regex replaces the existing one.
  
    Any specified key replaces the existing one.
  
  Options:
    --use-existing-key TEXT         use specified secret key which must be
                                    findable through the specified keyhandle
                                    (e.g. email, keyid, fingerprint)
    --gpgbin TEXT                   use specified gpg binary. if it is a simple
                                    name it is looked up on demand through the
                                    system's PATH. if it is None (the default)
                                    no change is made
    --email-regex TEXT              regex for matching all email addresses
                                    belonging to this identity. If it None (the
                                    default) no change is made to the existing
                                    regex.
    --prefer-encrypt                
                                    modify prefer-encrypt setting, default is to
                                    not change it.
    -h, --help                      Show this message and exit.

.. _`del-identity`:

del-identity subcommand
+++++++++++++++++++++++

**del-identity**:

  Usage: autocrypt del-identity [OPTIONS] IDENTITY_NAME
  
    delete an identity, its keys and all state.
  
    Make sure you have a backup of your whole account directory first.
  
  Options:
    -h, --help  Show this message and exit.

.. _`process-incoming`:

process-incoming subcommand
+++++++++++++++++++++++++++

**process-incoming**:

  Usage: autocrypt process-incoming [OPTIONS]
  
    parse autocrypt headers from stdin mail.
  
  Options:
    -h, --help  Show this message and exit.

.. _`process-outgoing`:

process-outgoing subcommand
+++++++++++++++++++++++++++

**process-outgoing**:

  Usage: autocrypt process-outgoing [OPTIONS]
  
    add autocrypt header for outgoing mail.
  
    We process mail from stdin by adding an Autocrypt header and send the
    resulting message to stdout. If the mail from stdin contains an Autocrypt
    header we keep it for the outgoing message and do not add one.
  
  Options:
    -h, --help  Show this message and exit.

.. _`sendmail`:

sendmail subcommand
+++++++++++++++++++

**sendmail**:

  Usage: autocrypt sendmail [OPTIONS] [ARGS]...
  
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

**test-email**:

  Usage: autocrypt test-email [OPTIONS] EMAILADR
  
    test which identity an email belongs to.
  
    Fail if no identity matches.
  
  Options:
    -h, --help  Show this message and exit.

.. _`make-header`:

make-header subcommand
++++++++++++++++++++++

**make-header**:

  Usage: autocrypt make-header [OPTIONS] EMAILADR
  
    print autocrypt header for an emailadr.
  
  Options:
    -h, --help  Show this message and exit.

.. _`export-public-key`:

export-public-key subcommand
++++++++++++++++++++++++++++

**export-public-key**:

  Usage: autocrypt export-public-key [OPTIONS] [KEYHANDLE_OR_EMAIL]
  
    print public key of own or peer account.
  
  Options:
    -h, --help  Show this message and exit.

.. _`export-secret-key`:

export-secret-key subcommand
++++++++++++++++++++++++++++

**export-secret-key**:

  Usage: autocrypt export-secret-key [OPTIONS]
  
    print secret key of own autocrypt account.
  
  Options:
    -h, --help  Show this message and exit.

