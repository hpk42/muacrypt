
Python Autocrypt repository
==============================================

This respository offers the following functionality:

- python autocrypt package to create and manage Autocrypt
  account directories and process incoming and outgoing mails,
  see `core/README.rst <core/README.rst>`_.

- autocrypt command line with sub commands for creating
  and managing Autocrypt account directories and process
  incoming and outgoing mails.
  see `core/README.rst <core/README.rst>`_.

- (in-progress) a simple bot implementation which can be
  deployed to properly answer Autocrypt mails, parsing
  headers from peers and sending (possibly encrypted) replies
  which reflect to the sender what the bot perceived in terms
  of autocrypt information.

**Requirements**

You need to separately install "gpg" or "gpg2" if you
want to use or manage keys with the system keyring.

**NOTE**

This implementation is not Level 1 compliant.  See #17.

Also note there is a separate python autocrypt implementation
effort ongoing at https://github.com/juga0/pyac which is based
on the "pgpy" library and does not depend on the "gpg" command
line tool.  We'd like to integrate with pgpy/pyac at a later stage.
