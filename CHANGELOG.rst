0.8.1
-----------------------

- fixed changelog

- #74 allow unicode To addresses in process-sendmail/outgoing

0.8.0
-----------------------

- reply to multiple CC'ed recipients with the bot so we can test
  gossip.

- introduce plugin architecture with hooks on incoming/outgoing mail
  and for adding new subcommands.

- add Autocrypt-Gossip headers to mails with multiple recipients.

- parse gossip headers with the bot.

- refine recommendations and add command line call

- add way to add subcommands from a plugin

- moved repo to hpk42/py-autocrypt and refined entry pages to link
  to new IRC channel and mailing list and describe the aims.

- removed "init" subcommand.  you can now directly use "add-account".

- completely revamped internal storage to use append-only logs.
  all state changes (and in particular Autocrypt header processing)
  is tracked in immutable entries.

- with gpg2 we now internally use a hardcoded passphrase to avoid
  problems with gpg-2.1.11 on ubuntu 16.04 which does not seem
  to allow no-passphrase operations very well.

- #22 introduce account.encrypt_mime and account.decrypt_mime API
  (not yet exposed to cmdline).

- make tests work against gpg 2.0.21, gpg-2.1.11 (and likely higher
  versions but those are hard to custom-build on ubuntu or older debian
  machines)

- introduce decrypt/encrypt support for the bot and implement
  the autocrypt Level 1 recommendation algorithm for determining
  if encryption should happen or not.



0.7.0
-------

- adapt Autocrypt header attribute names, parsing and processing to
  new Level 1 spec

- add "pgpy" backend but do not activate it yet because current pgpy
  versions aren ot compatible enough to gpg's crypto.

- change "sendmail" and "process-outoing" commands to not add autocrypt
  headers if no account can be determined for a mail.

- add first version of "claimchain" code which py-autocrypt is to
  use for its internal key management.  Claimchains are an append-only
  log of claims about cryptographic key material.


0.3
---

- initial "autocrypt" command line client with subcommands.

- the internally used API is unstable as of now
  but you can glimpse from the tests how to use
  it.

