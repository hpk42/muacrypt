0.7.0
-------

- adapt Autocrypt header attribute names, parsing and processing to
  new Level 1 spec

- add "pgpy" backend but do not activate it yet because current pgpy
  versions aren ot compatible enough to gpg's crypto.

- change "sendmail" and "process-outoing" commands to not add autocrypt
  headers if no identity can be determined for a mail.

- add first version of "claimchain" code which py-autocrypt is to
  use for its internal key management.  Claimchains are an append-only
  log of claims about cryptographic key material.


0.3
---

- initial "autocrypt" command line client with subcommands.

- the internally used API is unstable as of now
  but you can glimpse from the tests how to use
  it.

