muacrypt: Help mail agents manage Autocrypt encryption
======================================================

muacrypt provides a command line tool and a Python API to help
mail agents, both user and server-side, integrate and manage automated
e-mail end-to-end encryption with https://autocrypt.org.
The project was so far mainly developed by holger krekel (@hpk42)
and Azul (@azul) whose work is funded by the European Commission
through the `NEXTLEAP <https://nextleap.eu>`_ research project
on decentralized messaging.
The NEXTLEAP project is concerned with researching and developing
secure identity and e2e-encryption protocols and
aims to contribute to securing Autocrypt against active attacks.

Aims and goals
------------------------

- Automatically tested `Autocrypt Level 1
  <https://autocrypt.org/level1.html>`_ compliant API and command line tool,
  for use by mail user agents (MUAs) and remailers.

- an extendable architecture with plugins such as
  `muacryptcc <https://github.com/nextleap-project/muacryptcc>`_ which
  implements the `decentralized ClaimChain key consistency protocol
  <https://claimchain.github.io/>`_.

- a `kappa-style architecture
  <http://milinda.pathirage.org/kappa-architecture.com/>`_ for storing
  state in an append-only log which is addressable through immutable hashes.


Documentation, getting started
------------------------------

.. toctree::
   :maxdepth: 1

   install
   cmdline
   api
