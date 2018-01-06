muacrypt: help mail agents manage automated encryption
======================================================

.. note::

    There is a `tentative name change consideration
    <https://github.com/hpk42/py-autocrypt/issues/34>`_ for this project
    which is to result in change of links, names.

py-autocrypt provides a command line tool and a Python API to help
mail agents, both user and server-side, integrate and manage automated
e-mail end-to-end encryption.

Aims and goals
--------------

- `Autocrypt Level 1 compliant functionality
  <https://github.com/hpk42/py-autocrypt/milestone/1>`_ for use by mail user agents (MUAs)

- integrate with mailman3 and other server-side mailing software

- support debugging error situations, easy deployment of fixes

- implement out-of-band verification, with
  claimchains variants (see https://nextleap.eu)
  and a `kappa-style architecture <http://milinda.pathirage.org/kappa-architecture.com/>`_.


Background
----------

The project was so far mainly developed by holger krekel (@hpk42)
with some participation/contributions from @dkg, @juga0 and @azul.
Holger's work was and is partially funded by the European Commission
through the `NEXTLEAP <https://nextleap.eu>`_ research project on
decentralized messaging.

Note that this repository got moved away from the https://github.com/autocrypt
umbrella because that is mainly about the Autocrypt specification efforts itself
while MUA-side implementations happen through different social
arrangements.

.. toctree::
   :hidden:

   install
   cmdline
   diagrams
   api
