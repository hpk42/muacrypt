Autocrypt support for mail agents
=================================

py-autocrypt provides a command line tool and a Python API to help
mail agents integrate Autocrypt support and more.

See :doc:`install` for getting pip-installed with the ``autocrypt``
package released on the Python Package Index.

Here are some preliminary underlying aims and goals:

- `Autocrypt Level 1 compliant functionality
  <https://github.com/hpk42/py-autocrypt/milestone/1>`_ for use by mail user agents (MUAs)

- integrate with re-mailers and other specialized server-side mail agents

- provide support for debugging error cases, easy deployment of fixes

- implement out-of-band verification and claimchains variants (see https://nextleap.eu)

The project was so far mainly developed by holger krekel (hpk42)
with some participation/contributions from dkg, juga0 and azul.
Holger work was and is partially funded by the European Commission
through the `NEXTLEAP <https://nextleap.eu>`_ research project on
decentralized messaging.

Note that this repository got moved away from the https://github.com/autocrypt
umbrella because that is mainly about the Autocrypt specification efforts
while MUA/mail related implementations happen through different social
arrangements.

.. toctree::
   :hidden:

   install
   cmdline
   diagrams
   api
