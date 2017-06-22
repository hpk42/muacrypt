
Autocrypt Python API Reference
==============================

.. note::

    While the code documented here is automatically tested
    against gpg, gpg2, python2 and python3, all of the API here
    is subject to change during ``0.x`` releases. This doesn't
    mean that everything will actually change.


.. autosummary::

   autocrypt.account
   autocrypt.bot
   autocrypt.mime
   autocrypt.bingpg
   autocrypt.pgpycrypto

account module
--------------

.. automodule:: autocrypt.account
    :members:

bot module
----------

.. automodule:: autocrypt.bot
    :members:

mime module
-----------

.. automodule:: autocrypt.mime
    :members:

bingpg module
--------------

.. automodule:: autocrypt.bingpg
    :members:

pgpycrypto module
------------------

.. note::

  The "pgpy" backend is tested but not used not used yet because
  pgpy==0.4.1 are not sufficiently substituting gpg functionality yet.

.. automodule:: autocrypt.pgpycrypto

claimchain module
-----------------

.. note::

  The claimchain module is not required for, or part of Autocrypt Level 1.
  It is a prototype and experimental effort which azul and hpk are playing
  with to allow for helping users protect against MITM attacks or, conversely,
  to make it more costly for providers or network-level attackers who want
  to subvert communications.   This is part of their involvement on the
  NEXTLEAP EU project.

  Eventually claimchains could be integrated as a Plugin but this requires an
  according pluginization of py-autocrypt which is better to do after the prototyping
  stabilizes.

.. automodule:: autocrypt.claimchain
