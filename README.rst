muacrypt: Autocrypt encryption for mail agents
==============================================

``muacrypt`` is a support tool for implementing `Autocrypt Level 1
<https://autocrypt.org/autocrypt-spec-1.0.0.pdf>`_ compliant mail agents.
Autocrypt state is kept in an one more accounts which process and produce
autocrypt headers from incoming and outgoing e-mail. Each account is
tied to a set of e-mail addresses, specified as a regular expression.
Functionality is exposed through a command line tool ``muacrypt`` and a
Python api obtained through ``import muacrypt``. There is an evolving plugin
architecture which allows to add and modify behaviour of muacrypt.

This README is intended to help contributors to get setup with running
tests and using the command line tool.  The online docs at

https://muacrypt.readthedocs.io

contain more documentation about overall goals of the project.

testing
-------

To use the code and run tests you need to have installed:

- the command line client "gpg", optionally "gpg2",
  available through "gnupg" and "gnugp2" on debian.

- something to speed up gpg key creation, e.g.
  by installing "rng-tools" on debian.

- python2.7 and python3.5 including headers
  ("python2.7-dev" and "python3.5-dev" on debian).

- "tox" to run automated tests ("python-tox" on Debian)

In one installation command on Debian::

    apt install gnupg2 rng-tools python2.7-dev python3.5-dev python-tox

Afterwards you can run all tests::

    $ tox


installation
------------

You'll need the command line client "gpg", optionally "gpg2",
available through "gnupg" and "gnugp2" on debian.

To install the muacrypt command line tool you can install
the "muacrypt" python package into your virtual environment
of choice.  If you don't know about python's virtual environments
you may just install the debian package "python-pip" and then
use "pip" to install the muacrypt library and command line too::

    $ pip install --user muacrypt

The ``muacrypt`` command line tool will be installed into
``$HOME/.local/bin`` which needs to be in your ``PATH``.

installation for development
++++++++++++++++++++++++++++

If you plan to work/modify the sources and have
a github checkout we strongly recommend to create
and activate a python virtualenv and then once use
**pip without sudo in edit mode**::

    $ virtualenv venv
    $ source venv/bin/activate
    $ pip install -e .

Changes you subsequently make to the sources will be
available without further installing the muacrypt
package again.


running the command line
++++++++++++++++++++++++

After installation simply run the main command::

    muacrypt

to see available sub commands and options.  Start by
initializing an Autocrypt account which will maintain
its own keyring and not interfere with your possibly
existing gpg default keyring::

    $ muacrypt init

Afterwards you can create an Autocrypt header
for an email address::

    $ muacrypt make-header x@example.org

You can process and integrate peer's Autocrypt
keys by piping an email message into the ``process-incoming`` subcommand::

    $ muacrypt process-incoming <EMAIL_MESSAGE_FILE

At any point you can show the status of your muacrypt
account::

    $ muacrypt status
