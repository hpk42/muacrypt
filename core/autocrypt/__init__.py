# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

try:
    from _version import version
except ImportError:
    try:
        from setuptools_scm import get_version
        version = get_version()
    except (ImportError, LookupError):
        version = "0.3.1"

__version__ = version
__author__ = "Autocrypt team"
__author_mail__ = "autocrypt@lists.mayfirst.org"
__description__ = "Autocrypt: E-mail Encryption for Everyone example \
                   implementation"
__long_description__ = "."
__website__ = 'https://github.com/autocrypt/py-autocrypt'
__documentation__ = 'http://py-autocrypt.readthedocs.io/en/' + __version__
__authors__ = []
__copyright__ = """Copyright (C) 2016-2017 Autocrypt team
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
For details see the LICENSE file distributed along this program."""

__license__ = """
    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
