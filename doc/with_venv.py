""" helper to generate html and autodoc python docs with a temporary
virtualenv where we install the sources in edit mode.
"""
from __future__ import unicode_literals
import os
import sys
import subprocess


if __name__ == "__main__":
    venvdir = sys.argv[1]
    bindir = os.path.join(venvdir, "bin")
    assert venvdir
    os.environ["PATH"] = bindir + os.pathsep + os.environ["PATH"]
    if not os.path.exists(venvdir):
        subprocess.check_call(["virtualenv", "-p", sys.executable, venvdir])
        subprocess.check_call(["pip", "install", "-e", "../core"])

    # poor people's virtualenv activate
    sys.exit(subprocess.call(sys.argv[2:]))
