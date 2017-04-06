#
""""""
import os
import re
import sys
iswin32 = sys.platform == "win32" or (getattr(os, '_name', False) == 'nt')


def find_executable(name):
    """ Function copied from autocrypt/bingpg.py
        return a path object found by looking at the systems
        underlying PATH specification.  If an executable
        cannot be found, None is returned. copied and adapted
        from py.path.local.sysfind.
    """
    if os.path.isabs(name):
        return name if os.path.isfile(name) else None
    else:
        if iswin32:
            paths = os.environ['Path'].split(';')
            if '' not in paths and '.' not in paths:
                paths.append('.')
            try:
                systemroot = os.environ['SYSTEMROOT']
            except KeyError:
                pass
            else:
                paths = [re.sub('%SystemRoot%', systemroot, path)
                         for path in paths]
        else:
            paths = os.environ['PATH'].split(':')
        tryadd = []
        if iswin32:
            tryadd += os.environ['PATHEXT'].split(os.pathsep)
        tryadd.append("")

        for x in paths:
            for addext in tryadd:
                p = os.path.join(x, name) + addext
                try:
                    if os.path.isfile(p):
                        return p
                except Exception:
                    pass
    return None
