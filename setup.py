import os
from setuptools import setup

def main():
    with open(os.path.join("muacrypt", "__init__.py")) as f:
        for line in f:
            if "__version__" in line.strip():
                version = line.split("=", 1)[1].strip().strip('"')
                break

    with open("README.rst") as f:
        long_desc = f.read()

    setup(
        name='muacrypt',
        description='support tool and API for Autocrypt mail agents',
        long_description = long_desc,
        version=version,
        url='https://muacrypt.readthedocs.io',
        license='MIT license',
        platforms=['unix', 'linux', 'osx', 'cygwin', 'win32'],
        author='holger krekel and the muacrypt team',
        author_email='holger@merlinux.eu',
        classifiers=['Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: MIT License',
                     'Operating System :: POSIX',
                     'Operating System :: MacOS :: MacOS X',
                     'Topic :: Utilities',
                     'Intended Audience :: Developers',
                     'Programming Language :: Python'],
        packages=['muacrypt', 'test_muacrypt'],
        entry_points='''
            [console_scripts]
            muacrypt=muacrypt.cmdline:muacrypt_main
        ''',
        install_requires = ["click>=6.0", "six", "attrs", "pluggy", "termcolor", "execnet"],
        zip_safe=False,
    )

if __name__ == '__main__':
    main()

