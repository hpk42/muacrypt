import os
from setuptools import setup

def main():
    with open(os.path.join("autocrypt", "__init__.py")) as f:
        for line in f:
            if "__version__" in line.strip():
                version = line.split("=", 1)[1].strip().strip('"')
                break

    with open("README.rst") as f:
        long_desc = f.read()

    setup(
        name='autocrypt',
        description='Autocrypt: E-mail Encryption for Everyone example implementation',
        long_description = long_desc,
        version=version,
        url='https://autocrypt.org',
        license='MIT license',
        platforms=['unix', 'linux', 'osx', 'cygwin', 'win32'],
        author='holger krekel and the autocrypt team',
        author_email='holger@merlinux.eu',
        classifiers=['Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: MIT License',
                     'Operating System :: POSIX',
                     'Operating System :: MacOS :: MacOS X',
                     'Topic :: Utilities',
                     'Intended Audience :: Developers',
                     'Programming Language :: Python'],
        packages=['autocrypt'],
        entry_points='''
            [console_scripts]
            autocrypt=autocrypt.cmdline:autocrypt_main
            examplel1=autocrypt.examplel1:main
        ''',
        install_requires = ["click>=6.0", "six", "PGPy>=0.4.1", "emailpgp"],
        zip_safe=False,
    )

if __name__ == '__main__':
    main()
