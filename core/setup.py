import os
from setuptools import setup
from autocrypt import __version__

def main():
    # with open(os.path.join("autocrypt", "__init__.py")) as f:
    #     for line in f:
    #         if "__version__" in line.strip():
    #             version = line.split("=", 1)[1].strip().strip('"')
    #             break

    setup(
        name='autocrypt',
        description='Autocrypt: E-mail Encryption for everyone example \
                     implementation',
        version=__version__,
        url='https://autocrypt.org',
        license='MIT license',
        platforms=['unix', 'linux', 'osx', 'cygwin', 'win32'],
        author='the Autocrypt team',
        author_email='autocrypt at lists.mayfirst.org',
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
        ''',
        install_requires=[
            "click>=6.0",
             "six"
        ],
        dependency_links=[
            "https://github.com/SecurityInnovation/PGPy.git@\
             @release/0.4.1#egg=PGPy-0.4.1"
            ],
        extras_require={
            'dev': ['ipython', 'pyflakes', 'pep8'],
            'test': ['coverage', 'coveralls', 'codecov', 'tox',
                     'pytest', 'pytest-localserver', 'pytest-cov'],
        },
        zip_safe=False,
    )

if __name__ == '__main__':
    main()

