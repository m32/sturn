from distutils.core import setup
README = open('README.md', 'r').read()

setup(
    name='sturn',
    version='0.1.0',
    packages=['sturn'],
    provides=['sturn'],
    requires=['Twisted'],

    author='Grzegorz Makarewicz',
    url='https://github.com/m32/sturn',

    license='MIT',

    description="TURN and STUN library",
    classifiers=[
        'Programming Language :: Python',
        'Framework :: Twisted',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: System :: Networking',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    long_description=README
)
