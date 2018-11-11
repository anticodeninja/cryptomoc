from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'LICENSE.txt'), encoding='utf-8') as f:
    license = f.read()
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='cryptomoc',
    version='0.0.1',

    description='',
    long_description=long_description,

    url='https://github.com/anticodeninja/cryptomoc',

    maintainer='anticodeninja',
    author='anticodeninja',

    license=license,

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=[],

    entry_points={
        'console_scripts': [
            'cryptomoc=cryptomoc:main',
        ],
    },
)
