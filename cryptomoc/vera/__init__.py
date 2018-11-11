#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TODO
"""

import os
import subprocess
import cryptomoc.common as common

_M = common.module_file(__name__)
CONTAINER = 'container'
MOUNTED = 'mounted'
CRYPTO_FILE = 'crypto.txt'
PASSWORD_FILE = 'password.txt'
CAT_IMAGE = 'cat.jpg'


def gen():
    """Generate test env"""

    common.check_env()
    common.create_module(__name__)
    print('Created env')


def check():
    """Check student files"""

    os.makedirs(_M(MOUNTED), exist_ok=True)

    subprocess.check_call([
        'gpg', '-d', '--yes', '-o', _M(PASSWORD_FILE), _M(CRYPTO_FILE)])
    common_pass = open(_M(PASSWORD_FILE), 'r').read().strip()
    print('Common pass:', common_pass)

    subprocess.check_call([
        'veracrypt', '-t', '-p', common_pass, '-k', '', '--pim=0',
        '--protect-hidden=no', _M(CONTAINER), _M(MOUNTED)])
    print('Common storage mounted')

    try:
        shadow_filename = os.path.join(_M(MOUNTED), PASSWORD_FILE)
        shadow_pass = open(shadow_filename, encoding='cp1251').read().strip()
        print('Shadow pass:', shadow_pass)
    except Exception as e:
        print(e)
        print(', '.join(os.listdir(_M(MOUNTED))))
    finally:
        subprocess.check_call(['veracrypt', '-d', _M(MOUNTED)])
        print('Common storage unmounted')

    subprocess.check_call([
        'veracrypt', '-t', '-p', shadow_pass, '-k', '', '--pim=0',
        '--protect-hidden=no', _M(CONTAINER), _M(MOUNTED)])
    print('Shadow storage mounted')
    try:
        subprocess.check_call(['feh', os.path.join(_M(MOUNTED), CAT_IMAGE)])
    except Exception as e:
        print(e)
        print(', '.join(os.listdir(_M(MOUNTED))))
    finally:
        subprocess.check_call(['veracrypt', '-d', _M(MOUNTED)])
        print('Shadow storage unmounted')
