#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
История о том, что криптоконтейнеры вещь достаточно простая, необходимая в
обыденной жизни и что нет предела паранойи.
1. Необходимо придумать два пароля: pass_common и pass_shadow.
2. Необходимо создать контейнер VeraCrypt с shadow областью, используя для
   обычной и shadow-области пароли pass_common и pass_shadow, соответственно.
3. pass_common необходимо зашифровать используя публичный ключ преподавателя,
   результат шифрования необходимо сохранить в файле crypto.txt.
4. pass_shadow необходимо сохранить в файле password.txt и в обычной области
   VeraCrypt контейнера.
5. Необходимо найти в интернете картинку с понравившимся котиком, скачать и
   переименовать в cat.jpg и сохранить в shadow области VeraCrypt контейнера.
6. Необходимо прислать преподавателю два файла: container (VeraCrypt) и
   crypto.txt (с зашифрованным pass_common).
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
