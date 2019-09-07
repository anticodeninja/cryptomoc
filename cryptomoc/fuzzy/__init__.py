#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
История о том, что ошибки есть везде и не всегда их можно найти пользуясь
здравым смыслом. А там где нет здравого смысла есть метод грубой силы -
fuzzing.
1. Преподаватель дает два файла cli.py и native.so. Внутри native.so находится
   простая функция, которая делает вид, что проводит валидацию JSON, но на
   самом деле хранит в теле секретный код.
2. Подать на вход валидный JSON легко, но код 0x1FEA4BEEF скажет тебе что путь
   выбран не тот.
3. Подать на вход невалидный JSON не много сложней, но код 0x1DEADBEEF скажет
   тебе, что опять ты в тупике.
4. Легко ли будет найти вход, который к корректному коду тебя приведет?
"""

import ctypes
import random
import os
import shutil
import subprocess

from distutils import ccompiler
from distutils.extension import Extension

import cryptomoc.common as common

_M = common.module_file(__name__)
_R = common.resource_file(__name__)
VARIANTS_DB = 'variants.csv'

VARIETY = 3
MAX_VARIETY = 16
NONCE_LEN = 64

class Variant:

    def __init__(self):
        self.nonce = ''.join('{:x}'.format(random.randint(0, 15)) for x in range(NONCE_LEN))
        mask = [False] * MAX_VARIETY
        for i in range(MAX_VARIETY):
            mask[i] = random.randint(0, MAX_VARIETY - i - 1) < VARIETY - sum(mask[:i])
        self.mask = sum(1 << i if mask[i] else 0 for i in range(MAX_VARIETY))


def _gen_native(variant, target, debug=None, reference=None):
    extra_postargs = ['-g0', '-O2', '-fPIC']

    macros = [
        ('MAX_VARIETY', MAX_VARIETY),
        ('NONCE', '"' + variant.nonce + '"'),
        ('NONCE_LEN', NONCE_LEN),
        ('MASK', variant.mask),
    ]

    if debug is not None: macros.append(('DEBUG', 1))
    if reference is not None: macros.append(('REFERENCE', reference))

    compiler = ccompiler.new_compiler()
    objects = compiler.compile(
        sources=[_R('native.c')],
        output_dir=_M('tmp/{}'.format(target)),
        macros=macros,
        extra_postargs=extra_postargs)
    compiler.link_shared_object(objects, target, extra_postargs=extra_postargs)
    if not debug: subprocess.check_call(['strip', target])

    native = ctypes.CDLL(target)
    native.check.restype = ctypes.c_uint64
    return target, native

def test():
    DATAS = (
        (0 <<  0, 0x00000000, 0xfea4beef, '{"valid":"json"}'),
        (1 <<  0, 0x4d70fead, 0xc7026264, '['),
        (1 <<  1, 0x291326c2, 0xa361ba0b, '{1'),
        (1 <<  2, 0x216389db, 0xab111512, '{"",'),
        (1 <<  3, 0x3cf1bd96, 0xb683215f, '{"":1:'),
        (1 <<  4, 0x19d59486, 0x93a7084f, '{"":1,', ),
        (1 <<  5, 0x522e2434, 0xd85cb8fd, '{"":[1:}'),
        (1 <<  6, 0xad4ad111, 0x27384dd8, '{"":[1\0}'),
        (1 <<  7, 0xc6d584c8, 0x4ca71801, '{"":o}'),
        (1 <<  8, 0x32d1a998, 0xb8a33551, '{"":\0}'),
        (1 <<  9, 0xe249a88e, 0x683b3447, '{"\\g:1}'),
        (1 << 10, 0x1a5e496b, 0x902cd5a2, '{"\\ugggg":1}'),
        (1 << 11, 0x6f11c5b6, 0xe563597f, '{"\0:1}'),
        (1 << 12, 0x4a3e8474, 0xc04c18bd, '{"":-f}'),
        (1 << 13, 0x0aade6c6, 0x80df7a0f, '{"":1.f}'),
        (1 << 14, 0x46c4322c, 0xccb6aee5, '{"":1.1ef}'),
        (1 << 15, 0x4600860d, 0xcc721ac4, '{"":to}'),
        (1 << (MAX_VARIETY - 1), 0x4600860d, 0xcc721ac4, '{"":to}'),
        (0x13, 0x7db64ce9, 0xf7c4d020, '[{1{'),
        (0x666, 0x3bb25f12, 0xb1c0c3db, '{1{"\\ugggg"f{"":[""},"":[1\0,"\\h}'),
    )

    variant = Variant()
    variant.nonce = '0' * NONCE_LEN
    opts = {}
    opts['debug'] = True

    counters = dict(test_passed=0, test_all=0)

    def fix_result(name, exp, real):
        passed = exp == real
        print('\033[3{}m{} exp:{:16x} real:{:16x}\033[39m'.format(2 if passed else 1, name, exp, real))

        counters['test_all'] +=1
        counters['test_passed'] += 1 if passed else 0

    for test_id, (mask, exp_ref, exp_code, data) in enumerate(DATAS):
        variant.mask = mask

        if mask:
            opts.pop('reference', None)
            opts['target'] = _M('test_{}_ref.so'.format(test_id))
            _, native = _gen_native(variant, **opts)
            code = native.check(ctypes.create_string_buffer(data.encode('ascii')), len(data))
            fix_result('REF', exp_ref, code >> 32)
            fix_result('CHK', exp_code, code & 0xFFFFFFFF)

        opts['reference'] = exp_ref
        opts['target'] = _M('test_{}_chk.so'.format(test_id))
        _, native = _gen_native(variant, **opts)
        code = native.check(ctypes.create_string_buffer(data.encode('ascii')), len(data))
        fix_result('TST', exp_code, code & 0xFFFFFFFF)

    fix_result('ALL', counters['test_all'], counters['test_passed'])


def gen():
    """Generate students tasks"""

    common.check_env()
    common.create_module(__name__)

    students = common.load_students()
    if os.path.exists(_M(VARIANTS_DB)):
        passwords = [x for x in common.load_csv(_M(VARIANTS_DB))]
    else:
        passwords = [[x.name, '', '', '', ''] for x in students]

    for i, student in enumerate(students):
        print('Gen {0}: {1} '.format(i + 1, student), end='')

        if len(passwords[i][1]) > 0:
            print('skipped, already generated')
            continue

        print('generating...')
        variant = Variant()

        target, native = _gen_native(variant, _M('ref_{}.so'.format(i + 1)), debug=True)
        code = native.check(0, 0)
        reference = code >> 32
        code = code & 0xFFFFFFFF

        passwords[i][1] = '{:08x}'.format(code)
        passwords[i][2] = '{}'.format(variant.mask)
        passwords[i][3] = '{}'.format(variant.nonce)
        passwords[i][4] = '{:08x}'.format(reference)

        target_dir = _M('stud_{}'.format(i + 1))
        target_so = os.path.join(target_dir, 'native.so')
        target_cli = os.path.join(target_dir, 'cli.py')

        os.makedirs(target_dir, exist_ok=True)
        target, native = _gen_native(variant, target_so, reference=reference)
        shutil.copyfile(_R('cli.py'), target_cli)

        print('generated')

    shutil.rmtree(_M('tmp'))
    common.save_csv(_M(VARIANTS_DB), passwords)

    print('Created students tasks')


def check(mask):
    """Check student answer"""

    common.check_code(_M(VARIANTS_DB), mask)
