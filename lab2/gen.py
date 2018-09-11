#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.dirname(HERE))

import common  # noqa

MASK = 'Ваш код: {0}'
students = common.load_students()

if os.path.exists('list.csv'):
    passwords = [x for x in common.load_csv('list.csv')]
else:
    passwords = [[x.name, ''] for x in students]

for i, student in enumerate(students):
    print('Gen {0}: {1}'.format(i + 1, student))

    if len(student.keybase) == 0:
        print('has no keybase account')
        continue

    if len(passwords[i][1]) > 0:
        print('already generated')
        continue

    passwords[i][1] = common.gen_pass()
    source_filename = 'file{0}.bin'.format(i + 1)
    target_filename = source_filename + '.gpg'
    code_file = open(source_filename, 'w')
    print(MASK.format(passwords[i][1]), file=code_file)
    code_file.close()

    subprocess.check_call(['gpg', '--trust-model', 'always',
                           '-r', student.fingerprint,
                           '-z', '0', '-e', source_filename])
    subprocess.check_call(['./broke.py', target_filename])

common.save_csv('list.csv', passwords)
