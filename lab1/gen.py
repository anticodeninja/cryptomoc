#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import random
import subprocess

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.dirname(HERE))

import common  # noqa

MASKS = [
    'Наверно, ваш код: {0}',
    'Но также возможно ваш код: {0}',
    'Но не исключено, что: {0}'
]

students = common.load_students()

if os.path.exists('list.csv'):
    passwords = [x for x in common.load_csv('list.csv')]
else:
    passwords = [[x.name, ''] for x in students]

for i, student in enumerate(students):
    print('Gen {0}: {1}'.format(i + 1, student))

    if len(passwords[i][1]) > 0:
        print('already generated')
        continue

    passwords[i][1] = common.gen_pass()
    correct = random.choice(MASKS)
    for j, mask in enumerate(MASKS):
        filename = 'file{0}_{1}.bin'.format(i + 1, j)
        code_file = open('temp', 'w')
        print(mask.format(passwords[i][1]), file=code_file)
        code_file.close()

        subprocess.check_call(['gpg', '--batch', '--yes',
                               '--output', filename, '--clear-sign', 'temp'])
        os.unlink('temp')

        if mask == correct:
            continue

        code_file = open(filename, 'r')
        content = code_file.read()
        code_file.close()

        content = content.replace(passwords[i][1], common.gen_pass())

        code_file = open(filename, 'w')
        code_file.write(content)
        code_file.close()


common.save_csv('list.csv', passwords)
