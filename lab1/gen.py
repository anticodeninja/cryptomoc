#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import subprocess
import os

ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890'
MASKS = [
    'Наверно, ваш код: {0}',
    'Но также возможно ваш код: {0}',
    'Но не исключено, что: {0}'
]
STUDENTS = 1
PASS_LEN = 8


def genpass(length):
    return ''.join(random.choice(ALPHABET) for x in range(length))


passwords = open('list.rst', 'w')
for i in range(STUDENTS):
    print('Gen {0}'.format(i))
    correct = random.choice(MASKS)
    for j, mask in enumerate(MASKS):
        password = genpass(PASS_LEN)
        filename = 'file{0}_{1}.bin'.format(i, j)
        code_file = open('temp', 'w')
        print(mask.format(password), file=code_file)
        code_file.close()

        subprocess.check_call(['gpg', '--batch', '--yes',
                               '--output', filename, '--clear-sign', 'temp'])

        if mask != correct:
            code_file = open(filename, 'r')
            content = code_file.read()
            code_file.close()

            content = content.replace(password, genpass(PASS_LEN))

            code_file = open(filename, 'w')
            code_file.write(content)
            code_file.close()
        else:
            print(password, file=passwords)

os.unlink('temp')
