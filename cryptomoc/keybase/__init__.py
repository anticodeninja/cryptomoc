#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
1. Преподаватель посылает 3 файла: fileN_0.bin, fileN_1.bin, fileN_2.bin.
   Только в одном из них корректная подпись закрытым ключем преподавателя на
   https://keybase.io. Необходимо определить какой именно это файл.
2. Надо сформировать новый файл (или просто сообщение с текстом): "Мой код:
   ########", взяв код из файла на предыдущем шаге.
3. После этого полученный файл (сообщение) следует подписать своей подписью,
   зашифровать используя публичный ключ преподователя и отправить ему в
   ответном письме.
4. Если текст сообщения содержит корректный код, сообщение корректно
   зашифровано и подписано, то лабораторная считается засчитанной.
"""

import os
import random
import subprocess
import cryptomoc.common as common

_M = common.module_file(__name__)
VARIANTS_DB = 'variants.csv'
MASKS = [
    'Наверно, ваш код: {0}',
    'Но также возможно ваш код: {0}',
    'Но не исключено, что: {0}'
]


def gen():
    """Generate students tasks"""

    common.check_env()
    common.create_module(__name__)

    students = common.load_students()
    if os.path.exists(_M(VARIANTS_DB)):
        passwords = [x for x in common.load_csv(_M(VARIANTS_DB))]
    else:
        passwords = [[x.name, ''] for x in students]

    for i, student in enumerate(students):
        print('Gen {0}: {1} '.format(i + 1, student), end='')

        if len(passwords[i][1]) > 0:
            print('skipped, already generated')
            continue

        passwords[i][1] = common.gen_pass()
        correct = random.choice(MASKS)
        for j, mask in enumerate(MASKS):
            filename = _M('file{0}_{1}.bin'.format(i + 1, j))

            code_file = open('temp', 'w')
            print(mask.format(passwords[i][1]), file=code_file)
            code_file.close()
            subprocess.check_call([
                'gpg', '--batch', '--yes',
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
        print('generated')

    common.save_csv(_M(VARIANTS_DB), passwords)

    print('Created students tasks')


def check(mask):
    """Check student answer"""

    common.check_code(_M(VARIANTS_DB), mask)
