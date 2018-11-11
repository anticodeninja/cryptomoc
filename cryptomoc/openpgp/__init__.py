#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
1. Преподаватель посылает файл fileN.bin.pgp. Это файл зашифрованный открытым
   ключем студента, но к сожалению, побившийся в результате передачи.
2. Необходимо изучить структуру opengpg контейнера и исправить его содержимое,
   а затем расшифровать файл и достать оттуда свой код, который нужно отправить
   обратно.
3. Если текст сообщения содержит корректный код, сообщение корректно
   зашифровано и подписано, то лабораторная считается засчитанной.
"""

import os
import random
import subprocess
import cryptomoc.common as common

_M = common.module_file(__name__)
VARIANTS_DB = 'variants.csv'
MASK = 'Ваш код: {0}'

TAGS = {
    0: 'Reserved',
    1: 'Public-Key Encrypted Session Key Packet',
    2: 'Signature Packet',
    3: 'Symmetric-Key Encrypted Session Key Packet',
    4: 'One-Pass Signature Packet',
    5: 'Secret-Key Packet',
    6: 'Public-Key Packet',
    7: 'Secret-Subkey Packet',
    8: 'Compressed Data Packet',
    9: 'Symmetrically Encrypted Data Packet',
    10: 'Marker Packet',
    11: 'Literal Data Packet',
    12: 'Trust Packet',
    13: 'User ID Packet',
    14: 'Public-Subkey Packet',
    17: 'User Attribute Packet',
    18: 'Sym. Encrypted and Integrity Protected Data Packet',
    19: 'Modification Detection Code Packet',
}

PKEY_ALGO = {
    1: 'RSA (Encrypt or Sign)',
}

TRASH_BLOCKS = [
    [0xC4, 0x06, 0xDE, 0xAD, 0xDE, 0xAD, 0xBE, 0xEF],
    [0xCA, 0x04, 0xDE, 0xAD, 0xBE, 0xEF],
    [0xCB, 0x02, 0xBE, 0xEF],
    [0xCD, 0x06, 0xDE, 0xAD, 0xDE, 0xAD, 0xBE, 0xEF],
]


class OpenPgpContainer:

    def __init__(self, filename):
        self.headers_start = []
        with open(filename, 'rb') as source_file:
            self.data = [x for x in source_file.read()]
        index = 0
        while index < len(self.data):
            index = self.parse_header(index)

    def parse_header(self, index):
        print('Chunk, pos:', index,
              'data:', common.to_hex(self.data[index:index+32]))

        header_offset = index
        self.headers_start.append(header_offset)
        assert self.data[index] & 0x80 != 0x00, 'It is not OpenPGP format'

        new_header_format = self.data[index] & 0x40 != 0x00
        if new_header_format:
            packet_tag = self.data[index] & 0x3F
            index += 1

            if self.data[index] < 192:
                packet_length = self.data[index]
                index += 1
            elif self.data[index] < 224:
                packet_length = ((self.data[index] - 192) << 8) +\
                                self.data[index + 1] + 192
                index += 2
            else:
                raise NotImplementedError(
                    'Packet length format is not supported')
        else:
            packet_tag = (self.data[index] & 0x3C) >> 2
            length_type = self.data[index] & 0x03
            index += 1

            if length_type == 0:
                packet_length = self.data[index]
                index += 1
            elif length_type == 1:
                packet_length = (self.data[index] << 8) + self.data[index + 1]
                index += 2
            else:
                raise NotImplementedError(
                    'Packet length format is not supported')

        start_offset = index
        print('Tag:', packet_tag, TAGS.get(packet_tag, '**UNKNOWN**'))
        print('Length:', packet_length)

        if packet_tag == 1:
            print('Packet version:', self.data[index])
            index += 1
            print('KeyId:', common.to_hex(self.data[index:index+8]))
            index += 8
            print('PkeyAlgo:', PKEY_ALGO.get(self.data[index], 'unknown'))
            index += 1
        elif packet_tag == 18:
            encrypted_block_offset = header_offset
            print('Packet version:', self.data[index])
            index += 1
        elif TAGS.get(packet_tag, None) is not None:
            print('Parsing is not supported')
        else:
            raise NotImplementedError('Packet tag is not supported')

        index = start_offset + packet_length
        return index


def _broke(filename):
    container = OpenPgpContainer(filename)

    target_offset = random.choice(container.headers_start)
    target_block = random.choice(TRASH_BLOCKS)
    broken_data = container.data[:target_offset] +\
        target_block +\
        container.data[target_offset:]

    with open(filename, 'wb') as target_file:
        target_file.write(bytes(broken_data))


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

        if len(student.keybase) == 0:
            print('skipped, keybase account is not configured')
            continue

        if len(passwords[i][1]) > 0:
            print('skipped, already generated')
            continue

        print('generating...')
        passwords[i][1] = common.gen_pass()
        source_filename = 'file{0}.bin'.format(i + 1)
        target_filename = source_filename + '.gpg'
        code_file = open(_M(source_filename), 'w')
        print(MASK.format(passwords[i][1]), file=code_file)
        code_file.close()

        subprocess.check_call(['gpg', '--trust-model', 'always', '--yes',
                               '-r', student.fingerprint,
                               '-z', '0', '-e', _M(source_filename)])
        os.unlink(_M(source_filename))
        _broke(_M(target_filename))

        print('checking...')
        container = OpenPgpContainer(_M(target_filename))
        print('generated')

    common.save_csv(_M(VARIANTS_DB), passwords)

    print('Created students tasks')


def check(mask):
    """Check student answer"""

    common.check_code(_M(VARIANTS_DB), mask)
