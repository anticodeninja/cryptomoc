#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import random

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

headers_start = []


def to_hex(data):
    return ":".join("{:02x}".format(c) for c in data)


def parse_header(data, index):
    print('Chunk, pos:', index, 'data:', to_hex(data[index:index+32]))

    header_offset = index
    headers_start.append(header_offset)
    assert data[index] & 0x80 != 0x00, 'It is not OpenPGP format'

    new_header_format = data[index] & 0x40 != 0x00
    if new_header_format:
        packet_tag = data[index] & 0x3F
        index += 1

        if data[index] < 192:
            packet_length = data[index]
            index += 1
        elif data[index] < 224:
            packet_length = ((data[index] - 192) << 8) + data[index + 1] + 192
            index += 2
        else:
            raise NotImplementedError('Packet length format is not supported')
    else:
        packet_tag = (data[index] & 0x3C) >> 2
        length_type = data[index] & 0x03
        index += 1

        if length_type == 0:
            packet_length = data[index]
            index += 1
        elif length_type == 1:
            packet_length = (data[index] << 8) + data[index + 1]
            index += 2
        else:
            raise NotImplementedError('Packet length format is not supported')

    start_offset = index
    print('Tag:', packet_tag, TAGS.get(packet_tag, '**UNKNOWN**'))
    print('Length:', packet_length)

    if packet_tag == 1:
        print('Packet version:', data[index])
        index += 1
        print('KeyId:', to_hex(data[index:index+8]))
        index += 8
        print('PkeyAlgo:', PKEY_ALGO.get(data[index], 'unknown'))
        index += 1
    elif packet_tag == 18:
        encrypted_block_offset = header_offset
        print('Packet version:', data[index])
        index += 1
    elif TAGS.get(packet_tag, None) is not None:
        print('Parsing is not supported')
    else:
        raise NotImplementedError('Packet tag is not supported')

    index = start_offset + packet_length
    return index


source_file = open(sys.argv[1], 'rb')
source_data = [x for x in source_file.read()]

print(to_hex(source_data))
print(len(source_data))
print('========================')

index = 0
while index < len(source_data):
    index = parse_header(source_data, index)
print('========================')

target_offset = random.choice(headers_start)
target_block = random.choice(TRASH_BLOCKS)
source_data = source_data[:target_offset] + target_block +\
              source_data[target_offset:]

index = 0
while index < len(source_data):
    index = parse_header(source_data, index)
print('========================')

target_file = open(sys.argv[1], 'wb')
target_file.write(bytes(source_data))
