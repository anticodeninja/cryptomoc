#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
История о том, что blockchain стал настолько трендовым, что уже нельзя получить
хорошую оценку не намайнив несколько блоков. Но поскольку для написания
полноценного блокчейна надо написать целую кучу неинтересного кода поддержания
кучи p2p соединений ограничимся только демонстрацией концепции Proof-of-Work.
1. Преподаватель дает адрес сервера, который симулирует блокчейн сеть. Протокол
   крайне прост: а) команда TAKE служит для того, чтобы сервер отправил текущую
   цепочку блоков; б) команда PUSH<block> служит для того, чтобы сервер добавил
   новый блок в конец цепочки.
2. Собственно этого и кусочка кода проверки нового блока, должно быть
   достаточно, чтобы намайнить достаточное количество блоков, для получения
   хорошей оценки.
"""

import ctypes
import codecs
import json
import collections
import os
import socket
import subprocess
import time
import cryptomoc.common as common

from distutils import ccompiler
from distutils.extension import Extension

_M = common.module_file(__name__)
_R = common.resource_file(__name__)

BLOCK_SIZE = 256
CHAIN_FILE = _M('chain')
WALLETS_FILE = _M('wallets')

def _gen_native():
    extra_postargs = ['-fpic', '-O2', '-lcrypto']

    compiler = ccompiler.new_compiler()
    objects = compiler.compile([_R('native.c')], extra_postargs=extra_postargs)
    compiler.link_shared_object(objects, _M('native.so'), extra_postargs=extra_postargs)

    return ctypes.CDLL(_M('native.so'))

def _connect(addr, data):
    host_addr, host_port = addr.split(':')
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host_addr, int(host_port)))

    conn.send(data)
    buf = b''  # Buffer to hold received client data
    while True:
        data = conn.recv(4096)
        if data:
            buf += data
        else:
            break

    return buf


def _get_blocks(addr):
    buf = _connect(addr, 'TAKE'.encode('utf8'))
    chain = []
    for i in range(len(buf) // BLOCK_SIZE):
        chain.append(buf[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE])
    return chain


def gen():
    """Генерирует набор кошельков студентов"""

    common.check_env()
    common.create_module(__name__)
    native = _gen_native()

    students = common.load_students()
    wallets = collections.OrderedDict()
    block = ctypes.create_string_buffer(BLOCK_SIZE)
    for i, student in enumerate(students):
        print('Gen {0}: {1} ['.format(i + 1, student), end='')

        key_name = _M('student{}.key'.format(i+1))
        if not os.path.exists(key_name):
            print('k', end='')
            subprocess.check_call([
                'openssl', 'ecparam', '-genkey', '-name', 'secp256k1',
                '-noout', '-out', key_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        pub_name = _M('student{}.pub'.format(i+1))
        if not os.path.exists(pub_name):
            print('p', end='')
            subprocess.check_call([
                'openssl', 'ec', '-pubout',
                '-in', key_name, '-out', pub_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        enc_name = _M('student{}.enc'.format(i+1))
        if not os.path.exists(enc_name) and len(student.keybase) != 0:
            print('e', end='')
            subprocess.check_call([
                'gpg', '--trust-model', 'always', '--yes',
                '-r', student.fingerprint,
                '--output', enc_name, '--encrypt', key_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        native.write_target(block, pub_name.encode('utf8'));
        wallets[student.name] = ''.join('{:02x}'.format(x) for x in block[96:160])

        print('] generated')

    with open(WALLETS_FILE, 'w', encoding='utf8') as wallets_file:
        json.dump(wallets, wallets_file, ensure_ascii=False)

    print('Created students tasks')


def get_blocks(addr):
    """Получает текущую цепочку блоков с сервера"""
    native = _gen_native()
    chain = _get_blocks(addr)
    print('Length: {}'.format(len(chain)))
    for el in chain:
        native.print_block(el)


def get_balance(addr):
    """Получает текущую цепочку блоков с сервера и вычисляет баланс счетов
    студентов"""

    with open(WALLETS_FILE, 'r', encoding='utf8') as wallets_file:
        wallets = json.load(wallets_file)
    balances = {wallet: 5 for wallet in wallets.values()}

    chain = _get_blocks(addr)
    print('Length: {}'.format(len(chain)))
    for el in chain:
        balances[''.join('{:02x}'.format(x) for x in el[32:96])] -= 1
        balances[''.join('{:02x}'.format(x) for x in el[96:160])] += 1

    for name in sorted(wallets.keys()):
        print('{:40} = {}'.format(name, balances[wallets[name]]))


def push_block(addr, from_key, to_pub):
    """Добавляет новый блок на сервер"""
    native = _gen_native()
    block = ctypes.create_string_buffer(BLOCK_SIZE)
    chain = _get_blocks(addr)
    prev_block_id = chain[-1][:16] if len(chain) > 0 else bytes([0] * 16)

    start = time.time()
    native.write_prev_block_id(block, prev_block_id);
    native.write_target(block, _M(to_pub).encode('utf8'));
    native.write_source_and_sign(block, _M(from_key).encode('utf8'));
    native.solve_digest(block)
    end = time.time()
    print('Spent: {}'.format(end - start))
    native.print_block(block)

    print(_connect(addr, 'PUSH'.encode('utf8') + block).decode('utf8'))


def server(listen_port):
    """Запускает сервер"""
    native = _gen_native()
    chain = []
    if os.path.exists(CHAIN_FILE):
        with open(chain_filename, 'rb') as chain_file:
            while True:
                block = chain_file.read(BLOCK_SIZE)
                if not block:
                    break
                chain.append(block)

    with open(WALLETS_FILE, 'r', encoding='utf8') as wallets_file:
        targets = [bytes.fromhex(x) for x in json.load(wallets_file).values()]

    print('Blocks: {}'.format(len(chain)))
    print('Targets: {}'.format(len(targets)))

    bindsocket = socket.socket()
    bindsocket.bind(('0.0.0.0', int(listen_port)))
    bindsocket.listen(1)

    prev_block_id = chain[-1][0:16] if len(chain) > 0 else bytes([0] * 16)
    prev_attempt = time.time()

    while True:
        print("Waiting for client")
        conn = None
        try:
            conn, fromaddr = bindsocket.accept()
            print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))

            buf = b''  # Buffer to hold received client data
            while True:
                data = conn.recv(4096)
                if data:
                    buf += data
                else:
                    break

                if len(buf) >= 4:
                    if buf[0:4] == b'TAKE':
                        break
                    elif buf[0:4] == b'PUSH':
                        if len(buf) >= 260:
                            break
                    else:
                        break

            if buf[0:4] == b'TAKE' and len(buf) == 4:
                print('Sending blocks {}'.format(len(chain)))
                for el in chain:
                    conn.send(el)
                continue

            if buf[0:4] != b'PUSH' and len(buf) == 260:
                print('Incorrect {} {}'.format(len(buf), buf[0:4]))
                conn.send('Incorrect command'.encode('utf8'))
                continue

            if (time.time() - prev_attempt) < 5:
                conn.send('Too often attempts'.encode('utf8'))
                continue
            prev_attempt = time.time()

            block = buf[4:]
            if not native.check_block(block, prev_block_id):
                conn.send('Incorrect block'.encode('utf8'))
                continue

            if block[96:160] not in targets:
                conn.send('Unknown target'.encode('utf8'))
                continue

            chain.append(block)
            with open(CHAIN_FILE, 'ab') as chain_file:
                chain_file.write(block)
            prev_block_id = block[:16]

            print('Append block')
            conn.send('Block successfully append'.encode('utf8'))

        except Exception as e:
            print(e)
        finally:
            print("Closing connection")
            common.safe_exec(lambda: conn and conn.shutdown(socket.SHUT_RDWR))
            common.safe_exec(lambda: conn and conn.close())
