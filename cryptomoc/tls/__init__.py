#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
История о том, что криптография не такая уже сложная, а программы даже
относительно совместимые. Необходимо научиться извлекать ключа из keybase,
логинится на сервер через сокеты TCP, но с TLS, при этом ещё снимая трафик и
экспортируя сессионные ключи, чтобы трафик не был бесполезной горой мусора, а
его можно было проанализировать.
1. Сначала необходимо экспортировать ключи с keybase себе локально на ПК.
2. Используя openpgp2pem необходимо сконвертировать приватный ключ в PEM.
3. На основе предоставленных преподавателем корневых сертификатов (root.crt и
   root.key), с помощью openssl необходимо сгенерировать свой сертификат
   подписанный PEM ключом.
4. Используя этот сертификат надо установить TLS соединение по адресу,
   предоставленный преподавателем. При хорошем настроении у преподавателя, он
   может выдать вам код на Python.
5. Можно было бы сказать, что на этом все, но нет. Приключения только
   начинаются! Необходимо дописать свою программу, таким образом, чтобы она
   сохраняла сессионные ключи (tlslog). Опять же при хорошем настроении у
   преподавателя, он может выдать направления для движения мысли.
6. После чего, надо повторить шаг 4, снимая при этом трафик и записывая tlslog,
   проверить что Wireshark может корректно расшифровать этот трафик и
   отправить полученные файлы с именами dump.pcapng и tlslog.
"""

import ctypes
import os
import random
import re
import socket
import ssl
import subprocess
import cryptomoc.common as common

_M = common.module_file(__name__)
VARIANTS_DB = 'variants.csv'
CACHE_DB = 'cache.db'
DUMP_FILE = 'dump.pcapng'
KEYLOG_FILE = 'keylog'
MASK = 'Your code: '


def _get_rsa(fingerprint):
    p1 = subprocess.Popen(
        ['gpg', '--export', fingerprint],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=0)
    p2 = subprocess.Popen(
        ['openpgp2pem', fingerprint],
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        bufsize=0)
    p3 = subprocess.Popen(
        ['openssl', 'rsa', '-RSAPublicKey_in', '-text', '-noout'],
        stdin=p2.stdout,
        stdout=subprocess.PIPE,
        bufsize=0)
    return p3.stdout.read().decode('utf8')


def _check(cache, data):
    p = subprocess.Popen(
        ['openssl', 'x509', '-inform', 'DER', '-text', '-noout'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0)
    out, err = p.communicate(data)

    if len(err) > 0:
        return 'Cannot parse certificate'

    cert_data = out.decode('utf8')
    module = common.extract_module(cert_data)
    code = next((x[1] for x in cache if x[0] == module))

    return MASK + code if code\
        else 'Verification was not passed'


def gen():
    """Generate students tasks"""

    common.check_env()
    common.create_module(__name__)

    # TODO Add certificate chain generation here

    students = common.load_students()
    if os.path.exists(_M(VARIANTS_DB)):
        passwords = [x for x in common.load_csv(_M(VARIANTS_DB))]
    else:
        passwords = [[x.name, ''] for x in students]

    cache = []
    for i, student in enumerate(students):
        print('Gen {0}: {1} '.format(i + 1, student), end='')

        if len(student.keybase) == 0:
            print('has no keybase account')
            continue

        if len(passwords[i][1]) == 0:
            passwords[i][1] = common.gen_pass()
            print('generated')
        else:
            print('already generated')

        rsa_pub = common.extract_module(_get_rsa(student.fingerprint))
        cache.append([rsa_pub, passwords[i][1]])

    common.save_csv(_M(CACHE_DB), cache)
    common.save_csv(_M(VARIANTS_DB), passwords)

    print('Created students tasks')


def client(addr, cert):
    libssl = None
    try:
        libssl = ctypes.cdll.LoadLibrary('libssl.so.1.1')

        # size_t SSL_SESSION_get_master_key(
        #    const SSL_SESSION *session, unsigned char *out, size_t outlen);
        SSL_SESSION_get_master_key = libssl.SSL_SESSION_get_master_key
        SSL_SESSION_get_master_key.restype = ctypes.c_size_t
        SSL_SESSION_get_master_key.argtypes =\
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t

        # size_t SSL_get_client_random(
        #    const SSL *ssl, unsigned char *out, size_t outlen);
        SSL_get_client_random = libssl.SSL_get_client_random
        SSL_get_client_random.restype = ctypes.c_size_t
        SSL_get_client_random.argtypes =\
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t

        class PyObject(ctypes.Structure):
            _fields_ = [
                ('ob_refcnt', ctypes.c_size_t),
                ('ob_type', ctypes.c_void_p),
            ]

        class PySSLSocket(ctypes.Structure):
            _fields_ = [
                ('head', PyObject),
                ('Socket', ctypes.c_void_p),
                ('ssl', ctypes.c_void_p),
            ]

        class PySSLSession(ctypes.Structure):
            _fields_ = [
                ('head', PyObject),
                ('session', ctypes.c_void_p),
            ]

    except Exception:
        print('Incorrect version of openssl, keylog is disabled')

    host_addr, host_port = addr.split(':')
    server_sni_hostname = 'anticode.ninja'  # TODO Unhardcode
    server_cert = _M('root.crt')
    client_cert = _M(cert + '.crt')
    client_key = _M(cert + '.key')

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=server_cert)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(s, server_side=False,
                               server_hostname=server_sni_hostname)
    conn.connect((host_addr, int(host_port)))
    print("Connection established")

    if libssl:
        ssl_ptr = PySSLSocket.from_address(id(conn._sslobj)).ssl
        buf = ctypes.create_string_buffer(4096)
        res = SSL_get_client_random(ssl_ptr, buf, len(buf))
        client_random = bytes(buf)[:res].hex()

        session_ptr = PySSLSession.from_address(id(conn.session)).session
        buf = ctypes.create_string_buffer(4096)
        res = SSL_SESSION_get_master_key(session_ptr, buf, len(buf))
        master_key = bytes(buf)[:res].hex()

        with open(_M('keylog'), 'a') as log_file:
            print('CLIENT_RANDOM', client_random, master_key, file=log_file)

    buf = b''  # Buffer to hold received client data
    while True:
        data = conn.recv(4096)
        if data:
            buf += data
        else:
            print(buf.decode('utf8'))
            break

    print("Closing connection")
    conn.close()


def server(listen_port):
    server_cert = _M('root.crt')
    server_key = _M('root.key')

    cache = [x for x in common.load_csv(_M(CACHE_DB))]

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=server_cert)

    bindsocket = socket.socket()
    bindsocket.bind(('0.0.0.0', int(listen_port)))
    bindsocket.listen(1)

    while True:
        print("Waiting for client")
        conn = None
        try:
            newsocket, fromaddr = bindsocket.accept()
            print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))

            conn = context.wrap_socket(newsocket, server_side=True)
            print("SSL established. Peer: {}".format(conn.getpeercert()))

            conn.send(_check(cache, conn.getpeercert(True)).encode('utf8'))
        except Exception as e:
            print(e)
        finally:
            print("Closing connection")
            common.safe_exec(lambda: conn and conn.shutdown(socket.SHUT_RDWR))
            common.safe_exec(lambda: conn and conn.close())


def check():
    """Check student answer"""

    output = subprocess.check_output([
        'tshark', '-x',
        '-o', 'ssl.desegment_ssl_records: TRUE',
        '-o', 'ssl.desegment_ssl_application_data: TRUE',
        '-o', 'ssl.keylog_file: {}'.format(_M(KEYLOG_FILE)),
        '-r', _M(DUMP_FILE)], stderr=subprocess.DEVNULL).decode('utf8')

    data_re = re.compile(r'\S+\s{2,}(.+?)\s{2,}.+')
    block = None
    for line in output.split('\n'):
        line = line.strip()
        if line.startswith('Decrypted SSL'):
            block = []
        elif block is not None and len(line) == 0:
            data = common.safe_exec(lambda: bytes(block).decode('ascii'), True)
            if data and data.startswith(MASK):
                common.check_code(_M(VARIANTS_DB), data[len(MASK):])
            block = None
        elif block is not None:
            line = data_re.match(line).group(1)
            block += [int(x, 16) for x in line.split(' ')]
