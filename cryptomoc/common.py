#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import random
import re
import sys

STUDENTS_DB = 'students.csv'
ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890'
MODULES_RE = re.compile(r"Modulus:\n((?:[0-9a-f]|:\n|:|\ )+)", re.MULTILINE)
PASSWORD_LEN = 8


class Student:
    def __init__(self, name, email, keybase, fingerprint):
        self.name = name
        self.email = email
        self.keybase = keybase
        self.fingerprint = fingerprint

    def __str__(self):
        return self.name


def gen_pass():
    return ''.join(random.choice(ALPHABET) for x in range(PASSWORD_LEN))


def extract_module(data):
    modulus = MODULES_RE.search(data)
    if not modulus:
        return None
    return ''.join(x for x in modulus.group(1) if x in '0123456789abcdef')


def safe_exec(callback, supress=False):
    try:
        return callback()
    except Exception as ex:
        if not supress:
            print(ex)


def load_csv(filename):
    source_file = open(filename, 'r')
    for line in source_file:
        line = line.strip()
        if len(line) > 0:
            yield line.split(';')


def save_csv(filename, lines):
    target_file = open(filename, 'w')
    for line in lines:
        print(';'.join(line), file=target_file)


def check_env(filename=STUDENTS_DB, message='Not a cryptomoc directory'):
    if not os.path.exists(filename):
        print(message)
        sys.exit(1)


def load_students():
    students = []
    for line in load_csv(STUDENTS_DB):
        students.append(Student(*line))
    return students


def save_students(students):
    def gen(s):
        return (s.name, s.email, s.keybase, s.fingerprint)
    save_csv(STUDENTS_DB, (gen(s) for s in students))


def print_student_full(i, s):
    print('{:2} {:40} {:30} {:30}'.format(i, s.name, s.email, s.keybase))


def print_student_code(i, s, c):
    print('{:2} {:40} {:30}'.format(i, s.name, c))


def fuzzy_check(sid, student, mask):
    return mask == str(sid) or\
           mask in student.name or\
           mask in student.email or\
           mask in student.keybase


def check_code(db, mask):
    check_env(db, 'Lab is not init')

    students = load_students()
    passwords = [x for x in load_csv(db)]
    for i, student in enumerate(load_students(), 1):
        code = next((p[1] for p in passwords if p[0] == student.name), None)
        if fuzzy_check(i, student, mask) or code == mask:
            print_student_code(i, student, code)


def create_module(module):
    module_path = module.split('.')[-1]
    os.makedirs(module_path, exist_ok=True)


def module_file(module):
    module_path = module.split('.')[-1]
    return lambda x: os.path.join(module_path, x)


def to_hex(data):
    return ":".join("{:02x}".format(c) for c in data)
