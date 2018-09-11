#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import random

ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890'
PASSWORD_LEN = 8
HERE = os.path.abspath(os.path.dirname(__file__))


def gen_pass():
    return ''.join(random.choice(ALPHABET) for x in range(PASSWORD_LEN))


class Student:
    def __init__(self, name, email, keybase, fingerprint):
        self.name = name
        self.email = email
        self.keybase = keybase
        self.fingerprint = fingerprint

    def __str__(self):
        return self.name


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


def load_students():
    temp = []
    for line in load_csv(os.path.join(HERE, 'students.csv')):
        temp.append(Student(*line))
    return temp
