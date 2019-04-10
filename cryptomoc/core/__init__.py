#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Набор вспомогательных функций для проведения практик по курсу "Прикладная криптография"
"""

import importlib
import os
import subprocess
import urllib.request
import cryptomoc.common as common


def init():
    """Generate students database stub"""

    if os.path.exists(common.STUDENTS_DB):
        print('Students database is already created')
        return

    common.save_students([
        common.Student('Alice', 'alice@mail.org', 'alice', '#alice'),
        common.Student('Bob', 'bob@mail.org', 'bob', '#bob'),
    ])
    print('Created student database stub')


def list():
    """Show students list"""

    for i, student in enumerate(common.load_students(), 1):
        common.print_student_full(i, student)


def find(mask):
    """Find student by name|email|keybase login"""

    for i, student in enumerate(common.load_students(), 1):
        if not common.fuzzy_check(i, student, mask):
            continue
        common.print_student_full(i, student)


def importpgp():
    """Import students PGP keys from keybase.io"""

    for student in common.load_students():
        if not student.keybase:
            continue

        print('Importing', student.name)
        key_url = 'https://keybase.io/{0}/key.asc'.format(student.keybase)
        key_data = urllib.request.urlopen(key_url).read()
        subprocess.check_output(['gpg', '--import', '-'], input=key_data)

def modules():
    """Show description for all tasks"""

    for module_name in os.listdir(common.HERE):
        module_path = os.path.join(common.HERE, module_name, '__init__.py')
        if not os.path.exists(module_path):
            continue

        print(module_name)
        print(len(module_name) * '=')
        module = importlib.import_module(__name__.replace('core', module_name))
        print(module.__doc__)
        print()
