#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TODO
"""

import os
import random
import cryptomoc.common as common

_M = common.module_file(__name__)


def gen():
    """Generate test env"""

    common.check_env()
    common.create_module(__name__)
    print('Created env')


def create(source):
    common.check_env()
    common.check_env(_M(source), 'file with questions was not found')

    question_block = []
    questions_block = [question_block]
    with open(_M(source), 'r') as source_file:
        for line in source_file:
            line = line.strip()
            if len(line) == 0 and len(question_block) > 0:
                question_block = []
                questions_block.append(question_block)
            if len(line) > 0:
                question_block.append(line)

    students = common.load_students()
    target_file = open(_M('output'), 'w')  # TODO Unhardcode

    for i, student in enumerate(students, 1):
        print('Gen {0}: {1}'.format(i, student))

        print('{0}. {1}'.format(i, student.name), file=target_file)
        print('==================================================',
              file=target_file)
        for j, block in enumerate(questions_block, 1):
            print('{0}. {1}'.format(j, random.choice(block)), file=target_file)
        print(file=target_file)
