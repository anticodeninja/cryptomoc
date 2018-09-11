#!/usr/bin/env python
# -*- coding: utf-8 -*-

import common
import os
import subprocess

for student in common.load_students():
    if len(student.keybase) == 0:
        continue
    os.system('wget -qO - https://keybase.io/{0}/key.asc |'
              ' gpg --import -'.format(student.keybase))
