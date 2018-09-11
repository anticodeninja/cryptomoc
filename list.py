#!/usr/bin/env python
# -*- coding: utf-8 -*-

import common
import subprocess

for i, student in enumerate(common.load_students()):
    print(i + 1, student)
