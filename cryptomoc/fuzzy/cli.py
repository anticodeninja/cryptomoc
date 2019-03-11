#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ctypes
import os

try:
    import readline
except:
    pass

HERE = os.path.abspath(os.path.dirname(__file__))

def main():
    native = ctypes.CDLL(os.path.join(HERE, 'native.so'))
    native.check.restype = ctypes.c_uint64

    while True:
        data = input('>')
        result = native.check(ctypes.create_string_buffer(data.encode('ascii')), len(data))
        if result <= 0xFFFFFFFF:
            print('Safe is broken, your code is', hex(result))
        else:
            print('Sorry student, your code in another input!', hex(result))


if __name__ == "__main__":
    main()
