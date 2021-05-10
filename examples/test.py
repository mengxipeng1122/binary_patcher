#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    This example patches android .so file in gotvg platform
'''
import sys

sys.path.insert(0,"..");

from BinaryPatcher.BinaryPatcher import *

def main():
    pather = BinaryPatcher()
    pather.load('libMobilePlatform.so')
    pather.write('/tmp/gotvg_libretro.so')

    pather = BinaryPatcher()
    pather.load('super.mario.advance.2.us.gba')
    pather.write('/tmp/sma2.gba')

    pather = BinaryPatcher()
    pather.load('smbw.nes')
    pather.write('/tmp/smbw.nes')

if __name__ == '__main__':
    main()

