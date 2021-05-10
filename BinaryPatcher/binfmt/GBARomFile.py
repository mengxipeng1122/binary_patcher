#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .BinFile import BinFile

class GBARomFile(BinFile):
    def __init__(self):
        pass

    def load(self, fn, log_indent):
        with magic.Magic() as m:
            fm = m.from_buffer(open(fn,'rb').read())
            if fm == 'application/x-gba-rom':
                return True
        return False


