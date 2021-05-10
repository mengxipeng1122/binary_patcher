#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .BinFile import BinFile

class GBARomFile(BinFile):
    def __init__(self):
        pass

    def getName(self):
        return "GBARomFile"

    def load(self, fn, log_indent):
        return True


