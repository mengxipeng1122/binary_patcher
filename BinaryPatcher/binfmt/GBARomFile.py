#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .BinFile import BinFile
from ..arch.Arm import *

class GBARomFile(BinFile):
    def __init__(self):
        pass

    def getName(self):
        return "GBARomFile"

    def load(self, fn, log_indent):
        return True

    def updateSymbolMap(self, m, log_indent = 0): 
        pass # TODO: 

    def getArch(self):
        return Arm(True)


