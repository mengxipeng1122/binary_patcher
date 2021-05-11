#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .BinFile import BinFile
from ..arch.Arm import *
from ..util.log import *

class GBARomFile(BinFile):
    @decorator_inc_debug_level
    def __init__(self):
        pass

    @decorator_inc_debug_level
    def getName(self):
        return "GBARomFile"

    @decorator_inc_debug_level
    def load(self, fn):
        return True

    @decorator_inc_debug_level
    def updateSymbolMap(self, m): 
        pass # TODO: 

    @decorator_inc_debug_level
    def getArch(self):
        return Arm(True)


