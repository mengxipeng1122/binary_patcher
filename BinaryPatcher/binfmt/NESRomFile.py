#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .BinFile import BinFile
from ..util.log import *

class NESRomFile(BinFile):

    name    = 'GBARom'

    @decorator_inc_debug_level
    def __init__(self, info=None):
        BinFile.__init__(self, info);        


    @decorator_inc_debug_level
    def load(self, fn):
        return True


