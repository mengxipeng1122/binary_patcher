#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief 

from .BinFile import BinFile
from ..util.log import *

class ELFFile(BinFile):
    binary = None

    def __init__(self):
        pass

    def load(self, fn, log_indent = 0):
        self.binary = lief.parse(fn)
        return self.binary
        
        

