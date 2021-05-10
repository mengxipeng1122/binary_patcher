#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief 

from .BinFile import BinFile
from ..util.log import *

class ELFFile(BinFile):

    def __init__(self):
        pass

    def getName(self):
        return "ELFFile"

    def load(self, fn, log_indent = 0):
        self.binary = lief.parse(fn)
        if self.binary:
            return True
        return False
        
        

