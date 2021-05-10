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

    def updateSymbolMap(self, m, log_indent = 0):
        # update
        m.update( { sym.name : sym.value for sym in self.binary.exported_symbols} )
        # update plt 
        # TODO: hard code address offset
        sec = self.binary.get_section('.plt')
        m.update( { reloc.symbol.name : sec.virtual_address + t*0x0c+0x14 for t, reloc in enumerate(self.binary.pltgot_relocations) if reloc.has_symbol} )
        

