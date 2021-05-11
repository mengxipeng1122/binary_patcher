#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief 

from .BinFile import BinFile
from ..arch.Arm import *
from ..util.log import *

class ELFFile(BinFile):

    @decorator_inc_debug_level
    def __init__(self, info=None):
        BinFile.__init__(self, info);

    @decorator_inc_debug_level
    def getName(self):
        return "ELFFile"

    @decorator_inc_debug_level
    def load(self, fn):
        self.binary = lief.parse(fn)
        if self.binary:
            return True
        return False

    @decorator_inc_debug_level
    def updateSymbolMap(self, m):
        # update
        m.update( { sym.name : sym.value for sym in self.binary.exported_symbols} )
        # update plt 
        #m.update( { reloc.symbol.name : sec.virtual_address + t*0x0c+0x14 for t, reloc in enumerate(self.binary.pltgot_relocations) if reloc.has_symbol} )
        pltmap = {reloc.address : reloc.symbol.name for reloc in self.binary.pltgot_relocations}
        sec = self.binary.get_section('.plt')
        self.getArch().parsePlTSecUpdateSymol(bytes(sec.content), sec.virtual_address, pltmap, m )

    @decorator_inc_debug_level
    def getArch(self):
        if self.binary.header.machine_type == lief.ELF.ARCH.ARM: 
            return Arm(True)
        raise Exception(f'unsupported machine_type {self.binary.header.machine_type } ')

        
    

