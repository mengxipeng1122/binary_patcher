#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from keystone import *
from capstone import *

from .util.log import *

# base class of all patch step
class PatchStep:
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap):
        self.arch          = arch
        self.symbolMap     = symbolMap
        self.info          = info

    @decorator_inc_debug_level
    def run(self):
        raise NotImplementedError('Should have implemented this ')

    @decorator_inc_debug_level
    def calAddress(self,text):
        if text == None: return None
        for k, v in self.symbolMap.items():
            text = text.replace('%{'+k+'}%', hex(v))
        return eval(text)

class NopPatchStep(PatchStep):
    ''' 
        handle NomPatch
    ''' 
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt):
        PatchStep.__init__(self, info, arch, binfmt)
        ks_arch = arch.ks_arch
        ks_mode = arch.ks_mode
        if 'ThumbMode' in info:
            ThumbMode = info['ThumbMode']
            ks_mode  = KS_MODE_THUMB if ThumbMode else KS_ARCH_ARM
        self.ks = Ks(ks_arch, ks_mode)
         
    @decorator_inc_debug_level
    def run(self):
        # prepare all code 
        logDebug(f"self.info {self.info} ")
        start_address = self.calAddress(self.info['startAddress'])
        end_address   = self.calAddress(self.info['endAddress'  ])
        nopCode =  self.arch.asmCode(self.ks, self.arch.getNopCode(), start_address)
        if  end_address == None:
            yield start_address, nopCode
        else:
            for addr in range(start_address, end_address, len(nopCode)):
                yield addr, nopCode
                

