#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct

from keystone import *
from capstone import *

from ..util.log import *
from .Arch import *

class Arm(Arch):
    thumbMode = False
    @decorator_inc_debug_level
    def __init__(self, thumbMode=False):
        if thumbMode:
            Arch.__init__(self, KS_ARCH_ARM, KS_MODE_THUMB, CS_ARCH_ARM, CS_MODE_THUMB)
        else:
            Arch.__init__(self, KS_ARCH_ARM, KS_MODE_ARCH, CS_ARCH_ARM, CS_MODE_ARCH)
        self.thumbMode = thumbMode;

    @decorator_inc_debug_level
    def getNopCode(self):
        return "nop"

    @decorator_inc_debug_level
    def parsePlTSecUpdateSymol(self, sec, address, pltmap, m ):
        for o in range(0, len(sec) - 0x08, 0x04):
            ins0, ins1, ins2 = struct.unpack('III', sec[o:o+0x0c])
            # hard code for arm instruction 
            if ins0 & 0xffffff00 == 0xe28fc600 and ins1 & 0xffffff00 == 0xe28cca00 and ins2 & 0xfffff000 == 0xe5bcf000:
                off = (ins0 &  0xff)<<0x14
                off+= (ins1 &  0xff)<<0x0c
                off+= (ins2 & 0xfff)<<0x00
                addr= address+o+8+off
                if addr in pltmap:
                    symbolname = pltmap[addr]
                    m[symbolname] = address + o 

    @decorator_inc_debug_level
    def getInfo(self):
        info = Arch.getInfo(self)
        info['name'] = 'ARM'
        info['ThumbMode'] = self.thumbMode;
        return info
        

