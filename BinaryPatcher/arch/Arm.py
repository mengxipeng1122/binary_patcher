#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from .Arch import *

from keystone import *
from capstone import *

class Arm(Arch):
    def __init__(self, thumbMode=False):
        if thumbMode:
            Arch.__init__(self, KS_ARCH_ARM, KS_MODE_THUMB, CS_ARCH_ARM, CS_MODE_THUMB)
        else:
            Arch.__init__(self, KS_ARCH_ARM, KS_MODE_ARCH, CS_ARCH_ARM, CS_MODE_ARCH)

    def getNopInstruction(self, address, info=None):
        code = "nop"
        if 'ThumbMode' not in info:
            ks = Ks(self.ks_arch, self.ks_mode)
        else:
            ThumbMode = info['ThumbMode']
            ks = Ks(self.ks_arch, KS_MODE_THUMB if ThumbMode else KS_ARCH_ARM )
        return Arch.asmCode(self, ks, code, address)
        


