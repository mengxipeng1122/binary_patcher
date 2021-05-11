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

    def getNopCode(self):
        return "nop"
        


