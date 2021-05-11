#!/usr/bin/env python
# -*- coding: utf-8 -*-


from .Arm import *
from .M6502 import *

arch_clsz = {
        'ARM': Arm,
        'M6502': M6502,
}

