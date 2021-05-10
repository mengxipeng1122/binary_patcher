#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from .util.log import *


# base class of all patch step
class PatchStep:
    def __init__(self, info, log_indent=0):
        self.start_address = info['startAddress']
        self.end_address   = info['endAddress'  ]
        self.arch          = info['arch']
        self.info          = info

    def run(self, log_indent=0):
        raise NotImplementedError('Should have implemented this ')

class NopPatchStep(PatchStep):
    ''' 
        handle NomPatch
    ''' 
    def __init__(self, info, log_indent=0):
        PatchStep.__init__(self, info, log_indent)
         
    def run(self, log_indent=0):
        # prepare all code 
        yield eval(self.start_address), self.arch.getNopInstruction(eval(self.start_address), self.info)

