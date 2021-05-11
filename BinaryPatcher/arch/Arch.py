#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

class Arch(object):
    '''
        a abstract class for all architecture class
    '''
    def __init__(self, ks_arch, ks_mode, cs_arch, cs_mode):
        self.ks_arch = ks_arch 
        self.ks_mode = ks_mode 
        self.cs_arch = cs_arch 
        self.cs_mode = cs_mode 
        
    def getNopInstruction(self,address, info=None): raise NotImplementedError( "Should have implemented this" )

    def asmCode(self, ks, code, address=0):
        binCode, count = ks.asm(code, address); 
        return bytes(binCode)
    

