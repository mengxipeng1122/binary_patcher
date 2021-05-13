#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief
from ..util.log import *

class Arch(object):
    '''
        a abstract class for all architecture class
    '''

    compiler        = None
    compile_flags   = ""

    @decorator_inc_debug_level
    def __init__(self, ks_arch, ks_mode, cs_arch, cs_mode, info=None):
        self.ks_arch = ks_arch 
        self.ks_mode = ks_mode 
        self.cs_arch = cs_arch 
        self.cs_mode = cs_mode 
        if info != None and 'cflags' in info:
            self.compile_flags = info['cflags']
        
    @decorator_inc_debug_level
    def getNopInstruction(self,address, info=None): 
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def asmCode(self, ks, code, address=0, info=None):
        binCode, count = ks.asm(code, address); 
        return bytes(binCode), count

    @decorator_inc_debug_level
    def parsePlTSecUpdateSymol(self, sec, address, pltmap, m ):
        '''
            this method parse .plt section dat to update a map of symbol name ->  plt stub address 
            augments :
                sec -- content of .plt section , of type bytes
                address -- address of .plt section 
                pltmap  -- a map of  actual plt address => symbol name 
                m  -- symbol map need to upate
        ''' 
        raise NotImplementedError( "Should have implemented this" )
    
    @decorator_inc_debug_level
    def getInfo(self):
        return {
            'KS_ARCH' : self.ks_arch,
            'KS_MODE' : self.ks_mode,
            'CS_ARCH' : self.cs_arch,
            'CS_MODE' : self.cs_mode,
            'cflags'  : self.compile_flags,
        }
    
    @decorator_inc_debug_level
    def getks(self, info=None):
        return Ks(self.ks_arch, self.ks_mode)

    @decorator_inc_debug_level
    def dolink(self, bs, link_address, symboltab, binary, binary_sectab, info):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def alignAddress(self, address, mask=0xfffffffc):
        if isinstance(address, int): return address & mask
        raise Exception(f'unsupported augment {address} in alignCodeAddress ')



    @decorator_inc_debug_level
    def alignCodeAddress(self, address):
        raise NotImplementedError( "Should have implemented this" )
        
    @decorator_inc_debug_level
    def alignDataAddress(self, address):
        raise NotImplementedError( "Should have implemented this" )

        
