#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief
from keystone import *
from capstone import *

from ..util.log import *

class Arch(object):
    '''
        a abstract class for all architecture class
    '''

    info            = None
    name            = None

    @decorator_inc_debug_level
    def __init__(self, info=None):
        if info == None:
            info = {}
        info ['name']= self.name
        self.info  = info
        
    @decorator_inc_debug_level
    def getNopCode(self, info=None):
        raise NotImplementedError( "Should have implemented this" )

    def getJumpCode(self, from_address, to_address,info=None): 
        raise NotImplementedError( "Should have implemented this" )

    def getCallCode(self, caller_address, callee_address, info=None): 
        raise NotImplementedError( "Should have implemented this" )

    def getSaveContextCode(self, info=None): 
        raise NotImplementedError( "Should have implemented this" )

    def getRestoreContextCode(self, info=None): 
        raise NotImplementedError( "Should have implemented this" )


    @decorator_inc_debug_level
    def parsePlTSecUpdateSymol(self, sec, address, pltmap, m, info=None ):
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
        return self.info
    
    @decorator_inc_debug_level
    def getks(self, info=None):
        return Ks(self.info['KS_ARCH'], self.info['KS_MODE'])

    @decorator_inc_debug_level
    def getcs(self, info=None):
        return Cs(self.info['CS_ARCH'], self.info['CS_MODE'])

    @decorator_inc_debug_level
    def dolink(self, bs, link_address, symboltab, relocs, sectab, info=None):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def alignAddress(self, address, mask=0xfffffffc, info=None):
        if isinstance(address, int): return address & mask
        raise Exception(f'unsupported augment {address} in alignCodeAddress ')

    @decorator_inc_debug_level
    def alignCodeAddress(self, address, info=None):
        raise NotImplementedError( "Should have implemented this" )
        
    @decorator_inc_debug_level
    def alignDataAddress(self, address, info=None):
        raise NotImplementedError( "Should have implemented this" )
        
