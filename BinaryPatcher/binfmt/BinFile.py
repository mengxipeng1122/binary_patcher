#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from ..util.log import *

class BinFile( object ):
    '''
        a abstract class for all binfmtfiles class
    '''
    name    = None

    @decorator_inc_debug_level
    def __init__(self, info=None):
        self.binbs   = None
        self.info  = info

    @decorator_inc_debug_level
    def getArch(self):            
        raise NotImplementedError("Should have implemented this ")

    @decorator_inc_debug_level
    def load(self, fn):           
        raise NotImplementedError("Should have implemented this ")

    @decorator_inc_debug_level
    def write(self, fn):          
        raise NotImplementedError("Should have implemented this ")


    @decorator_inc_debug_level
    def updateSymbolMap(self, m): 
        raise NotImplementedError("Should have implemented this ")

    @decorator_inc_debug_level
    def getInfo(self):
        return self.info

    @decorator_inc_debug_level
    def addCave(self, l):
        raise NotImplementedError("Should have implemented this ")

    @decorator_inc_debug_level
    def patch(self, addr, bs):
        raise NotImplementedError("Should have implemented this ")

    @decorator_inc_debug_level
    def readByte(self, addr, le):
        raise NotImplementedError("Should have implemented this ")
