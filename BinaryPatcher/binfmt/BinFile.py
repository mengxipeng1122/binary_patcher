#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from ..util.log import *

class BinFile( object ):
    '''
        a abstract class for all binfmtfiles class
    '''
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
    def getName(self):            
        raise NotImplementedError("Should have implemented this ")

    @decorator_inc_debug_level
    def updateSymbolMap(self, m): 
        raise NotImplementedError("Should have implemented this ")


