#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

class BinFile( object ):
    '''
        a abstract class for all binfmtfiles class
    '''
    def load(self, fn, log_indent = 0): raise NotImplementedError("Should have implemented this ")
    def write(self, fn, log_indent = 0): raise NotImplementedError("Should have implemented this ")


