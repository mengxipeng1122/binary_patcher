#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

class Arch(object):
    '''
        a abstract class for all architecture class
    '''
    def load(self, fn): raise NotImplementedError( "Should have implemented this" )
    

