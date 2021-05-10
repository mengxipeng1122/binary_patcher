#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .binfmt   import *
from .util.log import *

class BinaryPatcher(object):
    '''
        This class is responsible for many binary patcher working  
    '''
    binfmt      = None
    binfmtName  = ""
    arch        = None
    archName    = ""
    log_indent  = 0

    def __init__(self, binfmtName:str = ""): # arch can inference from binary format 
        if binfmtName != "":
            assert binfmtName in bin_fmt_clzs, f'{binfmtName} is not supported '
            # create binfmt by given binfmt file
            self.binfmt = bin_fmt_clzs[binfmtName]()
            self.binfmtName = binfmtName

    def load(self, fn):
        if self.binfmt == None:
            fm = magic.Magic().from_buffer(open(fn,'rb').read())
            if fm in bin_fmt_magic_map:
                obj = bin_fmt_magic_map[fm]()
                ok = obj.load(fn, self.log_indent+1)
                if ok:
                    logInfo(f" {fn} is binary format {fm} ", self.log_indent);
                    self.binfmt = obj;
                    return ;
            for name, clz in bin_fmt_clzs.items():
                obj = clz()
                ok = obj.load(fn, self.log_indent+1)
                if ok:
                    logInfo(f" {fn} is binary format {name} ", self.log_indent);
                    self.binfmtName = name
                    self.binfmt = obj;
                    return
            raise Exception(f'unsupported binary format for file {fn}')
        else:
            ok = self.binfmt.load(fn, self.log_indent+1)
            assert ok, f'input file {fn} is not binary format {self.binfmtName}'
    
    def write(self, fn):
        pass

