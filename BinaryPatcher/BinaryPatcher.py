#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import magic

from .         import *
from .binfmt   import *
from .util.log import *

class BinaryPatcher(object):
    '''
        This class is responsible for many binary patcher working  
    '''
    binfmt      = None
    arch        = None
    log_indent  = 0
    symbolMap   = {} # store a function/address map for later patch
    patchesList = [] # all patches

    def __init__(self, binfmtName:str = ""): # arch can inference from binary format 
        if binfmtName != "":
            assert binfmtName in bin_fmt_clzs, f'{binfmtName} is not supported '
            # create binfmt by given binfmt file
            self.binfmt = bin_fmt_clzs[binfmtName]()

    def load(self, fn):
        if self.binfmt == None:
            fm = magic.Magic().from_buffer(open(fn,'rb').read())
            if fm in bin_fmt_magic_map:
                obj = bin_fmt_magic_map[fm]()
                self.binfmt = obj;
        assert self.binfmt != None, f'unsupported binary format for file {fn}'
        logInfo(f" {fn} is binary format {obj.getName()} have magic  {fm} ", self.log_indent);
        ok = self.binfmt.load(fn, self.log_indent+1)
        assert ok, f'input file {fn} is not binary format given'
        self.binfmt.updateSymbolMap(self.symbolMap)
        logInfo(f" {fn} have {len(self.symbolMap)} symbols ", self.log_indent);
        self.arch = self.binfmt.getArch()
    
    def addPatch(self, idx=-1,name=None, enable=True):
        '''
            if idx is less than 0; append new patch at current list 
        '''
        newPatch = {
                'enable':enable,
                'name':name,
                'steps':[],
            }
        if idx<0: 
            self.patchesList.append(newPatch)
            return len(self.patchesList)-1
        else:
            self.patchesList.insert(idx, newPatch)
            return idx

    def addPatchStep(self, typ, startAddress, info, endAddress=None, patchIdx=-1):
        assert typ in patchstep_map, f'have no {typ} patch step ' 
        assert isinstance(startAddress, str), f'{startAddress} is not of type str' 
        if endAddress!=None:
            assert isinstance(endAddress, str), f'{endAddress} is not of type str' 
        step = {
            'type'        : typ, 
            'startAddress': startAddress,
            'endAddress'  : endAddress,
            }
        step.update(info)
        self.patchesList[patchIdx]['steps'].append(step)

    def dump(self):
        print(json.dumps(self.patchesList, indent=2))

    def run(self):
        for patch in self.patchesList:
            name = patch['name']
            log(f'<+>hanling patch {name} ...', self.log_indent)
            self.log_indent+=1
            enable = patch['enable'] if 'enable' in patch else True 
            if not enable:
                log(f'<+>skip patch {name} ...', self.log_indent)
                continue
            steps = patch['steps']
            log(f'<+>patching  {name} of {len(steps)} steps ', self.log_indent)
            for i, step in enumerate(steps):
                self.log_indent+=1
                step['arch'] = self.arch
                obj = patchstep_map[step['type']](step, self.log_indent)
                for address, binaries in obj.run(self.log_indent):
                    log(f'<+> {hex(address)} {binaries}', self.log_indent)
                self.log_indent-=1
            self.log_indent-=1

    
    def write(self, fn):
        pass

