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
        logInfo(f" {fn} is binary format {obj.getName()} have magic  {fm} ");
        ok = self.binfmt.load(fn)
        assert ok, f'input file {fn} is not binary format given'
        self.binfmt.updateSymbolMap(self.symbolMap)
        logInfo(f" {fn} have {len(self.symbolMap)} symbols ");
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

    @decorator_inc_debug_level
    def run_patch_step(self, step):
        obj = patchstep_map[step['type']](step, self.arch, self.symbolMap)
        for address, binaries in obj.run():
            log(f'<+> {hex(address)} {binaries}')

    @decorator_inc_debug_level
    def run_patch(self, patch):
        name   = patch['name']
        enable = patch['enable'] if 'enable' in patch else True 
        if not enable:
            logWarn(f'<+>skip patch {name} ...')
            return 
        steps = patch['steps']
        logInfo(f'<+>patching  {name} of {len(steps)} steps ')
        for i, step in enumerate(steps):
            self.run_patch_step(step)

    def run(self):
        for patch in self.patchesList:
            name = patch['name']
            log(f'<+>hanling patch {name} ...')
            self.run_patch(patch)

    
    def write(self, fn):
        pass

