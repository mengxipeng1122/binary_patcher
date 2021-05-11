#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import magic

from .         import *
from .binfmt   import *
from .arch     import *
from .util.log import *

class BinaryPatcher(object):
    '''
        This class is responsible for many binary patcher working  
    '''
    binfmt      = None
    arch        = None
    cave_length = 0
    symbolMap   = {} # store a function/address map for later patch
    patchesList = [] # all patches

    def __init__(self, info=None): # arch can inference from binary format 
        if info != None:
            self.binfmt         = bin_fmt_clzs[ info['BINFMT']['name'] ](info['BINFMT'])
            self.arch           = arch_clsz[ info['ARCH']['name'] ](info['ARCH'])
            CAVE_LENGTH = info ['CAVE_LENGTH']
            self.cave_length    = eval(CAVE_LENGTH) if isinstance(CAVE_LENGTH, str) else CAVE_LENGTH
            self.symbolMap      = {k:eval(v) for k,v in info['SYMBOL_MAP'].items()}
            self.patchesList    = info['PATCHES']    

    def load(self, fn):
        if self.binfmt == None:
            fm = magic.Magic().from_buffer(open(fn,'rb').read())
            if fm in bin_fmt_magic_map:
                self.binfmt = bin_fmt_magic_map[fm]()
                logInfo(f" {fn} is binary format {self.binfmt.getName()} have magic  {fm} ");
        assert self.binfmt != None, f'unsupported binary format for file {fn}'
        ok = self.binfmt.load(fn)
        assert ok, f'input file {fn} is not binary format given'
        self.binfmt.updateSymbolMap(self.symbolMap)
        logInfo(f" {fn} have {len(self.symbolMap)} symbols ");
        if self.arch == None:
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

    def getInfo(self):
        return {
            'PATCHES'       : self.patchesList,
            'ARCH'          : self.arch.getInfo(),
            'BINFMT'        : self.binfmt.getInfo(),
            'CAVE_LENGTH'   : self.cave_length,
            'SYMBOL_MAP'    : { k:hex(v) for k, v in self.symbolMap.items() },
            }

    @decorator_inc_debug_level
    def run_patch_step(self, step):
        obj = patchstep_map[step['type']](step, self.arch, self.symbolMap)
        for address, binaries in obj.run():
            # TODO: handle patch address, binaries
            logInfo(f'<+> {hex(address)} {binaries}')
            self.binfmt.patch(address,binaries)

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
        if self.cave_length>0:
            self.symbolMap['CAVE_ADDRESS'] = self.binfmt.addCave(self.cave_length)
        for patch in self.patchesList:
            name = patch['name']
            logInfo(f'<+>hanling patch {name} ...')
            self.run_patch(patch)

    
    def write(self, fn):
        assert self.binfmt.binbs!=None, f'binbs equals to None when write '
        open(fn,'wb').write(self.binfmt.binbs)

