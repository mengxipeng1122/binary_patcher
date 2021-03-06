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
    def __init__(self, info=None): # arch can inference from binary format 
        self.binfmt      = None
        self.arch        = None
        self.cave_length = 0
        self.symbolMap   = {} # store a function/address map for later patch
        self.patchesList = [] # all patches

        if info != None:
            self.binfmt         = bin_fmt_clzs[ info['BINFMT']['name'] ](info['BINFMT'])
            self.arch           = arch_clzs[ info['ARCH']['name'] ](info['ARCH'])
            if 'CAVE_LENGTH' in info:
                CAVE_LENGTH = info ['CAVE_LENGTH'] 
                self.cave_length    = eval(CAVE_LENGTH) if isinstance(CAVE_LENGTH, str) else CAVE_LENGTH
            self.symbolMap      = {k:eval(v) for k,v in info['SYMBOL_MAP'].items()} if 'SYMBOL_MAP' in info else {}
            self.patchesList    = info['PATCHES'] if 'PATCHES' in info else []   

    def load(self, fn):
        if self.binfmt == None:
            fm = magic.Magic().from_buffer(open(fn,'rb').read())
            if fm in bin_fmt_magic_map:
                self.binfmt = bin_fmt_magic_map[fm]()
                logInfo(f" {fn} is binary format {self.binfmt.name} have magic  {fm} ");
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

    def addPatchStep(self, typ, startAddress=None, info=None, endAddress=None, patchIdx=-1):
        assert typ in patchstep_map, f'have no {typ} patch step ' 
        if startAddress != None:
            assert isinstance(startAddress, str), f'{startAddress} is not of type str' 
        if endAddress!=None:
            assert isinstance(endAddress, str), f'{endAddress} is not of type str' 
        step = {
            'type'        : typ, 
            'startAddress': startAddress,
            'endAddress'  : endAddress,
            }
        if info != None: step.update(info)
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
    def run_patch_step(self, step, info=None):
        if info != None and 'cflags' in info:
            if 'cflags' not in step:
                step['cflags'] = info['cflags']
            else:
                step['cflags'] += ' '+info['cflags']
        obj = patchstep_map[step['type']](step, self.arch, self.binfmt, self.symbolMap)
        run_result = []
        obj.run(self.write_cave_address, run_result)
        for address, binaries in run_result:
            logInfo(f'<+> {hex(address)} {binaries} {hex(self.write_cave_address[0])}')
            self.binfmt.patch(self.arch.alignAddressForAccess(address),binaries)

    @decorator_inc_debug_level
    def run_patch(self, patch, info=None):
        name   = patch['name']
        enable = patch['enable'] if 'enable' in patch else True 
        if not enable:
            logWarn(f'<+>skip patch {name} ...')
            return 
        steps = patch['steps']
        logInfo(f'<+>patching  {name} of {len(steps)} steps ')
        for i, step in enumerate(steps):
            self.run_patch_step(step, info)

    def run(self, info=None):
        if self.cave_length>0:
            logDebug(f'self.cave_length {self.cave_length}' )
            self.symbolMap['CAVE_ADDRESS'] = self.binfmt.addCave(self.cave_length, info)
            logDebug(f'CAVE_ADDRESS {hex(self.symbolMap["CAVE_ADDRESS"])}' )
        # NOTE: write_cave_address should be a list, so can pass by reference in run patch step
        self.write_cave_address = [self.symbolMap['CAVE_ADDRESS'] if 'CAVE_ADDRESS' in self.symbolMap else None]
        for patch in self.patchesList:
            name = patch['name']
            logInfo(f'<+>hanling patch {name} ...')
            self.run_patch(patch, info)

    @decorator_inc_debug_level    
    def write(self, fn):
        assert self.binfmt.binbs!=None, f'binbs equals to None when write '
        open(fn,'wb').write(self.binfmt.binbs)

