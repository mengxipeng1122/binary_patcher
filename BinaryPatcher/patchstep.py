#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from keystone import *
from capstone import *

from .util.log import *

# base class of all patch step
class PatchStep:
    name=None
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap, write_cave_address):
        self.info          = info
        self.arch          = arch
        self.symbolMap     = symbolMap
        self.write_cave_address  = write_cave_address
        self.start_address = self.calAddress(info['startAddress']) if 'startAddress' in info else None
        self.end_address   = self.calAddress(info['endAddress'  ]) if 'endAddress' in info else None

    @decorator_inc_debug_level
    def run(self):
        raise NotImplementedError('Should have implemented this ')

    @decorator_inc_debug_level
    def subSymbol(self,text):
        for k, v in self.symbolMap.items():
            text = text.replace('%{'+k+'}%', hex(v))
        return text

    @decorator_inc_debug_level
    def calAddress(self,text):
        if text == None: return None
        return eval(self.subSymbol(text))

class NopPatchStep(PatchStep):
    ''' 
        handle NopPatch
    ''' 
    name='NopPatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap, write_cave_address):
        PatchStep.__init__(self, info, arch, symbolMap, write_cave_address)
        self.ks = self.arch.getks(info)
         
    @decorator_inc_debug_level
    def run(self):
        # prepare all code 
        nopCode, count =  self.arch.asmCode(self.ks, self.arch.getNopCode(), self.start_address)
        assert count == 1
        if  self.end_address == None:
            yield self.start_address, nopCode
        else:
            for addr in range(self.start_address, self.end_address, len(nopCode)):
                yield False, addr, nopCode

class AsmPatchStep(PatchStep):
    ''' 
        handle NomPatch
    ''' 
    name='AsmPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap, cave_length):
        PatchStep.__init__(self, info, arch, symbolMap, cave_length)
        self.ks = self.arch.getks(info)
        self.asm = info['asm']
         
    @decorator_inc_debug_level
    def run(self):
        # prepare all code 
        nopCode, count =  self.arch.asmCode(self.ks, self.arch.getNopCode(), self.start_address)
        assert count == 1
        addr = self.start_address
        for code in self.asm:
            logDebug(f'code {code}')
            inst, count = self.arch.asmCode(self.ks, self.subSymbol(code), addr)
            assert count == 1
            yield False, addr, inst
            addr += len(inst)

class ParasitePatchStep(PatchStep):
    ''' 
        handle ParasitePatch, this patch step put a parasite code into a address space 
    ''' 
    name='ParasitePatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap, write_cave_address):
        PatchStep.__init__(self, info, arch, symbolMap, write_cave_address)
        logDebug(f'write_cave_address {write_cave_address}')
        assert write_cave_address!=None, " write_cave_address == None when do a parasite patch "
        self.offset             = eval(info['offset']) if 'offset' in info else 0
        self.src                = info['src']
        self.compiler           = self.arch.compiler    
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags      = self.arch.compile_flags   
        if 'cflags' in info: self.compile_flags+=f' {info["cflags"]}'

    @decorator_inc_debug_level
    def run(self):
        write_address =self.write_cave_address
        logDebug(f'write_cave_address -- {hex(write_address)}')
        objfn = os.path.join('/tmp', os.path.basename(f'{self.src}.o'))
        workdir = os.path.dirname(self.src)
        if workdir == ' '*len(workdir): workdir = '.'
        self.arch.compileObjectFile(self.src, objfn, workdir, self.compiler, f'{self.compile_flags}  -D WRITE_ADDRESS={hex(write_address)}', self.info)
        bs, fun_addr = self.arch.linkObjectFile(objfn, write_address, self.symbolMap, self.info);
        yield (True, write_address, bs)


class BytesPatchStep(PatchStep):
    ''' 
        handle BytesPatch
    ''' 
    name='BytesPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap, write_cave_address):
        PatchStep.__init__(self, info, arch, symbolMap, write_cave_address)
        self.bytes = info['bytes']

    @decorator_inc_debug_level
    def run(self):
        yield(False, self.start_address, bytes(self.bytes))


