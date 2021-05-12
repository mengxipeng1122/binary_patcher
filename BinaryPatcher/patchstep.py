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
    def __init__(self, info, arch, symbolMap):
        self.info          = info
        self.arch          = arch
        self.symbolMap     = symbolMap
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

    @decorator_inc_debug_level
    def compileSrcToCave(self, write_address:list, extera_compile_flags=""):
        self.arch.alignCodeAddress(write_address)
        logDebug(f'write_address -- {hex(write_address[0])}')
        objfn = os.path.join('/tmp', os.path.basename(f'{self.srcfn}.1.o'))
        workdir = os.path.dirname(self.srcfn)
        if workdir == ' '*len(workdir): workdir = '.'
        self.arch.compileObjectFile(self.srcfn, objfn, workdir, self.compiler, f'{self.compile_flags}  {extera_compile_flags}', self.info)
        bs, fun_addr = self.arch.linkObjectFile(objfn, write_address[0], self.symbolMap, self.info);
        yield write_address[0], bs
        write_address[0] += len(bs)

class NopPatchStep(PatchStep):
    ''' 
        handle NopPatch
    ''' 
    name='NopPatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap):
        PatchStep.__init__(self, info, arch, symbolMap)
        self.ks = self.arch.getks(info)
         
    @decorator_inc_debug_level
    def run(self, write_address:list):
        # prepare all code 
        self.start_address = self.arch.alignCodeAddress(self.start_address)
        self.end_address   = self.arch.alignCodeAddress(self.end_address)
        nopCode, count =  self.arch.asmCode(self.ks, self.arch.getNopCode(), self.start_address)
        assert count == 1
        if  self.end_address == None:
            yield self.start_address, nopCode
        else:
            for addr in range(self.start_address, self.end_address, len(nopCode)):
                yield addr, nopCode

class AsmPatchStep(PatchStep):
    ''' 
        handle NomPatch
    ''' 
    name='AsmPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap):
        PatchStep.__init__(self, info, arch, symbolMap)
        self.ks = self.arch.getks(info)
        self.asm = info['asm']
         
    @decorator_inc_debug_level
    def run(self, write_address:list):
        # prepare all code 
        self.start_address = self.arch.alignCodeAddress(self.start_address)
        nopCode, count =  self.arch.asmCode(self.ks, self.arch.getNopCode(), self.start_address)
        assert count == 1
        addr = self.start_address
        for code in self.asm:
            logDebug(f'code {code}')
            inst, count = self.arch.asmCode(self.ks, self.subSymbol(code), addr)
            assert count == 1
            yield addr, inst
            addr += len(inst)

class ParasitePatchStep(PatchStep):
    ''' 
        handle ParasitePatch, this patch step put a parasite code into a address space 
    ''' 
    name='ParasitePatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap):
        PatchStep.__init__(self, info, arch, symbolMap)
        self.offset             = eval(info['offset']) if 'offset' in info else 0
        self.srcfn              = info['src']
        self.compiler           = self.arch.compiler    
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags      = self.arch.compile_flags   
        if 'cflags' in info: self.compile_flags+=f' {info["cflags"]}'

    @decorator_inc_debug_level
    def run(self, write_address:list):
        address, bs =  next(self.compileSrcToCave(write_address))
        yield address, bs

class BytesPatchStep(PatchStep):
    ''' 
        handle BytesPatch
    ''' 
    name='BytesPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap):
        PatchStep.__init__(self, info, arch, symbolMap)
        self.bytes = info['bytes']

    @decorator_inc_debug_level
    def run(self, write_address:list):
        yield self.start_address, bytes(self.bytes)

class HookPatchStep(PatchStep):
    ''' 
        handle HookFunPatch 
    ''' 
    name = 'HookPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, symbolMap):
        assert cave_length>0, " cave_length == 0 when do a hook patch "
        PatchStep.__init__(self, info, arch, symbolMap)
        self.offset             = eval(info['offset']) if 'offset' in info else 0
        self.srcfn             = stepinfo['src']
        self.hook_address      = self.start_address
        self.arch              = arch
        self.compiler          = self.arch.compiler    
        if 'compiler' in stepinfo: self.compiler = stepinfo['compiler']
        self.compile_flags     = self.arch.compile_flags
        if 'cflags' in stepinfo: self.compile_flags+= ' '+stepinfo['cflags']
        self.skip_orgin_code   = stepinfo['skipcode'] if 'skipcode' in stepinfo else False;

    def run(self, write_address:list):
        hook_address = self.start_address
        fun_address, bs =  next(self.compileSrcToCave(write_address, f'-D HOOK_ADDRESS={hex(hook_address)}'))
        yield fun_address, bs

        stub_address = cave_address

        for p in self.arch.handleBFunPatch(hook_address, fun_address, stub_address, self.reg, self.ks, self.cs, self.binfile, self.skip_orgin_code):
            yield p



