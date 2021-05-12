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
        self.start_address = self.arch.alignCodeAddress(self.start_address)
        self.end_address   = self.arch.alignCodeAddress(self.end_address)
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
        self.start_address = self.arch.alignCodeAddress(self.start_address)
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
        self.srcfn              = info['src']
        self.compiler           = self.arch.compiler    
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags      = self.arch.compile_flags   
        if 'cflags' in info: self.compile_flags+=f' {info["cflags"]}'

    @decorator_inc_debug_level
    def run(self):
        write_address =self.write_cave_address
        logDebug(f'write_cave_address -- {hex(write_address)}')
        objfn = os.path.join('/tmp', os.path.basename(f'{self.srcfn}.1.o'))
        workdir = os.path.dirname(self.srcfn)
        if workdir == ' '*len(workdir): workdir = '.'
        self.arch.compileObjectFile(self.srcfn, objfn, workdir, self.compiler, f'{self.compile_flags}  -D WRITE_ADDRESS={hex(write_address)}', self.info)
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

# class HookPatchStep(PatchStep):
#     ''' 
#         handle HookFunPatch 
#     ''' 
#     name = 'HookPatch'
#     @decorator_inc_debug_level
#     def __init__(self, info, arch, symbolMap, write_cave_address):
#         assert cave_length>0, " cave_length == 0 when do a hook patch "
#         PatchStep.__init__(self, info, arch, symbolMap, write_cave_address)
#         self.offset             = eval(info['offset']) if 'offset' in info else 0
#         self.srcfn             = stepinfo['src']
#         self.hook_address      = self.start_address
#         self.arch              = arch
#         self.compiler          = self.arch.compiler    
#         if 'compiler' in stepinfo: self.compiler = stepinfo['compiler']
#         self.compile_flags     = self.arch.compile_flags
#         if 'cflags' in stepinfo: self.compile_flags+= ' '+stepinfo['cflags']
#         self.compile_flags     += f' -D HOOK_ADDRESS={hex(self.hook_address)}'
#         self.skip_orgin_code   = stepinfo['skipcode'] if 'skipcode' in stepinfo else False;
#         
# 
#     def run(self):
#         cave_address = self.write_cave_address
#         hook_address = self.start_address
#         codeAlignment = self.arch.getCodeAlignment();
#         nopInst = b'\0'; #getAsmInst(self.arch.getNopCode(), 0, self.ks)
# 
#         # add nope
#         nopsinst = self.addCodeForAlignment(cave_address, codeAlignment, nopInst);
#         yield ( True, cave_address, nopsinst )
#         cave_address += len(nopsinst)
# 
#         fun_address = cave_address
#         if self.objfn==None: self.objfn = os.path.join('/tmp', os.path.basename(f'{self.srcfn}.o'))
#         self.arch.compileObjectFile(self.srcfn, self.objfn, self.workdir, self.compiler, self.compile_flags, self.macros, self.string_macros, self.stepinfo)
#         bs, fun_addr = self.arch.linkObjectFile(self.objfn, self.cave_address, self.symboltab, self.pltinfo, self.cs, self.ks, self.binfile, self.stepinfo);
#         yield (True, fun_address, bs)
# 
#         cave_address += len(bs)
# 
#         nopsinst = self.addCodeForAlignment(cave_address, codeAlignment, nopInst);
#         yield ( True, cave_address, nopsinst )
#         cave_address += len(nopsinst)
# 
#         stub_address = cave_address
# 
#         for p in self.arch.handleBFunPatch(hook_address, fun_address, stub_address, self.reg, self.ks, self.cs, self.binfile, self.skip_orgin_code):
#             yield p



