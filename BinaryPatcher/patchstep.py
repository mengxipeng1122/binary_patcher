#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import lief
from keystone import *
from capstone import *

from .util.log import *
from .util.util import *

# base class of all patch step
class PatchStep:
    name=None
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        self.info          = info
        self.arch          = arch
        self.binfmt        = binfmt
        self.symbolMap     = symbolMap
        self.start_address = self.calAddress(info['startAddress']) if 'startAddress' in info else None
        self.end_address   = self.calAddress(info['endAddress'  ]) if 'endAddress' in info else None

    @decorator_inc_debug_level
    def run(self, write_address:list, ops:list=[]):
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
    def compileSrcToCave(self, write_address:list, ops:list, extera_compile_flags=""):
        write_address[0] = self.arch.alignCodeAddress(write_address[0])
        objfn = os.path.join('/tmp', os.path.basename(f'{self.srcfn}.1.o'))
        workdir = os.path.dirname(self.srcfn)
        if workdir == ' '*len(workdir): workdir = '.'
        cmd = f'cd {workdir}  && pwd && {self.compiler} -c -Wall -Werror -I.  {self.compile_flags} -o {objfn} {self.srcfn}'
        runCmd(cmd, showCmd=True, mustOk=True);
        bs, fun_addr = self.linkObjectFile(objfn, write_address[0], self.symbolMap, self.info);
        ops.append(( write_address[0], bs))
        write_address[0] += len(bs)

    @decorator_inc_debug_level
    def writeObjectFile(self, binary, write_address, info=None): 
        '''
            binary -- parsed variable by lief library
            write_address -- address that entire bytes will write 
            put binary data to a wrote for linking, 
            work only for ELF format now
        '''
        bs = b""
        # write sections
        sectab ={}
        for i, sec in enumerate(binary.sections):
            if lief.ELF.SECTION_FLAGS.ALLOC in sec.flags_list:
                if sec.type == lief.ELF.SECTION_TYPES.NOBITS:
                    bs += b'\0'*sec.size
                else:
                    bs += bytes(sec.content)
                sec.virtual_address=write_address; # set linked virtual_address
                write_address += sec.size
                next_write_address = getAlignAddr(write_address, 0x10);
                bs += b'\0'*(next_write_address-write_address)
                write_address=next_write_address
                sectab[sec.name] = sec.virtual_address # record all section address 
        symboltab = {} 
        # update symbol table for local variables
        if binary.has_static_symbol:
            for t, symbol in enumerate(binary.static_symbols):
                if symbol.type not in [ lief.ELF.SYMBOL_TYPES.OBJECT ,
                        lief.ELF.SYMBOL_TYPES.FUNC , ]:
                   continue
                if len(symbol.name) == 0: continue
                if symbol.shndx>=binary.header.numberof_sections: 
                    if symbol.shndx == int(lief.ELF.SYMBOL_SECTION_INDEX.COMMON):
                        symbol_address = binary.sections[symbol.value].virtual_address
                        symboltab[symbol.name] = symbol_address
                        continue
                sec_name = binary.sections[symbol.shndx].name
                symbol_address = sectab[sec_name] + symbol.value
                symboltab[symbol.name] = symbol_address
        return bs, sectab, symboltab

    @decorator_inc_debug_level
    def linkObjectFile(self, objfn, link_address, symboltab, info=None): 
        binary = lief.parse(objfn)
        bs, binary_sectab, binary_symboltab = self.writeObjectFile(binary, link_address);
        symboltab.update(binary_symboltab)
        logDebug(f'binary_sectab {binary_sectab}')
        return self.arch.dolink( bs, link_address, symboltab, binary, binary_sectab,  info)


class NopPatchStep(PatchStep):
    ''' 
        handle NopPatch
    ''' 
    name='NopPatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.ks = self.arch.getks(info)
         
    @decorator_inc_debug_level
    def run(self, write_address:list, ops:list=[]):
        # prepare all code 
        if self.start_address != None: self.start_address =self.arch.alignCodeAddress(self.start_address)
        if self.end_address != None:   self.end_address   = self.arch.alignCodeAddress(self.end_address)
        nopCode, count =  self.arch.asmCode(self.ks, self.arch.getNopCode(), self.start_address)
        assert count == 1
        if  self.end_address == None:
            ops.append(( self.start_address, nopCode))
        else:
            for addr in range(self.start_address, self.end_address, len(nopCode)):
                ops.append(( addr, nopCode))

class AsmPatchStep(PatchStep):
    ''' 
        handle NomPatch
    ''' 
    name='AsmPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.ks = self.arch.getks(info)
        self.asm = info['asm']
         
    @decorator_inc_debug_level
    def run(self, write_address:list, ops:list=[]):
        # prepare all code 
        self.start_address = self.arch.alignCodeAddress(self.start_address)
        nopCode, count =  self.arch.asmCode(self.ks, self.arch.getNopCode(), self.start_address)
        assert count == 1
        addr = self.start_address
        for code in self.asm:
            logDebug(f'code {code}')
            inst, count = self.arch.asmCode(self.ks, self.subSymbol(code), addr)
            assert count == 1
            ops.append(( addr, inst ))
            addr += len(inst)

class ParasitePatchStep(PatchStep):
    ''' 
        handle ParasitePatch, this patch step put a parasite code into a address space 
    ''' 
    name='ParasitePatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.offset             = eval(info['offset']) if 'offset' in info else 0
        self.srcfn              = info['src']
        self.compiler           = self.arch.compiler    
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags      = self.arch.compile_flags   
        if 'cflags' in info: self.compile_flags+=f' {info["cflags"]}'

    @decorator_inc_debug_level
    def run(self, write_address:list, ops:list=[]):
        self.compileSrcToCave(write_address,ops)

class BytesPatchStep(PatchStep):
    ''' 
        handle BytesPatch
    ''' 
    name='BytesPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.bytes = info['bytes']

    @decorator_inc_debug_level
    def run(self, write_address:list, ops:list=[]):
        ops.append(( self.start_address, bytes(self.bytes) ))

class HookPatchStep(PatchStep):
    ''' 
        handle HookFunPatch 
    ''' 
    name = 'HookPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        assert cave_length>0, " cave_length == 0 when do a hook patch "
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.offset             = eval(info['offset']) if 'offset' in info else 0
        self.srcfn             = stepinfo['src']
        self.hook_address      = self.start_address
        self.arch              = arch
        self.compiler          = self.arch.compiler    
        if 'compiler' in stepinfo: self.compiler = stepinfo['compiler']
        self.compile_flags     = self.arch.compile_flags
        if 'cflags' in stepinfo: self.compile_flags+= ' '+stepinfo['cflags']
        self.skip_orgin_code   = stepinfo['skipcode'] if 'skipcode' in stepinfo else False;

    def run(self, write_address:list, ops:list=[]):
        hook_address = self.start_address
        self.compileSrcToCave(write_address, ops,f'-D HOOK_ADDRESS={hex(hook_address)}')

        stub_address = cave_address

        self.arch.handleBFunPatch(hook_address, fun_address, stub_address, self.reg, self.ks, self.cs, self.binfile, self.skip_orgin_code, ops)



