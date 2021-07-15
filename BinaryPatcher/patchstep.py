#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import lief
import re
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
    def run(self, write_cave_address:list, ops:list=[]):
        raise NotImplementedError('Should have implemented this ')

    @decorator_inc_debug_level
    def subSymbol(self,text):
        for k, v in self.symbolMap.items():
            text = text.replace('%{'+k+'}%', hex(v))
        m = re.findall('%{sub_[0-9A-Fa-f]*}%', text)
        for t in m:
            tc = f'0x{t[6:-2]}'
            text = text.replace(t, tc)
        return text

    @decorator_inc_debug_level
    def calAddress(self,text):
        if text == None: return None
        if isinstance(text, str): return eval(self.subSymbol(text))
        if isinstance(text, int): return text
        raise Exception(f'unsupported text type {text} {type(text)}')

    @decorator_inc_debug_level
    def writeBytesToCave(self, bs, write_cave_address:list, ops:list):
        ops.append(( write_cave_address[0],bs))
        write_cave_address[0] += len(bs)

    @decorator_inc_debug_level
    def putAsmCodesToCave(self, code, write_cave_address:list, ops:list):
        inst, count = self.arch.asmCode(code, write_cave_address[0], self.info);
        self.writeBytesToCave(inst, write_cave_address, ops)
        return inst, count

    @decorator_inc_debug_level
    def compileSrcToCave(self, write_cave_address:list, ops:list, extera_compile_flags=""):
        src_addr = write_cave_address[0]
        objfn = self.arch.compileSrc(self.srcfn, src_addr, self.compiler, self.compile_flags, self.symbolMap, self.info);
        bs, fun_addr = self.linkObjectFile(objfn, src_addr, self.symbolMap);
        self.writeBytesToCave(bs, write_cave_address, ops)
        return fun_addr

    @decorator_inc_debug_level
    def writeObjectFile(self, binary, write_cave_address:int, info=None): 
        '''
            binary -- parsed variable by lief library
            write_cave_address -- address that entire bytes will write 
            put binary data to a wrote for linking, 
            work only for ELF format now
        '''
        bs = b""
        # write sections
        next_write_address = getAlignAddr(write_cave_address, 0x10);
        bs += b'\0'*(next_write_address-write_cave_address)
        write_cave_address=next_write_address
        sectab ={}
        for i, sec in enumerate(binary.sections):
            if lief.ELF.SECTION_FLAGS.ALLOC in sec.flags_list:
                if sec.type == lief.ELF.SECTION_TYPES.NOBITS:
                    bs += b'\0'*sec.size
                else:
                    bs += bytes(sec.content)
                sec.virtual_address=write_cave_address; # set linked virtual_address
                write_cave_address += sec.size
                next_write_address = getAlignAddr(write_cave_address, 0x10);
                bs += b'\0'*(next_write_address-write_cave_address)
                write_cave_address=next_write_address
                sectab[i] = sec.virtual_address # record all section address 
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
                symbol_address = sectab[symbol.shndx] + symbol.value
                symboltab[symbol.name] = symbol_address
        return bs, sectab, symboltab

    @decorator_inc_debug_level
    def linkObjectFile(self, objfn, link_address:int, symboltab): 
        binary = lief.parse(objfn)
        bs, sectab, binary_symboltab = self.writeObjectFile(binary, link_address);
        symboltab.update(binary_symboltab)
        return self.arch.dolink( bs, link_address, symboltab, binary.object_relocations, sectab, self.info)



class NopPatchStep(PatchStep):
    ''' 
        handle NopPatch
    ''' 
    name='NopPatch'

    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
         
    @decorator_inc_debug_level
    def run(self, write_cave_address:list, ops:list=[]):
        # prepare all code 
        nop_ins, count = self.arch.getNopInstruction(self.start_address, self.info); assert count ==1;
        if  self.end_address == None:
            ops.append(( self.start_address, nop_ins))
        else:
            for addr in range(self.start_address, self.end_address, len(nop_ins)):
                ops.append(( addr, nop_ins))

class AsmPatchStep(PatchStep):
    ''' 
        handle NomPatch
    ''' 
    name='AsmPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.asm = info['asm']
         
    @decorator_inc_debug_level
    def run(self, write_cave_address:list, ops:list=[]):
        # prepare all code 
        addr = self.start_address
        for code in self.asm:
            logDebug(f'code {code}')
            code = self.subSymbol(code)
            inst, count = self.arch.asmCode( code, addr, self.info); assert count ==1;
            logDebug(" go here ");
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
        if 'compile_flags' in info: self.compile_flags+=f' {info["compile_flags"]}'

    @decorator_inc_debug_level
    def run(self, write_cave_address:list, ops:list=[]):
        self.compileSrcToCave(write_cave_address,ops)

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
    def run(self, write_cave_address:list, ops:list=[]):
        ops.append(( self.start_address, bytes(self.bytes) ))

class StrPatchStep(PatchStep):
    ''' 
        handle StrPatch
    ''' 
    name='StrPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.str  = info['str']

    @decorator_inc_debug_level
    def run(self, write_cave_address:list, ops:list=[]):
        ops.append(( self.start_address, bytes(self.str,'utf-8')+b'\0' ))


class HookPatchStep(PatchStep):
    ''' 
        handle HookFunPatch 
    ''' 
    name = 'HookPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.offset            = eval(info['offset']) if 'offset' in info else 0
        self.srcfn             = info['src']
        self.hook_address      = self.start_address
        self.compiler          = self.arch.compiler
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags     = self.arch.compile_flags
        if 'compile_flags' in info: self.compile_flags+= ' '+info['compile_flags']
        self.skipOriginInst    = False
        if 'skipOriginInstruction' in info:
            self.skipOriginInst   = info['skipOriginInstruction']
        self.info              = info;

    def run(self, write_cave_address:list, ops:list=[]):
        hook_address = (self.start_address)

        fun_address = self.compileSrcToCave(write_cave_address, ops,f'-D HOOK_ADDRESS={hex(hook_address)}')

        stub_address = write_cave_address[0] 
        # write jmp stub instructions
        jmp_stub_inst, count = self.arch.getJumpInstruction(hook_address, stub_address, self.info); assert count ==1;
        # read original instructions 
        MAX_ORIGINAL_INSTR_LEN=0x20;
        jmp_stub_bs = jmp_stub_inst
        original_bs = b''
        while True:
            le_jmp_stub_bs = len(jmp_stub_bs)
            le_original_bs = len(original_bs)
            if le_jmp_stub_bs > MAX_ORIGINAL_INSTR_LEN: raise  Exception('many trails for jump stub instruction')
            if le_original_bs > MAX_ORIGINAL_INSTR_LEN: raise  Exception('many trails for jump stub instruction')
            if le_jmp_stub_bs == le_original_bs:
                if self.arch.isValidInstructions(original_bs, hook_address, self.info):
                    break
            if le_jmp_stub_bs > le_original_bs:
                original_bs = self.binfmt.readByte(self.arch.alignAddressForAccess(hook_address), le_original_bs+1)
            else:
                nop_ins, count = self.arch.getNopInstruction(hook_address+le_jmp_stub_bs, self.info); assert count ==1;
                jmp_stub_bs += nop_ins
        ops.append( ( hook_address, jmp_stub_bs ) )

        jump_back_address = hook_address+len(jmp_stub_bs);

        ################################################################################ 
        # write stub  
        #  write save context code
        inst, count = self.arch.getSaveContextInstruction( write_cave_address[0], self.info)
        self.writeBytesToCave(inst, write_cave_address, ops)
        #  write call function code
        inst, count = self.arch.getCallInstruction(write_cave_address[0], fun_address, self.info ); assert count ==1
        count = self.writeBytesToCave(inst, write_cave_address, ops); 
        #  write restore context code
        inst, count = self.arch.getRestoreContextInstruction(write_cave_address[0], self.info)
        self.writeBytesToCave(inst, write_cave_address, ops)
        #  write original instructions
        if not self.skipOriginInst:
            fixed_original_bs = self.arch.moveCode(original_bs, hook_address, write_cave_address[0], self.info)
            self.writeBytesToCave(fixed_original_bs, write_cave_address, ops)
        #  write jmp back instructions
        inst, count = self.arch.getJumpInstruction(write_cave_address[0], jump_back_address, self.info); assert count ==1;
        self.writeBytesToCave(inst, write_cave_address, ops)

class BFunPatchStep(PatchStep):
    ''' 
        handle BFunPatch 
    ''' 
    name = 'BFunPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.srcfn             = info['src']
        self.compiler          = self.arch.compiler
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags     = self.arch.compile_flags
        if 'compile_flags' in info: self.compile_flags+= ' '+info['compile_flags']
        self.ks = self.arch.getKs(info)
        self.cs = self.arch.getCs(info)

    def run(self, write_cave_address:list, ops:list=[]):
        hook_address = self.start_address

        logDebug(f'')
        fun_address = self.compileSrcToCave(write_cave_address, ops,f'-D FUN_ADDRESS={hex(hook_address)}')
        logDebug(f'')

        stub_address = write_cave_address[0]
        #nop_ins,count = self.arch.asmCode( self.arch.getNopInstruction(self.info)); assert count ==1;
        ################################################################################ 
        # write jmp instruction
        logDebug(f" hook_address {hex(hook_address)}")
        logDebug(f" fun_address  {hex(fun_address )}")
        inst, count = self.arch.getJumpInstruction(hook_address, fun_address, self.info); assert count ==1;
        ops.append( ( hook_address, inst ) )
        
