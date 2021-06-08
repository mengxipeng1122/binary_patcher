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
    def run(self, write_cave_address:list, ops:list=[]):
        raise NotImplementedError('Should have implemented this ')

    @decorator_inc_debug_level
    def subSymbol(self,text):
        for k, v in self.symbolMap.items():
            text = text.replace('%{'+k+'}%', hex(v))
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
        inst, count = asmCode(self.ks, code, write_cave_address[0], self.info);
        self.writeBytesToCave(inst, write_cave_address, ops)
        return inst, count

    @decorator_inc_debug_level
    def compileSrcToCave(self, write_cave_address:list, ops:list, extera_compile_flags=""):
        write_cave_address[0] = self.arch.alignCodeAddress(write_cave_address[0])
        objfn = os.path.join('/tmp', os.path.basename(f'{self.srcfn}.o'))
        workdir = os.path.dirname(self.srcfn)
        if workdir == ' '*len(workdir): workdir = '.'
        cmd = f'cd {workdir}  && pwd && {self.compiler} -c -Wall -Werror -I.  {self.compile_flags} {extera_compile_flags} -o {objfn} {self.srcfn}'
        logDebug(f'go here')
        runCmd(cmd, showCmd=True, mustOk=True);
        logDebug(f'go here')
        bs, fun_addr = self.linkObjectFile(objfn, write_cave_address[0], self.symbolMap, self.info);
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
    def linkObjectFile(self, objfn, link_address, symboltab, info=None): 
        binary = lief.parse(objfn)
        bs, sectab, binary_symboltab = self.writeObjectFile(binary, link_address, info);
        symboltab.update(binary_symboltab)
        logDebug(f'sectab {sectab}')
        return self.arch.dolink( bs, link_address, symboltab, binary.object_relocations, sectab,  info)



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
    def run(self, write_cave_address:list, ops:list=[]):
        # prepare all code 
        if self.start_address != None: self.start_address =self.arch.alignCodeAddress(self.start_address)
        if self.end_address != None:   self.end_address   = self.arch.alignCodeAddress(self.end_address)
        nopCode, count =  asmCode(self.ks, self.arch.getNopCode(self.info), self.start_address)
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
        logDebug(" go here ");
        self.ks = self.arch.getks(info)
        logDebug(f" go here {self.ks}");
        self.asm = info['asm']
         
    @decorator_inc_debug_level
    def run(self, write_cave_address:list, ops:list=[]):
        # prepare all code 
        self.start_address = self.arch.alignCodeAddress(self.start_address)
        nopCode, count =  asmCode(self.ks, self.arch.getNopCode(self.info), self.start_address)
        assert count == 1
        addr = self.start_address
        for code in self.asm:
            logDebug(f'code {code}')
            code = self.subSymbol(code)
            logDebug(f'code {code} {self.ks}')
            inst, count = asmCode(self.ks, code, addr)
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
        self.compiler           = self.arch.info['compiler']
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags      = self.arch.info['cflags']
        if 'cflags' in info: self.compile_flags+=f' {info["cflags"]}'

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
        self.compiler          = self.arch.info['compiler']
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags     = self.arch.info['cflags']
        if 'cflags' in info: self.compile_flags+= ' '+info['cflags']
        self.ks = self.arch.getks(info)
        self.cs = self.arch.getcs(info)

    def run(self, write_cave_address:list, ops:list=[]):
        hook_address = self.arch.alignCodeAddress(self.start_address)

        logDebug(f'')
        fun_address = self.compileSrcToCave(write_cave_address, ops,f'-D HOOK_ADDRESS={hex(hook_address)}')
        logDebug(f'')

        stub_address = write_cave_address[0] = self.arch.alignCodeAddress(write_cave_address[0])
        nop_ins,count = asmCode(self.ks, self.arch.getNopCode(self.info)); assert count ==1;
        # write jmp stub instructions
        jmp_stub_inst, count = asmCode(self.ks, self.arch.getJumpCode(hook_address, stub_address, self.info), hook_address); assert count ==1;
        # read original instructions 
        jmp_stub_bs = jmp_stub_inst
        original_bs = b''
        while True:
            le_jmp_stub_bs = len(jmp_stub_bs)
            le_original_bs = len(original_bs)
            if le_jmp_stub_bs > 0x20: raise  Exception('many trails for jump stub instruction')
            if le_original_bs > 0x20: raise  Exception('many trails for jump stub instruction')
            if isValidInstructions(self.cs, self.ks, original_bs, hook_address):
                if le_jmp_stub_bs == le_original_bs: break
            if le_jmp_stub_bs > le_original_bs:
                original_bs = self.binfmt.readByte(hook_address, le_original_bs+1)
                continue
            else:
                jmp_stub_bs += nop_ins
                continue
        ops.append( ( hook_address, jmp_stub_bs ) )

        jump_back_address = hook_address+len(jmp_stub_bs);

        ################################################################################ 
        # write stub  
        #  write save context code
        self.putAsmCodesToCave(self.arch.getSaveContextCode(self.info), write_cave_address, ops)
        #  write call function code
        inst, count = self.putAsmCodesToCave(self.arch.getCallCode(write_cave_address[0], fun_address, self.info), write_cave_address, ops); assert count ==1
        #  write restore context code
        self.putAsmCodesToCave(self.arch.getRestoreContextCode(self.info), write_cave_address, ops)
        #  write original instructions
        fixed_original_bs = moveCode(self.cs, self.ks, original_bs, hook_address, write_cave_address[0], self.info)
        self.writeBytesToCave(fixed_original_bs, write_cave_address, ops)
        #  write jmp back instructions
        inst, count = self.putAsmCodesToCave(self.arch.getJumpCode(write_cave_address[0], jump_back_address, self.info), write_cave_address, ops); assert count ==1;

class BFunPatchStep(PatchStep):
    ''' 
        handle BFunPatch 
    ''' 
    name = 'BFunPatch'
    @decorator_inc_debug_level
    def __init__(self, info, arch, binfmt, symbolMap):
        PatchStep.__init__(self, info, arch, binfmt, symbolMap)
        self.srcfn             = info['src']
        self.compiler          = self.arch.info['compiler']
        if 'compiler' in info: self.compiler = info['compiler']
        self.compile_flags     = self.arch.info['cflags']
        if 'cflags' in info: self.compile_flags+= ' '+info['cflags']
        self.ks = self.arch.getks(info)
        self.cs = self.arch.getcs(info)

    def run(self, write_cave_address:list, ops:list=[]):
        hook_address = self.arch.alignCodeAddress(self.start_address)

        logDebug(f'')
        fun_address = self.compileSrcToCave(write_cave_address, ops,f'-D FUN_ADDRESS={hex(hook_address)}')
        fun_address = self.arch.alignCodeAddress(fun_address)
        logDebug(f'')

        stub_address = write_cave_address[0] = self.arch.alignCodeAddress(write_cave_address[0])
        nop_ins,count = asmCode(self.ks, self.arch.getNopCode(self.info)); assert count ==1;
        ################################################################################ 
        # write jmp instruction
        logDebug(f" hook_address {hex(hook_address)}")
        logDebug(f" fun_address  {hex(fun_address )}")
        inst, count = self.putAsmCodesToCave(self.arch.getJumpCode(hook_address, fun_address, self.info), write_cave_address, ops); assert count ==1;

