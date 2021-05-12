#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief
from mxp.utils import *
from ..util.log import *

class Arch(object):
    '''
        a abstract class for all architecture class
    '''

    compiler        = None
    compile_flags   = ""

    @decorator_inc_debug_level
    def __init__(self, ks_arch, ks_mode, cs_arch, cs_mode, info=None):
        self.ks_arch = ks_arch 
        self.ks_mode = ks_mode 
        self.cs_arch = cs_arch 
        self.cs_mode = cs_mode 
        if info != None and 'cflags' in info:
            self.compile_flags = info['cflags']
        
    @decorator_inc_debug_level
    def getNopInstruction(self,address, info=None): 
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def asmCode(self, ks, code, address=0):
        binCode, count = ks.asm(code, address); 
        return bytes(binCode), count

    @decorator_inc_debug_level
    def parsePlTSecUpdateSymol(self, sec, address, pltmap, m ):
        '''
            this method parse .plt section dat to update a map of symbol name ->  plt stub address 
            augments :
                sec -- content of .plt section , of type bytes
                address -- address of .plt section 
                pltmap  -- a map of  actual plt address => symbol name 
                m  -- symbol map need to upate
        ''' 
        raise NotImplementedError( "Should have implemented this" )
    
    @decorator_inc_debug_level
    def getInfo(self):
        return {
            'KS_ARCH' : self.ks_arch,
            'KS_MODE' : self.ks_mode,
            'CS_ARCH' : self.cs_arch,
            'CS_MODE' : self.cs_mode,
            'cflags'  : self.compile_flags,
        }
    
    @decorator_inc_debug_level
    def compileObjectFile(self, srcfn, objfn, workdir, compiler, compile_flags, info):
        cmd = f'cd {workdir}  && pwd && {compiler} -c -Wall -Werror -I.  {compile_flags} -o {objfn} {srcfn}'
        runCmd(cmd, showCmd=True, mustOk=True);

    @decorator_inc_debug_level
    def getks(self, info):
        return Ks(self.ks_arch, self.ks_mode)

    @decorator_inc_debug_level
    def writeObjectFile(self, binary, write_address): 
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
    def linkObjectFile(self, objfn, link_address, symboltab, info): 
        binary = lief.parse(objfn)
        bs, binary_sectab, binary_symboltab = self.writeObjectFile(binary, link_address);
        symboltab.update(binary_symboltab)
        logDebug(f'binary_sectab {binary_sectab}')
        return self.dolink( bs, link_address, symboltab, binary, binary_sectab,  info)

    @decorator_inc_debug_level
    def dolink(self, bs, link_address, symboltab, binary, binary_sectab, info):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def alignCodeAddress(self, address):
        raise NotImplementedError( "Should have implemented this" )
        
    @decorator_inc_debug_level
    def alignDataAddress(self, address):
        raise NotImplementedError( "Should have implemented this" )
        
