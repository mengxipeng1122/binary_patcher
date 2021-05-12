#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct

from keystone import *
from capstone import *

from ..util.log import *
from .Arch import *

class Arm(Arch):
    thumbMode       = False

    @decorator_inc_debug_level
    def __init__(self, info=None):
        thumbMode = False
        if info != None and 'ThumbMode' in info:
            thumbMode = info['ThumbMode']
        if thumbMode:
            Arch.__init__(self, KS_ARCH_ARM, KS_MODE_THUMB, CS_ARCH_ARM, CS_MODE_THUMB, info)
        else:
            Arch.__init__(self, KS_ARCH_ARM, KS_MODE_ARM, CS_ARCH_ARM, CS_MODE_ARM, info)
        self.compiler        = 'arm-linux-gnueabihf-gcc'
        self.thumbMode       = thumbMode;

    @decorator_inc_debug_level
    def getNopCode(self):
        return "nop"

    @decorator_inc_debug_level
    def parsePlTSecUpdateSymol(self, sec, address, pltmap, m ):
        # trick get __GLOBAL_OFFSET_TABLE_ address
        ins0, ins1, ins2, ins3, ins4 = struct.unpack('IIIII', sec[0x00:0x14])
        if 0xe52de004 == ins0 and 0xe59fe004 == ins1 and 0xe08fe00e == ins2 and 0xe5bef008 == ins3:
            off = ins4
            symbolname = '_GLOBAL_OFFSET_TABLE_'
            addr = address + 0x10 + off
            m[symbolname] = addr
        for o in range(0, len(sec) - 0x08, 0x04):
            ins0, ins1, ins2 = struct.unpack('III', sec[o:o+0x0c])
            # hard code for arm instruction 
            if ins0 & 0xffffff00 == 0xe28fc600 and ins1 & 0xffffff00 == 0xe28cca00 and ins2 & 0xfffff000 == 0xe5bcf000:
                off = (ins0 &  0xff)<<0x14
                off+= (ins1 &  0xff)<<0x0c
                off+= (ins2 & 0xfff)<<0x00
                addr= address+o+8+off
                if addr in pltmap:
                    symbolname = pltmap[addr]
                    m[symbolname] = address + o 

    @decorator_inc_debug_level
    def getInfo(self):
        info = Arch.getInfo(self)
        info['name'] = 'ARM'
        info['ThumbMode'] = self.thumbMode;
        return info
        
    @decorator_inc_debug_level
    def compileObjectFile(self, srcfn, objfn, workdir, compiler, compile_flags, info):
        if 'ThumbMode' in info:
            if info['ThumbMode']:
                compile_flags += ' -mthumb'
            else:
                compile_flags += ' -marm'
        else:
            if self.thumbMode:
                compile_flags += ' -mthumb'
            else:
                compile_flags += ' -marm'
        Arch.compileObjectFile(self, srcfn, objfn, workdir, compiler, compile_flags, info)


    @decorator_inc_debug_level
    def getks(self, info):
        if 'ThumbMode' in info:
            if info['ThumbMode']:
                ks_mode = KS_MODE_THUMB;
            else:
                ks_mode = KS_MODE_ARM;
        else:
            if self.thumbMode:
                ks_mode = KS_MODE_THUMB;
            else:
                ks_mode = KS_MODE_ARM;
        return Ks(self.ks_arch, ks_mode)


    @decorator_inc_debug_level
    def dolink(self, bs, link_address, symboltab, binary, binary_sectab, info):
        ks = self.getks(info)
        bs = bytearray(bs)
        # write bytes for link 
        for reloc in binary.object_relocations:
            assert reloc.has_symbol, f'has not symbol in reclocation {reloc}'
            logDebug(f'reloc {reloc}')
            if not reloc.has_section: continue
            if  reloc.section.type != lief.ELF.SECTION_TYPES.PROGBITS   \
            and reloc.section.type != lief.ELF.SECTION_TYPES.NOBITS:
                continue
            address = reloc.section.virtual_address+reloc.address
            P = address
            offset  = address - link_address
            if reloc.symbol.name!='':
                if reloc.symbol.name in symboltab: symbol_addr = symboltab[reloc.symbol.name]
                else: raise Exception(f"can not found address for symbol {reloc.symbol.name} ")
            else:
                if reloc.symbol.type == lief.ELF.SYMBOL_TYPES.SECTION:
                    sec_name = binary.sections[reloc.symbol.shndx].name
                    symbol_addr = binary_sectab[sec_name]
            assert symbol_addr!=0, f'symboltab error {symboltab} {reloc.symbol.name} {reloc}'
            S = symbol_addr;
            A = struct.unpack('I', bs[offset:offset+4])[0]
        
            if reloc.type == 2: # R_ARM_ABS32
                originw = struct.unpack('I',bs[offset:offset+4])[0];
                bs[offset:offset+4] = struct.pack('I', symbol_addr+originw);
        
            elif reloc.type ==  3: # R_ARM_REL32
                # ((S + A) | T) | P
                w = (S+A) - P
                bs[offset:offset+4] = struct.pack('I', w)
        
            elif reloc.type == 10: # R_ARM_THM_CALL
                code = f'BLX {hex(symbol_addr)}'
                binCode, count = Arch.asmCode(self, ks, code, address); 
                assert count == 1
                ins = bytearray(binCode)
                bs[offset:offset+len(ins)] = ins
        
            elif reloc.type == 25: # R_ARM_BASE_PREL
                originw = struct.unpack('I',bs[offset:offset+4])[0];
                w = symbol_addr+originw-address
                bs[offset:offset+4] = struct.pack('i', w)

            elif reloc.type == 26: # R_ARM_GOT_PREL
                w = symboltab[f"{reloc.symbol.name}_ptr"] - symboltab[f'_GLOBAL_OFFSET_TABLE_']
                bs[offset:offset+4] = struct.pack('i', w)
                
            elif reloc.type == 28: # R_ARM_CALL
                code = f'BL {hex(symbol_addr)}'
                binCode, count = ks.asm(code, address); assert count == 1
                ins = bytearray(binCode)
                bs[offset:offset+len(ins)] = ins
        
            elif reloc.type == 43:#  R_ARM_MOVW_ABS_NC
                insn = list(cs.disasm(bs[offset:offset+4], address))[0]
                mnemonic = insn.mnemonic; 
                reg =  insn.op_str.split(',')[0]
                code = f'{mnemonic}\t{reg}, #{hex((symbol_addr>>0x00)&0xffff)}'
                binCode, count = ks.asm(code, address); assert count == 1
                ins = bytearray(binCode)
                bs[offset:offset+len(ins)] = ins
        
            elif reloc.type == 44:#  R_ARM_MOVW_ABS
                insn = list(cs.disasm(bs[offset:offset+4], address))[0]
                mnemonic = insn.mnemonic; 
                reg =  insn.op_str.split(',')[0]
                code = f'{mnemonic}\t{reg}, #{hex((symbol_addr>>0x10)&0xffff)}'
                binCode, count = ks.asm(code, address); assert count == 1
                ins = bytearray(binCode)
                bs[offset:offset+len(ins)] = ins
        
            elif reloc.type == 47:# R_ARM_THM_MOVW_ABS_NC
                insn = list(cs.disasm(bs[offset:offset+4], address))[0]
                mnemonic = insn.mnemonic; 
                reg =  insn.opt_str.split(',')[0]
                code = '{mnemonic}\t{reg}, #{hex((symbol_addr>>0x00)&0xffff)}'
                binCode, count = ks.asm(code, address); assert count == 1
                ins = bytearray(binCode)
                bs[offset:offset+len(ins)] = ins
        
            elif reloc.type == 48:# R_ARM_THM_MOVT_ABS
                insn = list(cs.disasm(bs[offset:offset+4], address))[0]
                mnemonic = insn.mnemonic; 
                reg =  insn.opt_str.split(',')[0]
                code = '{mnemonic}\t{reg}, #{hex((symbol_addr>>0x10)&0xffff)}'
                ins = bytearray(binCode)
                bs[offset:offset+len(ins)] = ins
            else:
                raise Exception(f'{reloc.type} unsupported reloc type')
        # calculate 'fun' symbol address
        return (bytes(bs), symboltab['fun'] & 0xffffffff if 'fun' in symboltab else None )

    @decorator_inc_debug_level
    def alignCodeAddress(self, address):
        if address == None: return None
        return address & 0xfffffffe

    @decorator_inc_debug_level
    def alignDataAddress(self, address):
        if address == None: return None
        return address & 0xfffffffc


