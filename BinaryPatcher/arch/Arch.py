#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import lief
from keystone import *
from capstone import *

from ..util.log  import *
from ..util.util import *

class Arch(object):
    '''
        a abstract class for all architecture class
    '''

    name            = None

    @decorator_inc_debug_level
    def __init__(self):
        self.compiler       = None
        self.compile_flags  = ""

    @decorator_inc_debug_level
    def loadInfo(self, info=None):
        if info!=None:
            for k, v in inspect.getmembers(self):
                # skip all functions
                if inspect.ismethod(v):  continue
                # skip all private and protected
                if k.startswith('_'): continue;
                if k in info:
                    setattr(self, k, info[k])
        
    @decorator_inc_debug_level
    def getNopInstruction(self, address, info=None):
        raise NotImplementedError( "Should have implemented this method" )

    def getJumpInstruction(self, from_address, to_address, info=None): 
        raise NotImplementedError( "Should have implemented this method" )

    def getCallInstruction(self, caller_address, callee_address, info=None): 
        raise NotImplementedError( "Should have implemented this method" )

    def getSaveContextInstruction(self, address, info=None): 
        raise NotImplementedError( "Should have implemented this method" )

    def getRestoreContextInstruction(self, address, info=None): 
        raise NotImplementedError( "Should have implemented this method" )

    @decorator_inc_debug_level
    def getInfo(self):
        return { k : v for k, v in inspect.getmembers(self) if not inspect.ismethod(v) and not k.startswith('_') }
  
    @decorator_inc_debug_level
    def dolink(self, bs, link_address, symboltab, relocs, sectab, info=None):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def alignAddressForAccess(self, address:int):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def asmCodeWithKs(self, ks, code, address):
        logDebug(f'  {code}, {hex(address)}')
        binCode, count = ks.asm(code, address); 
        return bytes(binCode), count

    @decorator_inc_debug_level
    def disasmCodeWithCs(self, cs, inst, address):
        codes = ""
        for i in cs.disasm(inst, address): 
            codes += f'{i.mnemonic}\t {i.op_str}\n'
        return codes
    
    @decorator_inc_debug_level
    def asmCode(self, code, address, info=None):
        ks = self.getKs(address, info)
        return self.asmCodeWithKs(ks, code, address);
    
    
    @decorator_inc_debug_level
    def disasmCode(self, inst, address, info=None):
        cs = self.getCs(address, info);
        return self.disasmCodeWithCs(cs, inst, address) 

    @decorator_inc_debug_level
    def isValidInstructions(self,inst, address, info=None):
        ''' 
            this function check whether the given bytes is a complete code, 
        ''' 
        ks = self.getKs(address, info)
        print(ks._arch, ks._mode)
        logDebug(f"ks {ks}")
        codes = self.disasmCode( inst, address, info);
        logDebug(f"codes {codes}")
        binCode, count = ks.asm(codes, address)
        logDebug(f"binCode {binCode} {count}")
        if binCode == None: return False;
        return inst == bytes(binCode);

    @decorator_inc_debug_level
    def moveCode(self, bs, from_address, to_address, info=None):
        ''' 
            this function check whether the given bytes is a complete code, 
        ''' 
        cs = self.getCs(from_address, info);
        codes = self.disasmCodeWithCs(cs, bs, from_address);
        ks = self.getKs(to_address, info);
        binCode, count = ks.asm(codes, to_address)
        assert binCode!=None, f'binCode equals to None'
        return bytes(binCode)
    
    @decorator_inc_debug_level
    def getCs(self, address, info=None):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def getKs(self, address, info=None):
        raise NotImplementedError( "Should have implemented this" )

    @decorator_inc_debug_level
    def compileSrc(self, srcfn, address, compiler, compile_flags, symbolMap, info=None):
        objfn = os.path.join('/tmp', os.path.basename(f'{srcfn}.o'))
        workdir = os.path.dirname(srcfn)
        if workdir == ' '*len(workdir): workdir = '.'
        cmd = f'cd {workdir}  && pwd && {compiler} -c -Wall -Werror -I.  {compile_flags} -o {objfn} {srcfn}'
        runCmd(cmd, showCmd=True, mustOk=True);
        return  objfn

