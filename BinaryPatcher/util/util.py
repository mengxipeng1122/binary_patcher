#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import math
import subprocess
from .log import *

@decorator_inc_debug_level
def getAlignAddr(o, align=4):
  '''
This function get a aligned address 
  '''
  o = int(math.ceil(o*1./align)*align)
  return o


@decorator_inc_debug_level
def getStr(s, READNAMELEN=80):
  '''
This function get a string from bytes
must return string 
Parameter:
  s -- input bytes
  READNAMELEN -- assume the size of result string is not larger then READNAMELEN
  '''
  idx = s[:READNAMELEN].find(b'\0')
  return s[:idx].decode('utf-8')




@decorator_inc_debug_level
def runCmd(cmd, showCmd =True, mustOk=False, showResult=False):
    '''
      run a shell command  on PC
      and return the output result
      parameter:
        cmd --- the command line
        showCmd -- whether show running command
        mustOk -- if this option is True and command run failed, then raise a exception
        showResult -- show result of command
    '''
    logDebug(f'mustOk{mustOk}')
    if showCmd:
        print (cmd)
    logDebug(f'mustOk{mustOk}')
    ## run it ''
    result = ""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    ## But do not wait till netstat finish, start displaying output immediately ##
    while True:
        try:
                output = p.stdout.readline().decode()
        except UnicodeDecodeError as e:
                print(' UnicodeDecodeError ', e);
        if output == '' and p.poll() is not None:
            break
        if output:
            result+=str(output)
            if showResult:
                print(output.strip())
                sys.stdout.flush()
    stderr = p.communicate()[1]
    if stderr:
        print (f'STDERR:{stderr}')
    p_status = p.wait()
    logDebug(f'mustOk{mustOk}')
    if mustOk:
        logDebug(f'69 p_status {p_status}')
        if p_status !=0: raise Exception('run %s failed %d' %(cmd, p_status))
    return result

@decorator_inc_debug_level
def asmCode(ks, code, address=0, info=None):
    binCode, count = ks.asm(code, address); 
    return bytes(binCode), count

@decorator_inc_debug_level
def disasmCode(cs, inst, address=0, info=None):
    codes = ""
    for i in cs.disasm(inst, address): 
        codes += f'{i.mnemonic}\t {i.op_str}\n'
    return codes

@decorator_inc_debug_level
def isValidInstructions(cs, ks, bs, address, info=None):
    ''' 
        this function check whether the given bytes is a complete code, 
    ''' 
    codes = disasmCode(cs, bs, address, info);
    binCode, count = ks.asm(codes, address, info)
    if binCode == None: return False;
    return bs == bytes(binCode);

@decorator_inc_debug_level
def moveCode(cs, ks, bs, from_address, to_address, info=None):
    ''' 
        this function check whether the given bytes is a complete code, 
    ''' 
    codes = disasmCode(cs, bs, from_address, info);
    binCode, count = ks.asm(codes, to_address, info)
    assert binCode!=None, f'binCode equals to None'
    return bytes(binCode)


