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
    if showCmd:
        print (cmd)
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
    if mustOk:
        if p_status !=0: raise Exception('run %s failed %d' %(cmd, p_status))
    return result

