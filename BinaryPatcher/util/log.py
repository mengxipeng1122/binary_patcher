#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from inspect import currentframe, getframeinfo
from .color import *

'''
    list all log function , set different color using color module

'''

LOG_LEV_ERROR  =0 
LOG_LEV_WARN   =1 
LOG_LEV_NOTICE =2 
LOG_LEV_INFO   =3 
LOG_LEV_DEBUG  =4 

log_indent_space=2
log_indent = 0
log_level  = LOG_LEV_DEBUG

def logError(msg):         # display error info, and raise exception
    if log_level>= LOG_LEV_ERROR: Color.pl(f'<R>{" "*log_indent_space*log_indent}{msg}')
    raise Exception(msg)

def logInfo(msg):          # display normal info 
    if log_level>= LOG_LEV_INFO: Color.pl(f'<G>{" "*log_indent_space*log_indent}{msg}')

def logNotice(msg):        # display noticeable  info
    if log_level>= LOG_LEV_NOTICE: Color.pl(f'<W>{" "*log_indent_space*log_indent}{msg}')
    
def logWarn(msg):          # display warning info
    if log_level>= LOG_LEV_WARN:   Color.pl(f'<P>{" "*log_indent_space*log_indent}{msg}')

def logDebug(msg):          # display warning info
    if log_level>= LOG_LEV_DEBUG:  Color.pl(f'<C>{" "*log_indent_space*log_indent}{msg}')
    
def log(msg):              # call log.pl directly
    Color.pl(f'{" "*log_indent_space*log_indent}{msg}')


def decorator_inc_debug_level(f):
    def wrapper(*args,**kwargs):
        global log_indent
        assert log_indent>=0, f'error log indent {log_indent} '
        log_indent+=1
        ret = f(*args)
        log_indent-=1
        return ret
    return wrapper
