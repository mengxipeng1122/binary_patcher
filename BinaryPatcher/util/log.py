#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from .color import *

'''
    list all log function , set different color using color module

'''

indent_space=2

def logError(msg, indent=0):         # display error info, and raise exception
    Color.pl(f'<R>{" "*indent_space*indent}{msg}')
    raise Exception(msg)

def logInfo(msg, indent=0):          # display normal info 
    Color.pl(f'<G>{" "*indent_space*indent}{msg}')

def logNotice(msg, indent=0):        # display noticeable  info
    Color.pl(f'<W>{" "*indent_space*indent}{msg}')
    
def logWarn(msg, indent=0):          # display warning info
    Color.pl(f'<P>{" "*indent_space*indent}{msg}')

def logDebug(msg, indent=0):          # display warning info
    Color.pl(f'<C>{" "*indent_space*indent}{msg}')
    
    
def log(msg, indent=0):              # call log.pl directly
    Color.pl(f'{" "*indent_space*indent}{msg}')

