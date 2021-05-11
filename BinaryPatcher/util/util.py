#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import math
from .log import *

@decorator_inc_debug_level
def getAlignAddr(o, align=4):
  '''
This function get a aligned address 
  '''
  o = int(math.ceil(o*1./align)*align)
  return o


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



