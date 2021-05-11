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


