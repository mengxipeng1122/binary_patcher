#!/usr/bin/env python
# -*- coding: utf-8 -*-
 
import inspect

from .patchstep import *

# all patch step classes 
patchstep_map = { obj.name : obj for name, obj in inspect.getmembers(sys.modules[__name__]) if inspect.isclass(obj) and issubclass(obj, PatchStep) and obj.name != None }

