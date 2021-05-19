#!/usr/bin/env python
# -*- coding: utf-8 -*-


from .Arch  import *
from .Arm   import *
from .M6502 import *

arch_clzs = { obj.name : obj for name, obj in inspect.getmembers(sys.modules[__name__]) if inspect.isclass(obj) and issubclass(obj, Arch) and obj.name != None }

