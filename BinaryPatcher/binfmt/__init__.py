#!/usr/bin/env python
# -*- coding: utf-8 -*-


from .BinFile       import *
from .ELFFile       import *
from .GBARomFile    import *
from .NESRomFile    import *

bin_fmt_clzs = { obj.name : obj for name, obj in inspect.getmembers(sys.modules[__name__]) if inspect.isclass(obj) and issubclass(obj, BinFile) and obj.name != None }

bin_fmt_magic_map =  {
        'application/x-sharedlib' : ELFFile,
        'application/x-gba-rom'   : GBARomFile ,
        'application/x-nes-rom'   : NESRomFile ,
}


