#!/usr/bin/env python
# -*- coding: utf-8 -*-


from .ELFFile       import *
from .GBARomFile    import *
from .NESRomFile    import *

bin_fmt_clzs =  {
        'ELFFile':      ELFFile ,
        'GBARom':       GBARomFile ,
        'NESRom':       NESRomFile ,
}

bin_fmt_magic_map =  {
        'application/x-sharedlib' : ELFFile,
        'application/x-gba-rom'   : GBARomFile ,
        'application/x-nes-rom'   : NESRomFile ,
}


