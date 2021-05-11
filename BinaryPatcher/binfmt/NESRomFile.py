#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import magic

from .BinFile import BinFile
from ..util.log import *

class NESRomFile(BinFile):
    @decorator_inc_debug_level
    def __init__(self):
        pass

    @decorator_inc_debug_level
    def getName(self):
        return "NESRomFile"

    @decorator_inc_debug_level
    def load(self, fn):
        return True


