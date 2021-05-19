#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

import os
import json
import BinaryPatcher
BinaryPatcher_path = BinaryPatcher.__path__
from BinaryPatcher.BinaryPatcher import *
import binascii
import argparse


def main():
    parser = argparse.ArgumentParser(description='Binary patcher based by LIEF')
    parser.add_argument('-i', '--info', help='patch info .json file name', required=True)
    parser.add_argument('srcfn', help='source file name')
    parser.add_argument('tagfn', help='target file name')
    args = parser.parse_args()

    patcher = BinaryPatcher(json.load(open(args.info)))
    patcher.load(args.srcfn)
    patcher.run()
    patcher.write(args.tagfn)
    log(f'<G> Bye')

if __name__ == '__main__':
    print(f"BinaryPatcher {BinaryPatcher_path}");
    main()

