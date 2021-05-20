#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief
import struct
import argparse
from BinaryPatcher.util.util import *

################################################################################
# encrypt ELF file use XOR algorithm
# use section offset in ELF header to indicate offset of encrypt table 
# in another words, reduce section table, use encryption table 
#   encryption table define 
#             items 
#        offset  -- 4bytes -- encrypt section offset in file
#        length  -- 4bytes -- encrypt section length
#        gap     -- 4bytes -- encrypt section gap , default is 1 , if it is 2, only operation 1 byte in every 2bytes 
# 
key0 = b"abcdefghijklmn0123456789"
key1 = b"bbccddnncc00rp\0997700\099"
key2 = b"zxcvbnm\0/65456132165464515"
key3 = b"1`2123123123178687689713212303\0cccaa"
def main():
    parser = argparse.ArgumentParser(description='ELF encryptor ')
    parser.add_argument('-o', '--offset', help='offset the encrypt section , default is .text section offset', type=int)
    parser.add_argument('-l', '--length', help='length the encrypt section , default is .text section length', type=int)
    parser.add_argument('-g', '--gap'   , help='gap    the encrypt section , default is 1', default=1)
    parser.add_argument('srcfn', help='source file name')
    parser.add_argument('tagfn', help='target file name')

    args = parser.parse_args()
    print(args)
    # read binary content
    bs = bytearray(open(args.srcfn,'rb').read())
    binary = lief.parse(bs)
    if args.offset == None:
        sec = binary.get_section('.text')
        args.offset = sec.offset
    if args.length == None:
        sec = binary.get_section('.text')
        args.length = sec.size
    print(f'offset {args.offset} {hex(args.offset)} length  {args.length} {hex(args.length)} gap {args.gap} {args.gap}')
    for o in range(args.offset, args.offset+args.length, args.gap):
        b = bs[o]
        b ^= key0[o%len(key0)]
        b ^= key1[o%len(key1)]
        b ^= key2[o%len(key2)]
        b ^= key3[o%len(key3)]
        bs[o]=b
    # put encrypt info at the end of the file 
    encrypt_info_offset = getAlignAddr(len(bs), 0x10)
    if encrypt_info_offset>len(bs):
        bs += b'\0' *(encrypt_info_offset-len(bs))
    bs += struct.pack('III', args.offset, args.length, args.gap)
    # mod section header offset to encrypt info
    e_CLASS     = binary.header.identity_class;
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
        bs[0x20:0x24] = struct.pack('I', encrypt_info_offset)
    else:
        bs[0x28:0x30] = struct.pack('Q', encrypt_info_offset)
    # write magic word
    bs[:4] = b'\xfd\xfd\xfd\xfd'
    open(args.tagfn,'wb').write(bs)
    
        

if __name__ == '__main__':
    main()

