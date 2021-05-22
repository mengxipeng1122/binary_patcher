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
key0 =b'\xC5\x89\x42\x88\xCA\xA7\xD4\x89\x34\x0F\x01\xDC\x74\x36\xDF\x5C\x27\x78\xDB\xD9\x41'
key1 =b'\x05\x17\x52\xBF\x67\xE5\xEA\x93\x6A\x00\x72\x3C\xE3\x9F\x5B\x39\xEF\xFB\xB5\x50\x12\x08\x66'
key2 =b'\xC0\x84\xC7\x9D\x8D\xAB\xA9\x57\xCA\x3D\xC9\x8E\x58\xA2\x96\xB6\x60\xA9\x13\x16\xCB\x85\x97\x25\xD6\xA3\x3E\x99\x3D\x8D\x23\x4E\x56'
key3 =b'\xA9\xC3\x2A\x37\x79\x31\xB8\xBC\x8C\x63\xDF\x7F\x80\x13\x7C\xA7\x4E\xDA\xE1\xAD\xD3\x1C\x8E\x0B\x84\x6D\x19\x7A\x59\xC1\x7E\x96\x7A\xB9\xB9'

def main():
    parser = argparse.ArgumentParser(description='ELF encryptor ')
    parser.add_argument('-o', '--offset', help='offset the encrypt section , default is .text section offset', type=int)
    parser.add_argument('-l', '--length', help='length the encrypt section , default is .text section length', type=int)
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
    print(f'offset {args.offset} {hex(args.offset)} length  {args.length} {hex(args.length)} gap 1')
    for o in range(args.offset, args.offset+args.length):
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
    bs += struct.pack('III', args.offset, args.length, 1)
    # mod section header offset to encrypt info
    e_CLASS     = binary.header.identity_class;
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
        bs[0x20:0x24] = struct.pack('I', encrypt_info_offset)
    else:
        bs[0x28:0x30] = struct.pack('Q', encrypt_info_offset)
    # write magic word
    bs[9] = 0xff
    open(args.tagfn,'wb').write(bs)
    
        

if __name__ == '__main__':
    main()

