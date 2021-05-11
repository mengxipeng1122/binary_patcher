#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import lief 

from .BinFile import BinFile
from ..arch.Arm import *
from ..util.log import *
from ..util.util import *


NEW_CAVE_METHOD_NEW_PROGRAM_HEADER_END = 0
NEW_CAVE_METHOD_USE_NOTE_SEGMENT       = 1
NEW_CAVE_METHOD_TEXT_SEGMENT_END       = 2
NEW_CAVE_METHOD_LAST_SEGMENT_END       = 3
NEW_CAVE_METHOD_MOVE_TEXT_DATA_SEGMENT = 4

CAVE_METHOD = NEW_CAVE_METHOD_LAST_SEGMENT_END

new_ph_table_len = 0x1000

def parseELFHeader(bs, e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx = struct.unpack("IBBBBB7sHHIIIIIHHHHHH", bs)
        return e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx 
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx = struct.unpack("IBBBBB7sHHIIQQQHHHHHH", bs)
        return e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx 
    else:  raise Exception(f' unknown ELF_CLASS {e_CLASS} ' )


def constructELFHeader( e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx ):
    if e_ident_EI_CLASS == int(lief.ELF.ELF_CLASS.CLASS32): 
        return struct.pack("IBBBBB7sHHIIIIIHHHHHH", e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx )
    elif e_ident_EI_CLASS == int(lief.ELF.ELF_CLASS.CLASS64): 
        return struct.pack("IBBBBB7sHHIIQQQHHHHHH", e_ident_EI_MAG0 ,          e_ident_EI_CLASS , e_ident_EI_DATA , e_ident_EI_VERSION , e_ident_EI_OSABI , e_ident_EI_ABIVERSION , e_ident_EI_PAD , e_type , e_machine , e_version , e_entry , e_phoff , e_shoff , e_flags , e_ehsize , e_phentsize , e_phnum , e_shentsize , e_shnum , e_shstrndx )
    else:  raise Exception(f' unknown ELF_CLASS {e_ident_EI_CLASS} ' )

def parseProgramHeader(bs, e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = struct.unpack('IIIIIIII', bs)
        return p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align 
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        p_type  , p_flags,  p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_align  = struct.unpack('IIQQQQQQ', bs)
        return p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align 
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

def constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align , e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        return struct.pack('IIIIIIII', p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align)
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        return struct.pack('IIQQQQQQ', p_type  , p_flags, p_offset, p_vaddr , p_paddr , p_filesz, p_memsz ,  p_align)
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

def parseSectionHeader(bs, e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize = struct.unpack('IIIIIIIIII', bs)
        return sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize = struct.unpack('IIQQQQIIQQ', bs)
        return sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

def constructSectionHeader( sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize , e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        return struct.pack('IIIIIIIIII', sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize )
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        return struct.pack('IIQQQQIIQQ', sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize )
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

def parseSymTab(bs, e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        st_name , st_value, st_size, st_info, st_other, st_shndx  = struct.unpack('IIIBBH', bs)
        return st_name , st_value, st_size, st_info, st_other, st_shndx  
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        st_name , st_value, st_size, st_info, st_other, st_shndx  = struct.unpack('QBBIQQ', bs) # TODO: 
        return st_name , st_value, st_size, st_info, st_other, st_shndx  
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

def constructSymTab( st_name , st_value, st_size, st_info, st_other, st_shndx , e_CLASS):
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32: 
        return struct.pack('IIIBBH',st_name , st_value, st_size, st_info, st_other, st_shndx )
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64: 
        st_name , st_value, st_size, st_info, st_other, st_shndx  = struct.unpack('QBBIQQ', bs) # TODO: 
        return st_name , st_value, st_size, st_info, st_other, st_shndx  
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

def insertParasite2ElfByNote(fn, bs, PAGE_SIZE=0x4000):
    # Find the max address of any load segment 
    binary = lief.parse(fn);
    binbs  = bytearray(open(fn,'rb').read()) # read whole file content to memory 
    e_CLASS     = binary.header.identity_class;
    e_phnum     = binary.header.numberof_segments
    e_phentsize = binary.header.program_header_size
    e_phoff     = binary.header.program_header_offset

    max_load_addr = 0;
    PAGE_SIZE=0x4000
    for segment in binary.segments:
        if segment.type != lief.ELF.SEGMENT_TYPES.LOAD: continue
        segment_end_address = segment.virtual_address+segment.virtual_size
        if max_load_addr<segment_end_address: max_load_addr = segment_end_address
    inject_address = (max_load_addr + PAGE_SIZE - 1)  // PAGE_SIZE * PAGE_SIZE;

    parasite_sz = len(bs);
    new_seg_off = getAlignAddr(os.path.getsize(fn)+0x100, 0x1000)

    if new_seg_off>len(binbs): binbs += b'\0'*(new_seg_off - len(bs))

    # move segments 
    offset = e_phoff
    old_ph_tab = binbs[offset:offset+e_phnum*e_phentsize]

    # reverse 0x1000 for new ph table 

    p_type   = 1 # PT_LOAD
    p_flags  = 7 # RWX
    p_vaddr  = p_paddr = inject_address;
    p_filesz = p_memsz = len(bs)  + new_ph_table_len
    p_align  = 0x1000
    p_offset = new_seg_off;

    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
        new_ph = struct.pack('IIIIIIII', 
          p_type  ,
          p_offset,
          p_vaddr ,
          p_paddr ,
          p_filesz,
          p_memsz ,
          p_flags ,
          p_align ,
            )
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
        new_ph = struct.pack('IIIIIIII', 
          p_type  ,
          p_flags ,
          p_offset,
          p_vaddr ,
          p_paddr ,
          p_filesz,
          p_memsz ,
          p_align ,
            )
    else: assert False, f'unknow e_CLASS {e_CLASS}'
    
    
    new_e_phoff  = new_seg_off
    binbs += b'\0' * new_ph_table_len
    offset = new_e_phoff;
    binbs[offset:offset+len(old_ph_tab)] = old_ph_tab; offset += len(old_ph_tab)
    binbs[offset:offset+len(new_ph)] = new_ph; offset += len(new_ph)
    new_e_phnum = e_phnum+1

    # change program segment number
    if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
        offset=0x1c; binbs[offset:offset+4] = struct.pack('I', new_e_phoff)
        offset=0x2c; binbs[offset:offset+2] = struct.pack('H', new_e_phnum)
    elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
        offset=0x20; binbs[offset:offset+8] = struct.pack('Q', new_e_phoff)
        offset=0x38; binbs[offset:offset+2] = struct.pack('H', new_e_phnum)
    else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )

    binbs += bs
    # write back modified data
    open(fn,'wb').write( binbs)
    return inject_address+new_ph_table_len



class ELFFile(BinFile):

    # create a new cave use new program header 
    @decorator_inc_debug_level
    def new_cave_new_program_header_end(le, fn):
        max_load_addr = 0;
        binary = lief.parse(fn);
        binbs  = bytearray(open(fn,'rb').read()) # read whole file content to memory 
        e_CLASS     = binary.header.identity_class;
        e_phnum     = binary.header.numberof_segments
        e_phentsize = binary.header.program_header_size
        e_phoff     = binary.header.program_header_offset
        e_shnum     = binary.header.numberof_sections
        e_shentsize = binary.header.section_header_size
        e_shoff     = binary.header.section_header_offset
    
        section_header = binbs[ e_shoff: e_shoff+e_shentsize*e_shnum ]
        program_header = binbs[ e_phoff: e_phoff+e_phentsize*e_phnum ]
    
        # get max_load_addr
        load_segs_id  = [t for t in range(len(binary.segments)) if binary.segments[t].type == lief.ELF.SEGMENT_TYPES.LOAD ]
        assert len(load_segs_id) >= 2, f' need to at least 2 segment of type load  {load_segs_id}' 
        seg_id = load_segs_id[-1]
        seg = binary.segments[seg_id]
        max_load_addr = seg.virtual_address+seg.virtual_size
        max_load_addr = getAlignAddr(max_load_addr, seg.alignment)
    
        inject_address = max_load_addr;
    
        max_load_addr += le + e_shentsize*(e_phnum+1)
        max_load_addr = getAlignAddr(max_load_addr, seg.alignment)
    
        max_load_offset = max_load_addr-seg.virtual_address+seg.file_offset
        if max_load_offset>e_shoff:
            binbs = binbs[:e_shoff]+(b'\0'*(max_load_offset-e_shoff))
            
        # new segment 
        p_type   = 1 # PT_LOAD
        p_flags  = 7 # RWX
        p_vaddr  = p_paddr = inject_address;
        p_filesz = p_memsz = max_load_addr-inject_address
        p_align  = 0x1000
        p_offset = len(binbs)
        program_header += constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
        binbs+= b'\0'*p_filesz
        new_e_phoff = len(binbs)
        new_e_phnum = e_phnum+1
    
        # change program segment number
        if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
            offset=0x1c; binbs[offset:offset+4] = struct.pack('I', new_e_phoff)
            offset=0x2c; binbs[offset:offset+2] = struct.pack('H', new_e_phnum)
        elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
            offset=0x20; binbs[offset:offset+8] = struct.pack('Q', new_e_phoff)
            offset=0x38; binbs[offset:offset+2] = struct.pack('H', new_e_phnum)
        else:  raise Exception(f' unknown ELF_CLASS {e_CLASS} ' )
    
        #put program_header
        binbs += program_header
    
        if True:
            # update ELF header 
            if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
                e_shoff = struct.unpack('I', binbs[0x20:0x24])[0]
                e_shoff = len(binbs)
                binbs[0x20:0x24] = struct.pack('I', e_shoff)
            elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
                e_shoff = struct.unpack('Q', binbs[0x28:0x30])[0]
                e_shoff = len(binbs)
                binbs[0x28:0x30] = struct.pack('Q', e_shoff)
            else:  raise Exception(f' unknown ELF_CLASS {e_CLASS} ' )
        #put program_header
        binbs += section_header
    
        # write back modified data
        open(fn,'wb').write( binbs)
        return inject_address
    
    # create a new cave use new program header 
    @decorator_inc_debug_level
    def new_cave_note_segment(le, fn):
        max_load_addr = 0;
        binary = lief.parse(fn);
        binbs  = bytearray(open(fn,'rb').read()) # read whole file content to memory 
        e_CLASS     = binary.header.identity_class;
        e_phnum     = binary.header.numberof_segments
        e_phentsize = binary.header.program_header_size
        e_phoff     = binary.header.program_header_offset
    
        max_load_addr = 0;
        PAGE_SIZE=0x4000
        for segment in binary.segments:
            if segment.type != lief.ELF.SEGMENT_TYPES.LOAD: continue
            segment_end_address = segment.virtual_address+segment.virtual_size
            if max_load_addr<segment_end_address: max_load_addr = segment_end_address
        inject_address = (max_load_addr + PAGE_SIZE - 1)  // PAGE_SIZE * PAGE_SIZE;
    
        # find segment note  
        note_seg_id = -1
        for t, segment in enumerate(binary.segments):
            if segment.type == lief.ELF.SEGMENT_TYPES.NOTE:
                note_seg_id = t;
                break
        assert note_seg_id>=0, f'can not found note segment ' 
    
        bs = b'\0'*le
        parasite_sz = len(bs);
        new_seg_off = getAlignAddr(os.path.getsize(fn)+0x100, 0x1000)
        if new_seg_off>len(binbs): binbs += b'\0'*(new_seg_off - len(bs))
    
        # update note segment item
        p_type   = 1 # PT_LOAD
        p_flags  = 7 # RWX
        p_vaddr  = p_paddr = inject_address;
        p_filesz = p_memsz = len(bs)  + new_ph_table_len
        p_align  = 0x1000
        p_offset = new_seg_off;
    
        with open(fn, 'r+') as f:
            if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
                new_ph = struct.pack('IIIIIIII', 
                  p_type  ,
                  p_offset,
                  p_vaddr ,
                  p_paddr ,
                  p_filesz,
                  p_memsz ,
                  p_flags ,
                  p_align ,
                    )
                f.seek(e_phoff + note_seg_id * e_phentsize)
                f.write(new_ph);
            elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
                new_ph = struct.pack('IIIIIIII', 
                  p_type  ,
                  p_flags ,
                  p_offset,
                  p_vaddr ,
                  p_paddr ,
                  p_filesz,
                  p_memsz ,
                  p_align ,
                    )
                f.seek(e_phoff + note_seg_id * e_phentsize)
                f.write(new_ph);
            else: assert False, f'unknow e_CLASS {e_CLASS}'
        return inject_address
    
    # create a new cave use new program header 
    @decorator_inc_debug_level
    def new_cave_text_segment_end(le, fn):
        max_load_addr = 0;
        binary = lief.parse(fn);
        binbs  = bytearray(open(fn,'rb').read()) # read whole file content to memory 
        e_CLASS     = binary.header.identity_class;
        e_phnum     = binary.header.numberof_segments
        e_phentsize = binary.header.program_header_size
        e_phoff     = binary.header.program_header_offset
        e_shnum     = binary.header.numberof_sections
        e_shentsize = binary.header.section_header_size
        e_shoff     = binary.header.section_header_offset
    
        load_segs_id  = [t for t in range(len(binary.segments)) if binary.segments[t].type == lief.ELF.SEGMENT_TYPES.LOAD ]
        assert len(load_segs_id) >= 2, f' need to at least 2 segment of type load  {load_segs_id}' 
        text_seg_id, data_seg_id = load_segs_id[:2]
    
        text_seg = binary.segments[text_seg_id]
        data_seg = binary.segments[data_seg_id]
            
        assert text_seg.virtual_address + text_seg.virtual_size + le < data_seg.virtual_address , f''' 
            gap between is too small to insert parasite code 
            ==================================================
            text_seg: 
            {text_seg}
            text address : {hex(text_seg.virtual_address)}
            text end address : {hex(text_seg.virtual_address+text_seg.virtual_size)}
    
            ==================================================
            data_seg 
            {data_seg}
            data address : {hex(data_seg.virtual_address)}
            data end address : {hex(data_seg.virtual_address+data_seg.virtual_size)}
    
            ==================================================
            gap : {hex(data_seg.virtual_address-text_seg.virtual_address-text_seg.virtual_size)}
            le  : {hex(le)}
        '''
    
        inject_address = text_seg.virtual_address + text_seg.virtual_size
    
        # update gap data
        old_gap_data = binbs[text_seg.file_offset+len(text_seg.content):data_seg.file_offset]
    
        if(len(old_gap_data) > le): return inject_address
    
        # use whole gap
        #new_gap_data = b'\0'* (data_seg.virtual_size-text_seg.virtual_size-len(text_seg.content))
        new_data_offset = text_seg.file_offset+(data_seg.virtual_address-text_seg.virtual_address)
        new_text_size   = data_seg.virtual_address - text_seg.virtual_address
    
        # update text segment header
        if True:
            text_seg_header = binbs[e_phoff+text_seg_id*e_phentsize:e_phoff+text_seg_id*e_phentsize+e_phentsize]
            p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = parseProgramHeader( text_seg_header, e_CLASS)
            p_flags = 7
            p_filesz = new_text_size
            p_memsz  = new_text_size
            binbs[e_phoff+text_seg_id*e_phentsize:e_phoff+text_seg_id*e_phentsize+e_phentsize] = constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
    
        # update data segment header
        if True:
            p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = parseProgramHeader( binbs[e_phoff+data_seg_id*e_phentsize:e_phoff+data_seg_id*e_phentsize+e_phentsize] , e_CLASS)
            p_offset = new_data_offset
            binbs[e_phoff+data_seg_id*e_phentsize:e_phoff+data_seg_id*e_phentsize+e_phentsize] = constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
    
        if True:
            offset_mod = new_data_offset - data_seg.file_offset
            for t, seg in enumerate(binary.segments):
                if seg.type == lief.ELF.SEGMENT_TYPES.LOAD: continue
                if seg.file_offset >= data_seg.file_offset:
                    p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = parseProgramHeader( binbs[ e_phoff + e_phentsize*t: e_phoff + e_phentsize*t+e_phentsize ], e_CLASS)
                    p_offset += offset_mod
                    binbs[ e_phoff + e_phentsize*t: e_phoff + e_phentsize*t+e_phentsize ] = constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
    
        # update section segment items
        if True:
            offset_mod = new_data_offset - data_seg.file_offset
            data_sections_name = [sec.name for sec in data_seg.sections]
            for t, sec in enumerate(binary.sections):
                if sec.offset >= data_seg.file_offset:
                    sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize = parseSectionHeader( binbs[ e_shoff + e_shentsize*t: e_shoff + e_shentsize*t+e_shentsize ], e_CLASS)
                    sh_offset += offset_mod
                    binbs[ e_shoff + e_shentsize*t: e_shoff + e_shentsize*t+e_shentsize ] = constructSectionHeader( sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize , e_CLASS)
        if True:
            binbs0 = binbs[:text_seg.file_offset+len(text_seg.content)].copy()
            binbs1 = binbs[data_seg.file_offset:].copy()
            new_gap_bs = (b'\0' * (data_seg.virtual_address-text_seg.virtual_address-len(text_seg.content))) 
            binbs  = binbs0+ new_gap_bs + binbs1
    
        # update elf header
        if True:
            if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
                e_shoff = struct.unpack('I', binbs[0x20:0x24])[0]
                e_shoff += offset_mod
                binbs[0x20:0x24] = struct.pack('I', e_shoff)
            elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
                e_shoff = struct.unpack('Q', binbs[0x28:0x30])[0]
                e_shoff += offset_mod
                binbs[0x28:0x30] = struct.pack('Q', e_shoff)
            else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )
    
        open(fn,'wb').write(binbs)
        return inject_address
    
    # move segment and data segment for new parasite code , 
    # this parasite code is insert to 
    @decorator_inc_debug_level
    def new_cave_move_text_data_segment(le, fn):
        max_load_addr = 0;
        binary = lief.parse(fn);
        binbs  = bytearray(open(fn,'rb').read()) # read whole file content to memory 
        e_CLASS     = binary.header.identity_class;
        e_phnum     = binary.header.numberof_segments
        e_phentsize = binary.header.program_header_size
        e_phoff     = binary.header.program_header_offset
        e_shnum     = binary.header.numberof_sections
        e_shentsize = binary.header.section_header_size
        e_shoff     = binary.header.section_header_offset
        header_size = binary.header.header_size
    
        section_header = binbs[ e_shoff: e_shoff+e_shentsize*e_shnum ]
        program_header = binbs[ e_phoff: e_phoff+e_phentsize*e_phnum ]
    
        old_offset = e_phoff + e_phentsize*e_phnum
        old_text_data = bytearray(binbs[old_offset:e_shoff])
        offset_mod  = le
    
        load_segs_id  = [t for t in range(len(binary.segments)) if binary.segments[t].type == lief.ELF.SEGMENT_TYPES.LOAD ]
        assert len(load_segs_id) >= 2, f' need to at least 2 segment of type load  {load_segs_id}' 
        text_seg_id, data_seg_id = load_segs_id[:2]
    
        text_seg = binary.segments[text_seg_id]
        data_seg = binary.segments[data_seg_id]
    
        assert text_seg.virtual_address == 0 ,f' text_seg virtual_address does not equal to 0 ' 
            
        inject_address = text_seg.virtual_address + old_offset
    
        #new_gap_data = b'\0'* (data_seg.virtual_size-text_seg.virtual_size-len(text_seg.content))
        # update data segments header
        if True:
            for t, seg in enumerate(binary.segments):
                if seg.file_offset >= old_offset:
                    p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = parseProgramHeader( binbs[ e_phoff + e_phentsize*t: e_phoff + e_phentsize*t+e_phentsize ], e_CLASS)
                    p_offset += offset_mod
                    p_paddr   += offset_mod
                    p_vaddr   += offset_mod
                    binbs[ e_phoff + e_phentsize*t: e_phoff + e_phentsize*t+e_phentsize ] = constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
    
        t = text_seg_id
        p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = parseProgramHeader( binbs[ e_phoff + e_phentsize*t: e_phoff + e_phentsize*t+e_phentsize ], e_CLASS)
        p_flags = 7
        p_filesz += offset_mod
        p_memsz  += offset_mod
        binbs[ e_phoff + e_phentsize*t: e_phoff + e_phentsize*t+e_phentsize ] = constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
    
        # update section segment items
        if True:
            data_sections_name = [sec.name for sec in data_seg.sections]
            for t, sec in enumerate(binary.sections):
                #if lief.ELF.SECTION_FLAGS.ALLOC in sec.flags_list:
                if t>0:
                    sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize = parseSectionHeader( section_header[ e_shentsize*t: e_shentsize*t+e_shentsize ], e_CLASS)
                    sh_offset += offset_mod
                    sh_addr   += offset_mod
                    section_header[  e_shentsize*t:  e_shentsize*t+e_shentsize ] = constructSectionHeader( sh_name  , sh_type  , sh_flags , sh_addr  , sh_offset , sh_size   , sh_link   , sh_info   , sh_addralign , sh_entsize , e_CLASS)
    
    
        # update static symtab
        section_names = [sec.name for sec in binary.sections]
        if '.symtab' in section_names:
            sec = [sec for sec in binary.sections if sec.name == '.symtab'][0]
            for t, sym in enumerate(binary.static_symbols):
                tbs = binbs[sec.offset+sec.entry_size*t: sec.offset+sec.entry_size*t+sec.entry_size]
                st_name , st_value, st_size, st_info, st_other, st_shndx  = parseSymTab(tbs, e_CLASS)
                st_value += offset_mod
                old_text_data[sec.offset+sec.entry_size*t-old_offset: sec.offset+sec.entry_size*t+sec.entry_size-old_offset] = constructSymTab( st_name , st_value, st_size, st_info, st_other, st_shndx , e_CLASS)
    
        # update dynamic .dynsym
        if True:
            sec = [sec for sec in binary.sections if sec.name == '.dynsym'][0]
            for t, sym in enumerate(binary.dynamic_symbols):
                tbs = binbs[sec.offset+sec.entry_size*t: sec.offset+sec.entry_size*t+sec.entry_size]
                st_name , st_value, st_size, st_info, st_other, st_shndx  = parseSymTab(tbs, e_CLASS)
                st_value += offset_mod
                old_text_data[sec.offset+sec.entry_size*t-old_offset: sec.offset+sec.entry_size*t+sec.entry_size-old_offset] = constructSymTab( st_name , st_value, st_size, st_info, st_other, st_shndx , e_CLASS)
    
        # update dynamic .dynamic
        if True:
            sec = [sec for sec in binary.sections if sec.name == '.dynamic'][0]
            for t, sym in enumerate(binary.dynamic_entries):
                tbs = binbs[sec.offset+sec.entry_size*t: sec.offset+sec.entry_size*t+sec.entry_size]
                #  TODO : only 32 bit now 
                d_tag, d_val  = struct.unpack('II', tbs)
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.STRTAB):   d_val += offset_mod
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.SYMTAB):   d_val += offset_mod
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.GNU_HASH): d_val += offset_mod
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.PLTGOT):   d_val += offset_mod
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.JMPREL):   d_val += offset_mod
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.VERNEED):  d_val += offset_mod
                if d_tag == int(lief.ELF.DYNAMIC_TAGS.VERSYM):   d_val += offset_mod
                old_text_data[sec.offset+sec.entry_size*t-old_offset: sec.offset+sec.entry_size*t+sec.entry_size-old_offset] = struct.pack("II", d_tag, d_val)
    
        if True:
            binbs  = binbs[:old_offset]
            binbs += b'\0'*le
            binbs += old_text_data
    
        # update elf header
        if True:
            if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
                e_shoff = struct.unpack('I', binbs[0x20:0x24])[0]
                e_shoff = len(binbs)
                binbs[0x20:0x24] = struct.pack('I', e_shoff)
                e_entry = struct.unpack('I', binbs[0x18:0x1c])[0]
                if e_entry !=0: e_entry += offset_mod
                binbs[0x18:0x1c] = struct.pack('I', e_entry)
            elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
                e_shoff = struct.unpack('Q', binbs[0x28:0x30])[0]
                e_shoff = len(binbs)
                binbs[0x28:0x30] = struct.pack('Q', e_shoff)
                e_entry = struct.unpack('Q', binbs[0x18:0x20])[0]
                if e_entry !=0: e_entry += offset_mod
                binbs[0x18:0x20] = struct.pack('Q', e_entry)
            else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )
            binbs += section_header
    
        open(fn,'wb').write(binbs)
        return inject_address
        
        
    # create a new cave use new program header 
    @decorator_inc_debug_level
    def new_cave_last_segment_end(self,le):
        binary = self.binary  
        binbs  = self.binbs
        e_CLASS     = binary.header.identity_class;
        e_phnum     = binary.header.numberof_segments
        e_phentsize = binary.header.program_header_size
        e_phoff     = binary.header.program_header_offset
        e_shnum     = binary.header.numberof_sections
        e_shentsize = binary.header.section_header_size
        e_shoff     = binary.header.section_header_offset
    
        load_segs_id  = [t for t in range(len(binary.segments)) if binary.segments[t].type == lief.ELF.SEGMENT_TYPES.LOAD ]
        assert len(load_segs_id) >= 2, f' need to at lease 2 segment of type load  {load_segs_id}' 
    
        # get max_load_addr
        seg_id = load_segs_id[-1]
        seg = binary.segments[seg_id]
        max_load_addr = seg.virtual_address+seg.virtual_size
        max_load_addr = getAlignAddr(max_load_addr, seg.alignment)
    
        # find section header (assume section header always is put at end of the file 
        section_header = binbs[e_shoff:]
        assert len(section_header)>=e_shentsize*e_shnum, 'section header has been corrupted , e_shentsize {e_shentsize} e_shnum {e_shnum}, length of section_header {len(section_header}  '
    
        inject_address = max_load_addr
        max_load_addr += le
    
        max_load_offset = max_load_addr-seg.virtual_address+seg.file_offset
        if max_load_offset>e_shoff:
            binbs = binbs[:e_shoff]+(b'\0'*(max_load_offset-e_shoff))
            
        new_data_size   = max_load_addr - seg.virtual_address 
    
        if True:
            p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  = parseProgramHeader( binbs[e_phoff+seg_id*e_phentsize:e_phoff+seg_id*e_phentsize+e_phentsize] , e_CLASS)
            p_filesz = new_data_size
            p_memsz = new_data_size
            p_flags = 7
            binbs[e_phoff+seg_id*e_phentsize:e_phoff+seg_id*e_phentsize+e_phentsize] = constructProgramHeader( p_type  , p_offset, p_vaddr , p_paddr , p_filesz, p_memsz , p_flags , p_align  , e_CLASS)
    
        if True:
            # update ELF header 
            if e_CLASS == lief.ELF.ELF_CLASS.CLASS32:
                e_shoff = struct.unpack('I', binbs[0x20:0x24])[0]
                e_shoff = len(binbs)
                binbs[0x20:0x24] = struct.pack('I', e_shoff)
            elif e_CLASS == lief.ELF.ELF_CLASS.CLASS64:
                e_shoff = struct.unpack('Q', binbs[0x28:0x30])[0]
                e_shoff = len(binbs)
                binbs[0x28:0x30] = struct.pack('Q', e_shoff)
            else:  raise Exception(' unknown ELF_CLASS {e_CLASS} ' )
    
        if True:
            # put section header to the end of the file 
            binbs += section_header
        self.binbs = binbs
        self.binary = lief.parse(self.binbs)
        return inject_address

    @decorator_inc_debug_level
    def __init__(self, info=None):
        BinFile.__init__(self, info);
        if self.info == None:
            self.info  = {
                'name': self.getName(),
                }

    @decorator_inc_debug_level
    def getName(self):
        return "ELFFile"

    def rebuild(self):
        binary = self.binary
        e_CLASS     = binary.header.identity_class;
        e_phnum     = binary.header.numberof_segments
        e_phentsize = binary.header.program_header_size
        e_phoff     = binary.header.program_header_offset
        e_shnum     = binary.header.numberof_sections
        e_shentsize = binary.header.section_header_size
        e_shoff     = binary.header.section_header_offset
        binbs       = self.binbs
        info        = self.info
        ################################################################################
        # handle ctors
        #  show origin ctors
        for t, dyn in enumerate(binary.dynamic_entries): 
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.INIT_ARRAY: INIT_ARRAY = dyn.value
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.INIT_ARRAYSZ: INIT_ARRAYSZ = dyn.value
        INIT_ARRAY_OFFSET = binary.virtual_address_to_offset(INIT_ARRAY)
        ctors = list(struct.unpack('I'*(INIT_ARRAYSZ//4), binbs[INIT_ARRAY_OFFSET:INIT_ARRAY_OFFSET+INIT_ARRAYSZ]))
        while 0 in ctors: ctors.remove(0)
        if 'remove_ctors' in info:
            for hexd in info['remove_ctors']:
                add = eval(hexd)
                if add in ctors: ctors.remove(add)
        if 'add_ctors' in info:
            for hexd in info['add_ctors']:
                add = eval(hexd)
                ctors.append(add)
        assert len(ctors)*4 <= INIT_ARRAYSZ, f' new ctors is big than old room {ctors} {len(ctors)*4} {INIT_ARRAYSZ}' 
        INIT_ARRAYSZ = len(ctors)*4
        binbs[INIT_ARRAY_OFFSET:INIT_ARRAY_OFFSET+INIT_ARRAYSZ] = struct.pack('I' *(INIT_ARRAYSZ//4), *ctors)
        sec_id = [b for b in range(len(binary.sections)) if binary.sections[b].name == '.dynamic'][0]
        sec = binary.sections[sec_id]
        for t, dyn in enumerate(binary.dynamic_entries): 
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.INIT_ARRAY: binbs[sec.offset+sec.entry_size*t:sec.offset+sec.entry_size*t+sec.entry_size] = struct.pack('II',  int(dyn.tag), INIT_ARRAY)
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.INIT_ARRAYSZ: binbs[sec.offset+sec.entry_size*t:sec.offset+sec.entry_size*t+sec.entry_size] = struct.pack('II',  int(dyn.tag), INIT_ARRAYSZ)

        ################################################################################
        # handle dtors
        #  show origin dtors
        for t, dyn in enumerate(binary.dynamic_entries): 
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.FINI_ARRAY: FINI_ARRAY = dyn.value
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.FINI_ARRAYSZ: FINI_ARRAYSZ = dyn.value
        FINI_ARRAY_OFFSET = binary.virtual_address_to_offset(FINI_ARRAY)
        dtors = list(struct.unpack('I'*(FINI_ARRAYSZ//4), binbs[FINI_ARRAY_OFFSET:FINI_ARRAY_OFFSET+FINI_ARRAYSZ]))
        while 0 in dtors: dtors.remove(0)
        if 'remove_dtors' in info:
            for hexd in info['remove_dtors']:
                add = eval(hexd)
                if add in dtors: dtors.remove(add)
        if 'add_dtors' in info:
            for hexd in info['add_dtors']:
                add = eval(hexd)
                dtors.append(add)
        assert len(dtors)*4 <= FINI_ARRAYSZ, f' new dtors is big than old room {dtors} {len(ctors)*4} {FINI_ARRAYSZ}' 
        FINI_ARRAYSZ = len(dtors)*4
        binbs[FINI_ARRAY_OFFSET:FINI_ARRAY_OFFSET+FINI_ARRAYSZ] = struct.pack('I' *(FINI_ARRAYSZ//4), *dtors)
        sec_id = [b for b in range(len(binary.sections)) if binary.sections[b].name == '.dynamic'][0]
        sec = binary.sections[sec_id]
        for t, dyn in enumerate(binary.dynamic_entries): 
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.FINI_ARRAY: binbs[sec.offset+sec.entry_size*t:sec.offset+sec.entry_size*t+sec.entry_size] = struct.pack('II',  int(dyn.tag), FINI_ARRAY)
            if dyn.tag == lief.ELF.DYNAMIC_TAGS.FINI_ARRAYSZ: binbs[sec.offset+sec.entry_size*t:sec.offset+sec.entry_size*t+sec.entry_size] = struct.pack('II',  int(dyn.tag), FINI_ARRAYSZ)

        ################################################################################
        # handle remove_libraries
        if 'remove_libraries' in info:
            sec_id = [b for b in range(len(binary.sections)) if binary.sections[b].name == '.dynstr'][0]
            sec = binary.sections[sec_id]
            needToRemoveIDs= []
            for t, dyn in enumerate(binary.dynamic_entries): 
                if dyn.tag == lief.ELF.DYNAMIC_TAGS.NEEDED:
                    offset = dyn.value
                    name = getStr(binbs[sec.offset+offset:])
                    if name in info['remove_libraries']: needToRemoveIDs.append(t)
            sec_id = [b for b in range(len(binary.sections)) if binary.sections[b].name == '.dynamic'][0]
            sec = binary.sections[sec_id]
            total_entries = len(binary.dynamic_entries)
            entry_size  = sec.entry_size
            for t in sorted(needToRemoveIDs, reverse=True):
                tbs = binbs[sec.offset+entry_size*t+entry_size:sec.offset+total_entries*entry_size]
                binbs[sec.offset+entry_size*t:sec.offset+total_entries*entry_size-entry_size] = tbs
                
        ################################################################################
        # handle remove_symbols
        if 'remove_symbols' in info:
            sec_id = [b for b in range(len(binary.sections)) if binary.sections[b].name == '.dynsym'][0]
            sec = binary.sections[sec_id]
            total_entries = len(binary.dynamic_symbols)
            entry_size  = sec.entry_size
            for t, sym in enumerate(binary.dynamic_symbols): 
                if sym.name in info['remove_symbols']: 
                    binbs[sec.offset+entry_size*t:sec.offset+t*entry_size+entry_size] = b'\0'*entry_size
        self.binbs = binbs

    @decorator_inc_debug_level
    def load(self, fn):
        self.binary = lief.parse(fn)
        if self.binary:
            self.binbs=bytearray(open(fn,'rb').read())
            self.rebuild()
            return True
        return False

    @decorator_inc_debug_level
    def updateSymbolMap(self, m):
        # update
        m.update( { sym.name : sym.value for sym in self.binary.exported_symbols} )
        # update plt 
        #m.update( { reloc.symbol.name : sec.virtual_address + t*0x0c+0x14 for t, reloc in enumerate(self.binary.pltgot_relocations) if reloc.has_symbol} )
        pltmap = {reloc.address : reloc.symbol.name for reloc in self.binary.pltgot_relocations}
        sec = self.binary.get_section('.plt')
        self.getArch().parsePlTSecUpdateSymol(bytes(sec.content), sec.virtual_address, pltmap, m )

    @decorator_inc_debug_level
    def getArch(self):
        if self.binary.header.machine_type == lief.ELF.ARCH.ARM: 
            return Arm(True)
        raise Exception(f'unsupported machine_type {self.binary.header.machine_type } ')

    @decorator_inc_debug_level
    def addCave(self, le):
        assert le>0, 'cave length should be large than zero'
        if CAVE_METHOD == NEW_CAVE_METHOD_NEW_PROGRAM_HEADER_END:
            return new_cave_new_program_header_end(le, fn)
        elif CAVE_METHOD == NEW_CAVE_METHOD_USE_NOTE_SEGMENT:
            return new_cave_note_segment(le, fn)
        elif CAVE_METHOD == NEW_CAVE_METHOD_TEXT_SEGMENT_END:
            return new_cave_text_segment_end(le, fn)
        elif CAVE_METHOD == NEW_CAVE_METHOD_LAST_SEGMENT_END:
            return self.new_cave_last_segment_end(le)
        elif CAVE_METHOD == NEW_CAVE_METHOD_MOVE_TEXT_DATA_SEGMENT:
            return new_cave_move_text_data_segment(le, fn)
        else: raise Exception(f' unknown method {CAVE_METHOD} ')
        
    @decorator_inc_debug_level
    def patch(self, addr, bs):
        for t, seg in enumerate(self.binary.segments):
            if addr>= seg.virtual_address and addr < seg.virtual_address + seg.virtual_size: 
                off = seg.file_offset + ( addr - seg.virtual_address )
                self.binbs[off:off+len(bs)] = bs
                return 
        raise Exception(f'write {hex(addr)} -- {len(bs)} failed' )
    

