#!/usr/bin/env python2.7
#-*-coding:utf-8 -*-
'''
written by ben
2015/10/26
'''
from ctypes import *

#map the linux types to ctypes
'''reference to the linux source code :/include/uapi/linux/elf.h
and /include/linux/types.h
'''
Elf32_Addr = c_uint        #4bytes
Elf32_Half = c_ushort      #2bytes
Elf32_Off  = c_uint        #4bytes
Elf32_Sword= c_int         #4bytes
Elf32_Word = c_uint        #4bytes
Elf64_Addr = c_ulonglong   #8bytes
Elf64_Half = c_ushort      #2bytes
Elf64_SHalf= c_short       #2bytes
Elf64_Off  = c_ulonglong   #8bytes
Elf64_Sword= c_int         #4bytes
Elf64_Word = c_uint        #4bytes
Elf64_Xword= c_ulonglong   #8bytes
Elf64_Sxword=c_longlong    #8bytes


#structure of elf header (64bit)
'''linux source code:  /include/uapi/linux/elf.h
typedef struct elf64_hdr {
  unsigned char	e_ident[EI_NIDENT];	/* ELF "magic number" */
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;		/* Entry point virtual address */
  Elf64_Off e_phoff;		/* Program header table file offset */
  Elf64_Off e_shoff;		/* Section header table file offset */
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;
'''
class Elf64_Ehdr(Structure):
	_fields_ = [
	      ("e_ident",c_ubyte*16),             
	      ("e_type",Elf64_Half),
	      ("e_machine",Elf64_Half),
	      ("e_version",Elf64_Word),
	      ("e_entry",Elf64_Addr),
	      ("e_phoff",Elf64_Off),
	      ("e_shoff",Elf64_Off),
	      ("e_flags",Elf64_Word),
	      ("e_ehsize",Elf64_Half),
	      ("e_phentsize",Elf64_Half),
	      ("e_phnum",Elf64_Half),
	      ("e_shentsize",Elf64_Half),
	      ("e_shnum",Elf64_Half),
	      ("e_shstrndx",Elf64_Half)
	         ]
#structure of section table
'''linux source code:  /include/uapi/linux/elf.h
typedef struct elf64_shdr {
  Elf64_Word sh_name;       /* Section name, index in string tbl */
  Elf64_Word sh_type;       /* Type of section */
  Elf64_Xword sh_flags;     /* Miscellaneous section attributes */
  Elf64_Addr sh_addr;       /* Section virtual addr at execution */
  Elf64_Off sh_offset;      /* Section file offset */
  Elf64_Xword sh_size;      /* Size of section in bytes */
  Elf64_Word sh_link;       /* Index of another section */
  Elf64_Word sh_info;       /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
} Elf64_Shdr;
'''
class Elf64_Shdr(Structure):
    _fields_ = [
        ("sh_name",Elf64_Word),
        ("sh_type",Elf64_Word),
        ("sh_flags",Elf64_Xword),
        ("sh_addr",Elf64_Addr),
        ("sh_offset",Elf64_Off),
        ("sh_size",Elf64_Xword),
        ("sh_link",Elf64_Word),
        ("sh_info",Elf64_Word),
        ("sh_addralign",Elf64_Xword),
        ("sh_entsize",Elf64_Xword)
    ]
#structure of ELF symbol
'''linux source code:  /include/uapi/linux/elf.h
typedef struct elf64_sym {
  Elf64_Word st_name;       /* Symbol name, index in string tbl */
  unsigned char st_info;    /* Type and binding attributes */
  unsigned char st_other;   /* No defined meaning, 0 */
  Elf64_Half st_shndx;      /* Associated section index */
  Elf64_Addr st_value;      /* Value of the symbol */
  Elf64_Xword st_size;      /* Associated symbol size */
} Elf64_Sym;

'''
class Elf64_Sym(Structure):
    _fields_ = [
        ("st_name",Elf64_Word),
        ("st_info",c_ubyte),
        ("st_other",c_ubyte),
        ("st_shndx",Elf64_Half),
        ("st_value",Elf64_Addr),
        ("st_size",Elf64_Xword)
    ]
#structure of ELF Program Header
'''linux source code:  /include/uapi/linux/elf.h
typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;       /* Segment file offset */
  Elf64_Addr p_vaddr;       /* Segment virtual address */
  Elf64_Addr p_paddr;       /* Segment physical address */
  Elf64_Xword p_filesz;     /* Segment size in file */
  Elf64_Xword p_memsz;      /* Segment size in memory */
  Elf64_Xword p_align;      /* Segment alignment, file & memory */
} Elf64_Phdr;
'''
class Elf64_Phdr(Structure):
    _fields_ = [
        ("p_type",Elf64_Word),
        ("p_flags",Elf64_Word),
        ("p_offset",Elf64_Off),
        ("p_vaddr",Elf64_Addr),
        ("p_paddr",Elf64_Addr),
        ("p_filesz",Elf64_Xword),
        ("p_memsz",Elf64_Xword),
        ("p_align",Elf64_Xword)
    ]
    
#ELF Header flags define
class ELFflags:
    ELFMagic=bytearray([0x7f,0x45,0x4c,0x46])
    ELFClass32=0x01
    ELFClass64=0x02
    ELFLSB=0x01
    ELFMSB=0x02
    ELFVersion=0x01

#ELF section flags defin
class ELFSectionflags:
    SHF_WRITE=0x01
    SHF_ALLOC=0x02
    SHF_EXECINSTR=0x04

#ELF Symbol flags define
class ELFSymflags:
    #symbol binding info flags :st_info(high 4bits)
    STB_LOCAL=0x00
    STB_GLOBAL=0x01  
    STB_WEAK=0x02
    #symbol type info flags :st_info(low 4bits)
    STT_NOTYPE=0x00
    STT_OBJECT=0x01
    STT_FUNC=0x02
    STT_SECTION=0x03
    STT_FILE=0x04
    #symbol section flags:st_shndx
    SHN_ABS=0xfff1
    SHN_COMMON=0xfff2
    SHN_UNDDEF=0x00

#ELF Program Header flags define
class ELFPhdrflags:
    #flags of p_type
    PT_NULL=0x00
    PT_LOAD=0x01
    PT_DYNAMIC=0x02
    PT_INTERP=0x03
    PT_NOTE=0x04
    PT_SHLIB=0x05
    PT_PHDR=0x06
    PT_TLS=0x07
    PT_LOOS=0x60000000
    PT_HIOS=0x6fffffff
    PT_LOPROC=0x70000000
    PT_HIPROC=0x7fffffff
    PT_GNU_EH_FRAME=0x6474e550
    PT_GNU_STACK=0x6474e551
    #ELF Program Section Previlege Flags define:p_flags
    PF_R=0x04
    PF_W=0x02
    PF_X=0x01

#section type define
class SectionType:
    SHT_NULL = 0x0
    SHT_PROGBITS = 0x1
    SHT_SYMTAB  = 0x2
    SHT_STRTAB = 0x3
    SHT_RELA = 0x4
    SHT_HASH = 0x5
    SHT_DYNAMIC	= 0x6
    SHT_NOTE = 0x7
    SHT_NOBITS = 0x8
    SHT_REL	= 0x9
    SHT_SHLIB = 0x10
    SHT_DYNSYM = 11
    SHT_NUM	= 0x12
    SHT_LOPROC = 0x70000000
    SHT_HIPROC = 0x7fffffff
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0xffffffff

class Elf_Rel(Structure):
    _fields_ = [
        ("r_offset",Elf64_Addr),
        ("r_info",Elf64_Xword),
    ]

class Elf_Rela(Structure):
    _fields_ = [
        ("r_offset",Elf64_Addr),
        ("r_info",Elf64_Xword),
        ('r_addend',Elf64_Sxword)
    ]
class _U__Elf64_Dyn(Union):
	_fields_ = [("d_val", Elf64_Xword),
				("d_ptr", Elf64_Addr),]
class Elf64_Dyn(Structure):
    _anonymous_ = ("d_un",)
    _fields_ = [("d_tag", Elf64_Sxword),
				("d_un", _U__Elf64_Dyn),]


