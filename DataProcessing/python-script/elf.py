#!/usr/bin/env python2.7
#-*-coding:utf-8 -*-


from ctypes import *
from typedef import *
from collections import defaultdict

class Elf64_Parse():
    'class for parsing the elf binary'
    def __init__(self,elf):
        #print "#starting to parse the binary"
        self.elf=bytearray(elf)   #convert the binary file to bytearray
        #print "bytarray",self.elf
        self.__elfheader=None       #a Elf64_Ehdr struct to store elf header
        self.__shdr=[]              #a Elf64_Shdr struct to store elf section table
        self.shstrtab=None
        self.__sym=[]
        self.__dynsym=[]
        self.__reloca = []
        self.__reloc = []
        self.__dynamic=[]
        self.strtab=None
        self.dynstr = None
        self.__phdr=[]
        self.__Parse__elfheader()
        self.__ParseSectionTable()
        #self.__ParseStrtab()
        #self.__ParseSymbolTable()
        #self.__ParseDynsym()
        self.__ParseProgramHeader()



    def __Parse__elfheader(self):
        'parse the elf header'
        e_ident=self.elf[:16]
        magic=e_ident[:4]
        e_class=e_ident[4]
        data=e_ident[5]
        version=e_ident[6]
        if magic!=ELFflags.ELFMagic or \
            e_class!=ELFflags.ELFClass64 or \
            data!=ELFflags.ELFLSB or \
            version!=ELFflags.ELFVersion:
            print("invalid elf!")
            return None
        self.__elfheader=Elf64_Ehdr.from_buffer_copy(self.elf)

    def __ParseSectionTable(self):
        'parse the elf section table'
        st_shnum=self.__elfheader.e_shnum
        st_shentsize=self.__elfheader.e_shentsize
        st_size=st_shnum*st_shentsize
        st_addr_start=self.__elfheader.e_shoff
        st_addr_end=self.__elfheader.e_shoff+st_size
        st_base=self.elf[st_addr_start:st_addr_end]
        #extract the section structure
        for i in range(st_shnum):
            shdr_temp=Elf64_Shdr.from_buffer_copy(st_base)
            self.__shdr.append(shdr_temp)
            st_base=st_base[st_shentsize:]
        #self.shstrtab=self.elf[self.__shdr[self.__elfheader.e_shstrndx].sh_offset:]
        #extract the section string name
        #for i in range(st_shnum):
            #self.__shdr[i].section_name=self.shstrtab[self.__shdr[i].sh_name:].split(b"\0")[0]
    
    def __ParseStrtab(self):
        'parse the .strtab section'
        strtab_index=-1
        #find the index of string section in section table
        for i in range(self.__elfheader.e_shnum):
            if self.__shdr[i].section_name==".strtab":
                strtab_index=i
                break
        if strtab_index==-1:
            print("Missing .strtab!")
            return None
        self.strtab=self.elf[self.__shdr[strtab_index].sh_offset:]

    def __Parse_dynstr(self):
        for i in range(self.__elfheader.e_shnum):
            if self.__shdr[i].section_name==".dynstr":
                dynstr_index = i
        self.dynstr = self.elf[self.__shdr[dynstr_index].sh_offset:]

    def __ParseSymbolTable(self):
        'parse the elf symbol table'
        sym_index=-1
        #find the index of symbol section in section table
        for i in range(self.__elfheader.e_shnum):
            if self.__shdr[i].section_name==".symtab":
                sym_index=i
                break
        if sym_index==-1:
            print("Missing .symtab symbol!")
            return None
        sym_addr_start=self.__shdr[sym_index].sh_offset
        sym_addr_end=self.__shdr[sym_index].sh_offset+self.__shdr[sym_index].sh_size
        sym_base=self.elf[sym_addr_start:sym_addr_end]
        sym_num=self.__shdr[sym_index].sh_size/sizeof(Elf64_Sym)
        #extract the symbol structure
        for i in range(sym_num):
            sym_temp=Elf64_Sym.from_buffer_copy(sym_base)
            self.__sym.append(sym_temp)
            sym_base=sym_base[sizeof(Elf64_Sym):]
        if self.strtab!=None:
            #extract the symbol string name
            for i in range(sym_num):
                self.__sym[i].sym_name=self.strtab[self.__sym[i].st_name:].split("\0")[0]
      
    def __ParseDynsym(self):
        'parse the elf .dynsym section'
        #parse the .dynsym if it exists
        for shdr in self.__shdr:
            if shdr.section_name==".dynsym":
                dynsym_addr_start=shdr.sh_offset
                dynsym_addr_end=shdr.sh_offset+shdr.sh_size
                dynsym_base=self.elf[dynsym_addr_start:dynsym_addr_end]
                dynsym_num=shdr.sh_size/sizeof(Elf64_Sym)
                for i in range(dynsym_num):
                    dynsym_temp=Elf64_Sym.from_buffer_copy(dynsym_base)
                    self.__dynsym.append(dynsym_temp)
                    dynsym_base=dynsym_base[sizeof(Elf64_Sym):]
                if self.strtab!=None:
                    for i in range(dynsym_num):
                        self.__dynsym[i].sym_name=self.strtab[self.__dynsym[i].st_name:].split("\0")[0]

    def __ParseProgramHeader(self):
        'parse the program header'
        ph_addr_start=self.__elfheader.e_phoff
        ph_addr_end=ph_addr_start+self.__elfheader.e_phentsize*self.__elfheader.e_phnum
        phdr_base=self.elf[ph_addr_start:ph_addr_end]
        for i in range(self.__elfheader.e_phnum):
            phdr_temp=Elf64_Phdr.from_buffer_copy(phdr_base)
            self.__phdr.append(phdr_temp)
            phdr_base=phdr_base[self.__elfheader.e_phentsize:]

    def __ParseRelocation(self):
        'parse the elf relocation section'
        for shdr in self.__shdr:
            if shdr.sh_type == SectionType.SHT_RELA:
                self.parse_reloca_64(shdr)
            if shdr.sh_type == SectionType.SHT_REL:
                self.parse_reloc_64(shdr)
    def parse_reloca_64(self,section):
        #for i in range(0, section.sh_size/24):
            #ofs = 
        reloca_start = section.sh_offset
        reloca_end = section.sh_size+reloca_start
        reloca_base=self.elf[reloca_start:reloca_end]
        reloca_num = section.sh_size/sizeof(Elf_Rela)

        for i in range(reloca_num):
            reloca_temp = Elf_Rela.from_buffer_copy(reloca_base)
            self.__reloca.append(reloca_temp)
            reloca_base = reloca_base[sizeof(Elf_Rela):]
    def parse_reloc_64(self,section):
        reloc_start = section.sh_offset
        reloc_end = section.sh_size+reloca_start
        reloc_base=self.elf[reloca_start:reloca_end]
        reloc_num = section.sh_size/sizeof(Elf_Rel)

        for i in range(reloca_num):
            reloc_temp = Elf_Rel.from_buffer_copy(reloc_base)
            self.__reloc.append(reloc_temp)
            reloc_base = reloc_base[sizeof(Elf_Rel):]
    
    def __ParseDynamic(self):
        for shdr in self.__shdr:
            if shdr.sh_type == SectionType.SHT_DYNAMIC:
                dynamic_start = shdr.sh_offset
                dynamic_end = shdr.sh_size + dynamic_start
                dynamic_base = self.elf[dynamic_start:dynamic_end]
                dynamic_num = shdr.sh_size/sizeof(Elf64_Dyn)
                #print "size of %d"%sizeof(Elf64_Dyn)
                #print "start,end,dynamic_num,size %lx,%lx,%d,%d"%(dynamic_start,dynamic_end,dynamic_num,shdr.sh_size)
                for i in range(dynamic_num):
                    dynamic_temp = Elf64_Dyn.from_buffer_copy(dynamic_base)
                    self.__dynamic.append(dynamic_temp)
                    dynamic_base = dynamic_base[sizeof(Elf64_Dyn):]

    def GetDynamic(self):
        self.__ParseDynamic()
        return self.__dynamic
    
    def GetRelocation(self):
        self.__ParseRelocation()
        return self.__reloca,self.__reloc
    
    def GetElfheader(self):
        return self.__elfheader

    def GetShdr(self):
        return self.__shdr

    def GetPhdr(self):
        return self.__phdr

    def GetSym(self):
        return self.__sym

    def GetDynsym(self):
        return self.__dynsym

    def GetDynstr(self):
        self.__Parse_dynstr()
        return self.dynstr

            
