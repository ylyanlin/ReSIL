#!/usr/bin/env python2.7
#-*-coding:utf-8 -*-
import binascii

from capstone import *
from capstone.x86 import *
from ctypes import *
from typedef import *
from elf import *

class Dissamble(object):
    'dissamble the binary for exec section'
    def __init__(self,elf,shdr,start_addr,end_addr):
        #print "#starting to dissamble the bianry"
        self.__elf=bytearray(elf)
        self.__shdr=shdr
        self.__start_addr = start_addr
        self.__end_addr = end_addr
        self.dissamble_dict=dict()    #the dissambled section dict
        self.dissambled_ins = list()
        self.__X_boundary={}      #the address boundary of executed sections
        self.__R_boundary={}      #the address boundary of read only sections
        self.__RW_boundary={}     #the address boundary of read & write sections
        self.base_addr=None       #the base address of elf when loading
        self.__Dissamble()
        #self.Output()

    def __Dissamble(self):
        shdr_addr_start=-1
        shdr_addr_end=-1
        for i in range(len(self.__shdr)):
            if self.__shdr[i].sh_flags == ELFSectionflags.SHF_EXECINSTR + ELFSectionflags.SHF_ALLOC:
                if self.__start_addr >= self.__shdr[i].sh_addr:
                    self.base_addr = self.__shdr[i].sh_addr - self.__shdr[i].sh_offset
                    shdr_addr_start = self.__start_addr - self.base_addr
                    shdr_addr_end = self.__end_addr - self.base_addr
                    shdr_bytes = self.__elf[shdr_addr_start:shdr_addr_end]
                    md = Cs(CS_ARCH_X86, CS_MODE_64)
                    md.detail = True
                    self.dissambled_ins = list(md.disasm(str(shdr_bytes), self.__start_addr))
        '''
        for i in range(len(self.__shdr)):
            #dissamble the the executed sections and record the address boundary
            if self.__shdr[i].sh_flags==ELFSectionflags.SHF_EXECINSTR+ELFSectionflags.SHF_ALLOC:
                #if self.__shdr[i].section_name==".text":
                    #compute the base address of the elf base on .text vitual address
                    #self.base_addr=self.__shdr[i].sh_addr-self.__shdr[i].sh_offset
                shdr_addr_start=self.__shdr[i].sh_offset
                shdr_addr_end=shdr_addr_start+self.__shdr[i].sh_size
                shdr_virtual_addr=self.__shdr[i].sh_addr
                if self.__shdr[i].section_name=='.plt':
                    #patch the start address of .plt section with offset 0x10 bytes
                    #cause the offset of the first jmp instruction in .plt is 0x10
                    shdr_addr_start+=0x10
                    shdr_virtual_addr+=0x10
                #if self.__shdr[i].section_name=='.fini':
                    #shdr_addr_end = self.__shdr[i].sh_offset + self.__shdr[i].sh_size

                shdr_bytes=self.__elf[shdr_addr_start:shdr_addr_end]
                md=Cs(CS_ARCH_X86,CS_MODE_64)
                md.detail=True
                #md.syntax = CS_OPT_SYNTAX_ATT
                #md.syntax = CS_OPT_SYNTAX_INTEL
                dissamble_ins=md.disasm(str(shdr_bytes),shdr_virtual_addr)
                self.dissamble_dict[i]=list(dissamble_ins)
                
                #self.__X_boundary[str(self.__shdr[i].section_name)]=[self.__shdr[i].sh_addr,self.__shdr[i].sh_addr+self.__shdr[i].sh_size]
            #record the address boundary of read only sections
            #elif self.__shdr[i].sh_flags==ELFSectionflags.SHF_ALLOC:
                #self.__R_boundary[str(self.__shdr[i].section_name)]=[self.__shdr[i].sh_addr,self.__shdr[i].sh_addr+self.__shdr[i].sh_size]
            #record the address boundary of read & write sections
            #elif self.__shdr[i].sh_flags==ELFSectionflags.SHF_ALLOC+ELFSectionflags.SHF_WRITE:
                #self.__RW_boundary[str(self.__shdr[i].section_name)]=[self.__shdr[i].sh_addr,self.__shdr[i].sh_addr+self.__shdr[i].sh_size]
        '''
    
    def GetXboundary(self):
        return self.__X_boundary

    def GetRboundary(self):
        return self.__R_boundary

    def GetRWboundary(self):
        return self.__RW_boundary

    def Output(self):
        #out=open("./dissamble.txt","w")
        for key in self.dissamble_dict:
            for ins in self.dissamble_dict[key]:
                str1="%x:\t%s\t%s\t%s\n"%(ins.address,binascii.hexlify(ins.bytes),ins.mnemonic,ins.op_str)
                #out.write(str1)
                print(str1)
        #out.close()

