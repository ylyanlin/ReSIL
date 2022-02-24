"""
Insert the summarized instructions for cases that the access of 
the argument is in helper functions and remove irrelevant instructions
"""

from __future__ import print_function
import stat
import argparse
import os
import sys
import re
import string
import pickle
import binascii
import numpy as np
import time
from collections import defaultdict
from capstone import *
from capstone.x86 import *
from ctypes import *
from typedef import *
from elf import *
from dissamble import *
from dissamble_full import *
from multiprocessing import Pool
from os.path import expanduser

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.common.py3compat import itervalues
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
	describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import LocationEntry
from elftools.common.py3compat import bytes2str

sys.setrecursionlimit(100000)

target_dir = "./callee-insert-ins"

dwarf = list()
text_addr = 0

binary_dict = dict()
# function_dict = dict()          #store function info start_addr:func_name
function_dict_bin2func = dict()
# structure_dict = defaultdict(dict)   #store structure info
function_call_dict = defaultdict(list)  # callee:[caller1, caller2,...]
function_call_dict_bin2func = defaultdict(list)

struct_info = dict()  # store structure info, func_name:structure_list
struct_info_bin2func = dict()

ret_type_dict = dict()  # func_addr:ret_type
arg_type_dict = dict()  # func_addr:[arg_type]
num_arg = dict()  # func_addr:num_arg
external_func_arg_nums = dict()
external_func_arg_types = dict()

entry2name = dict()
entry2inst_bytes = defaultdict(list)
uninsert_entry2inst_bytes = defaultdict(list)
entry2inst_strings = defaultdict(list)
entry2end = dict()
snaitized_inst_strings = defaultdict(list)
hashed_func_str = dict()

extern_func = dict()  # key: function address; value: function name

func_range = dict()
addr2ins = dict()
function_info = dict()
funcName2addr = dict()
# plt = dict()
offset2die = dict()
info_binfunc = dict()
#function_start2end = dict()


type_info = {
	#'char': 0,
	'int8': 100,
	'int16': 101,
	'int32': 102,
	'int64': 103,
	'float': 104,
	'pointer': 105,
	#'enum': 7,
	#'struct': 8,
	#'union': 9
}

#we only extract instructions which will access these registersp
bit8 = ['dil','sil','dl','cl','r8l','r9l']
bit16 = ['di','si','dx','cx','r8w','r9w']
bit32 = ['edi','esi','edx','ecx','r8d','r9d','esp','ebp']
bit64 = ['rdi','rsi','rdx','rcx','r8','r9','rsp','rbp']
floating = ['xmm0','xmm1','xmm2','xmm3','xmm4','xmm5','xmm6','xmm7']


def approximate_type(type_str):
	int8_list = ['_Bool', 'bool', 'char', 'unsigned char', 'signed char']
	int16_list = ['short', 'unsigned short', 'short unsigned int','short int']
	int32_list = ['int', 'signed int', 'unsigned int']
	int64_list = ['long int', 'long unsigned int', 'long long int', 'long long unsigned int']

	# int_list = ['_Bool', 'unsigned int', 'int', 'long long int', 'long long unsigned int', 'unsigned short',
	# 'short unsigned int', 'short', 'long unsigned int', 'short int', 'long int']
	# char_list = ['char', 'unsigned char', 'signed char']
	if type_str[-1] == '*' or type_str == 'func_ptr' or type_str.split()[0][-1] == '*' or type_str.find('* [') != -1 or type_str.find('&') != -1:
		return 'pointer'
	elif type_str in int8_list:
		return 'int8'
	elif type_str in int16_list:
		return 'int16'
	elif type_str in int32_list:
		return 'int32'
	elif type_str in int64_list:
		return 'int64'
	elif type_str[:5] == 'enum ':
		return 'enum'
	# elif type_str in char_list:
	# return 'char'
	elif type_str[:7] == 'struct ':
		return 'struct'
	elif type_str[:6] == 'union ':
		return 'union'
	elif type_str == 'double' or type_str == 'long double':
		return 'float'
	else:
		return type_str

def tohex(val, nbits):
	value = hex((val + (1 << nbits)) % (1 << nbits))
	return value


def disassembling(shdr,elfparse,start_addr,end_addr):
	#print(start_addr, end_addr)
	disassm = Dissamble(elfparse.elf,shdr,start_addr,end_addr)
	i = 0
	addr2inst = dict()
	#ins_array = dict()
	for ins in disassm.dissambled_ins:
		addr2inst[i] = [ins.address, ins]
		i += 1

	#print(i)
	return addr2inst


# for ins in disassm.dissamble_dict['.plt']:
# pltins[ins.address] = ins

def get_function_info(binname):
	function_start2end = dict()
	cmd = "readelf -s -W " + binname + " |grep FUNC|awk '{print $2,$3, $8}'"
	with os.popen(cmd) as file:
		for line in file:
			line = line.split()
			func_name = line[2]
			# print func_name
			func_start = int(line[0], 16)

			if "0x" in line[1]:
				size = int(line[1],16)
			else:
				size = int(line[1])
			func_end = func_start + size
			#print(func_start,func_end)
			if (func_start > 0 and func_start != func_end):
				# function_info[func_name] = (func_start,func_end)
				function_info[func_start] = func_name
				funcName2addr[func_name] = func_start
				function_start2end[func_start] = func_end
	# print(funcName2addr)
	return function_start2end

def find_disp(op_str):
	disp_index = op_str.find("+")
	new_op_str = op_str[:disp_index] + ']'

	return new_op_str

#replace call with D6 imm32 the first byte is the number of argument, the next 2 bytes are the type for each argument:

def replace_call_external(func_name,len):
	global external_func_arg_nums, external_func_arg_types
	inst_bytes = np.empty(16, dtype=int)

	if func_name in external_func_arg_nums and func_name in external_func_arg_nums :
		arg_nums = external_func_arg_nums[func_name]
		if arg_nums > 14:
			return inst_bytes.tolist()

		inst_bytes[0] = 0xD6
		inst_bytes[1] = arg_nums
		replaced_type_value = np.full(14, 115, dtype=int)

		if func_name in external_func_arg_types:
			type_list = external_func_arg_types[func_name]
			index = 0
			for i in type_list:
				# print(i)
				temp_type = approximate_type(i)
				if temp_type in type_info:
					type_value = type_info[temp_type]
					replaced_type_value[index] = type_value
					# inst_bytes[index+2] = type_value
					index += 1
				else:
					return inst_bytes.tolist()

		for j in range(2, 16):
			inst_bytes[j] = replaced_type_value[j - 2]

	return inst_bytes.tolist()


def replace_call(func_addr, len):
	global num_arg, arg_type_dict
	'''
	inst_bytes = np.empty(len,dtype = int)
	if func_addr in num_arg:
		arg_nums = num_arg[func_addr]
		if arg_nums > 16:
			return inst_bytes.tolist()
	inst_bytes[0] = 0xD6
	inst_bytes[1] = arg_nums

	for j in range(2, len):
		inst_bytes[j] = 0

	'''

	inst_bytes = np.empty(16, dtype=int)
	if func_addr in num_arg:
		arg_nums = num_arg[func_addr]
		if arg_nums > 14:
			return inst_bytes.tolist()

		inst_bytes[0] = 0xD6
		inst_bytes[1] = arg_nums
		replaced_type_value = np.full(14,115, dtype=int)



		#print(len(type_list))
		if func_addr in arg_type_dict:
			type_list = arg_type_dict[func_addr]
			index = 0
			for i in type_list:
				#print(i)
				temp_type = approximate_type(i)
				if temp_type in type_info:
					type_value = type_info[temp_type]
					replaced_type_value[index] = type_value
					#inst_bytes[index+2] = type_value
					index += 1
				else:
					return inst_bytes.tolist()

		for j in range(2,16):
			inst_bytes[j] = replaced_type_value[j-2]



	return inst_bytes.tolist()

def disassemble_binary(shdr,elfparse):
	disassm = Dissamble_full(elfparse.elf, shdr)
	addr2ins = dict()
	for key in disassm.dissamble_dict:
		for ins in disassm.dissamble_dict[key]:
			if key != ".plt":
				addr2ins[ins.address] = ins

	return addr2ins


def find_op_size(opcode):
	count = 0
	for op in opcode:
		if op != 0:
			count += 1
		else:
			break

	return count

def insert_ins(addr, end_addr, read_ins_info,assembly,num_floats):

	#unused 1-byte opcode: 0xD6
	#unused 2-byte opcode: integer register 0x0f 0x25, floating point register 0x0f 0x27
	#unused 3-byte opcode : integer register 0x0f 0x38 0x51, floating point register 0x0f 0x38 0x53
	inserted_ins = list()
	if addr in read_ins_info:
		for offset_list in read_ins_info[addr]:
			for offset in offset_list:
				inst_bytes = list()
				inserted_ins_bytes = list()
				if offset in assembly:
					if offset > end_addr or offset < addr:
						ins = assembly[offset]
						#print("%x\t%s\t%s"%(ins.address,ins.mnemonic,ins.op_str))
						for byte in ins.bytes:
							#print("byte "+str(hex(byte)))
							inst_bytes.append(byte)

						ins_size = len(inst_bytes)

						#print(inst_bytes)
						if find_op_size(ins.prefix) != 0 and ins.rex != 0:
							prefix = inst_bytes[0]
							rex = inst_bytes[1]
							inserted_ins_bytes.append(prefix)
							inserted_ins_bytes.append(rex)
							opcode_index = 2
						elif find_op_size(ins.prefix) == 0 and ins.rex != 0:
							prefix = 0
							rex = inst_bytes[0]
							inserted_ins_bytes.append(rex)
							opcode_index = 1
						elif find_op_size(ins.prefix) != 0 and ins.rex == 0:
							prefix = inst_bytes[0]
							inserted_ins_bytes.append(prefix)
							rex = 0
							opcode_index = 1
						else:
							prefix = 0
							rex = 0
							opcode_index = 0

						opcode_size = find_op_size(ins.opcode)

						if opcode_size == 1:
							inserted_ins_bytes.append(0xD6)
							for i in range(opcode_index+opcode_size,ins_size):
								inserted_ins_bytes.append(inst_bytes[i])
						elif opcode_size == 2:
							inserted_ins_bytes.append(0x0f)
							if 'xmm' not in ins.op_str:
								inserted_ins_bytes.append(0x25)
								for i in range(opcode_index+opcode_size,ins_size):
									inserted_ins_bytes.append(inst_bytes[i])
							else:
								if num_floats > 0:
									print("find xmm")
									inserted_ins_bytes.append(0x27)
									for i in range(opcode_index+opcode_size,ins_size):
										inserted_ins_bytes.append(inst_bytes[i])
								else:
									inserted_ins_bytes = list()
						elif opcode_size == 3:
							inserted_ins_bytes.append(0x0f)
							inserted_ins_bytes.append(0x38)
							if 'xmm' not in ins.op_str:
								inserted_ins_bytes.append(0x51)
								for i in range(opcode_index+opcode_size,ins_size):
									inserted_ins_bytes.append(inst_bytes[i])
							else:
								if num_floats > 0:
									inserted_ins_bytes.append(0x53)
									for i in range(opcode_index+opcode_size,ins_size):
										inserted_ins_bytes.append(inst_bytes[i])
								else:
									inserted_ins_bytes = list()

						#for i in range(opcode_index+opcode_size,ins_size):
							#inserted_ins_bytes.append(inst_bytes[i])

						#print("new ins bytes",inserted_ins_bytes)
						#if len(inserted_ins_bytes) > 0:
						inserted_ins.append(inserted_ins_bytes)

						'''
						print("\tPrefix: ",ins.prefix)
						print("\trex: 0x%x" %ins.rex)
						for op in ins.opcode:
							if op != 0:
								print("\topcode: %x "%op)
						if find_op_size(ins.opcode) > 1:
							print("opcode is larger than 1 byte")
						'''

	return inserted_ins


def only_integer_arg(addr):
	global arg_type_dict

	if addr in arg_type_dict:
		type_list = arg_type_dict[addr]
		index = 0
		for i in type_list:
			# print(i)
			temp_type = approximate_type(i)
			if temp_type in type_info:
				if temp_type == 'float':
					return False
			else:
				return False

		return True
	else:
		return False



def parse_function(shdr, elfparse, start_addr, end_addr,replace_call_flag,insert_ins_flag,read_ins_info,assembly,only_integer_flag,filter_out_flag,num_floats):
	index = 0
	addr2inst = disassembling(shdr, elfparse, start_addr, end_addr)
	#print(len(addr2inst))
	if only_integer_flag:
		if not only_integer_arg(start_addr):
			return
	for x in range(len(addr2inst)):
		[addr, ins] = addr2inst[x]
		if addr < end_addr and addr >= start_addr:
			index += 1
			# ins = addr2inst[addr]
			#if filter_out_flag:
			if ins.id != X86_INS_NOP:
				inst_bytes = list()
				sanitized_s = list()
				s = ''
				
				if ins.id != X86_INS_CALL and not (ins.id >= X86_INS_JA and ins.id <= X86_INS_JS):
					(regs_read, regs_write) = ins.regs_access()
					#print("%s\t%s" % (ins.mnemonic, ins.op_str))
					find_interested_reg = 0
					if len(regs_read) > 0:
						#print("\tRegisters read:", end="")
						for r in regs_read:
							reg_name = ins.reg_name(r)
							if reg_name in bit8 or reg_name in bit16 or reg_name in bit32 or reg_name in bit64 or reg_name in floating:
								find_interested_reg = 1
								#print(" %s" % (reg_name), end="")
						#print("")

					if len(regs_write) > 0:
						#print("\tRegisters modified:", end="")
						for r in regs_write:
							reg_name = ins.reg_name(r)
							if reg_name in bit8 or reg_name in bit16 or reg_name in bit32 or reg_name in bit64 or reg_name in floating:
								find_interested_reg = 1
								#print(" %s" % (reg_name), end="")
						#print("")
					if find_interested_reg:
						s = ins.mnemonic + " " + ins.op_str
						for byte in ins.bytes:
							#print("byte "+str(hex(byte)))
							inst_bytes.append(byte)
							sanitized_s.append(byte)



				#sanitized_s = ins.mnemonic+" "+ins.op_str
				#print(s)

				# for a direct call instruction, transform the target to the name of the function
				first = 0
				if ins.id == X86_INS_CALL:
					s = ins.mnemonic + " " + ins.op_str
					for byte in ins.bytes:
						# print("byte "+str(hex(byte)))
						inst_bytes.append(byte)
						sanitized_s.append(byte)
					if not (ins.operands[0].type == X86_OP_REG or ins.operands[0].type == X86_OP_MEM):
						if ins.operands[0].value.imm in function_info:
							target = ins.operands[0].value.imm
							name = function_info[ins.operands[0].value.imm]
							if replace_call_flag:
								inst_bytes = replace_call(target, ins.size)
								if all([ v == 0 for v in inst_bytes ]):
									num_arg.pop(start_addr)
									arg_type_dict.pop(start_addr)

							if insert_ins_flag and first == 0:
								inserted_ins = insert_ins(start_addr, end_addr,read_ins_info,assembly,num_floats)
								first = 1
								if len(inserted_ins) != 0:
									for inserted_ins_bytes in inserted_ins:
										entry2inst_bytes[start_addr].append(inserted_ins_bytes)


							s = ins.mnemonic + " " + name
							# sanitized_s = ins.mnemonic+" "+name
							for i in range(len(sanitized_s) - 1, len(sanitized_s) - 4, -1):
								sanitized_s[i] = 0

							if start_addr in function_info:
								caller_name = function_info[start_addr]
								function_call_dict[(caller_name, name)].append(index)

						if ins.operands[0].value.imm in extern_func:
							name = extern_func[ins.operands[0].value.imm]
							if replace_call_flag:
								inst_bytes = replace_call_external(name, ins.size)
								if all([ v == 0 for v in inst_bytes ]):
									num_arg.pop(start_addr)
									arg_type_dict.pop(start_addr)


							s = ins.mnemonic + " " + name
							# sanitized_s = ins.mnemonic+" "+name
							for i in range(len(sanitized_s) - 1, len(sanitized_s) - 4, -1):
								sanitized_s[i] = 0

				if (ins.id >= X86_INS_JA and ins.id <= X86_INS_JS):
					s = ins.mnemonic + " " + ins.op_str
					for byte in ins.bytes:
						# print("byte "+str(hex(byte)))
						inst_bytes.append(byte)
						sanitized_s.append(byte)
					if (ins.operands[0].type == X86_OP_REG) or (ins.operands[0].type == X86_OP_MEM):
						continue

					target_addr = ins.operands[0].value.imm
					next_inst_addr = ins.address + ins.size
					offset = target_addr - start_addr
					offset = tohex(offset, 64)
					s = ins.mnemonic + " " + str(offset)[:len(str(offset)) - 1]
					# sanitized_s = ins.mnemonic
					if ins.size == 2:
						sanitized_s[1] = 0
					else:
						for i in range(len(sanitized_s) - 1, len(sanitized_s) - 4, -1):
							sanitized_s[i] = 0

				# qword[rip + offset]
				if ins.op_count(X86_OP_MEM) > 0 and find_interested_reg:
						operand_count = len(ins.operands)
						for j in range(operand_count):
							if ins.operands[j].type == X86_OP_MEM:
								if ins.operands[j].value.mem.base == X86_REG_RIP:
									raw_off = ins.disp_offset
									if ins.disp_size != 0:
										# print("instruction: "+ s)
										# print("\t\tinstruction offset: (%d,%d) "%(raw_off,ins.disp_size))

										for i in range(raw_off, raw_off + ins.disp_size):
											sanitized_s[i] = 0
					
				if (len(inst_bytes)) != 0:
					entry2inst_bytes[start_addr].append(inst_bytes)
					uninsert_entry2inst_bytes[start_addr].append(inst_bytes)
				if len(s) != 0:
					entry2inst_strings[start_addr].append(unicode(s))
				snaitized_inst_strings[start_addr].append(unicode(sanitized_s))

		#if addr == end_addr:
			#if x > 0:
				#[addr_end, ins] = addr2inst[x - 1]
	[addr_end, ins] = addr2inst[len(addr2inst) - 1]
	entry2end[start_addr] = int(addr_end)


def parseAsm(asmfile):
	global text_addr
	func_name_pattern = re.compile("[0-9a-fA-F]{1,16}\s<\S*>:")

	lines = list()

	with open(asmfile, "r") as f:
		for line in f:
			lines.append(line)

	i = 0
	while i < len(lines):
		# print i
		# print lines[i-1]
		line = lines[i]
		if "Disassembly of section .plt:" in line:
			# print "**** find plt"
			i += 1
			while 'Disassembly of section .text:' not in lines[i]:
				m = func_name_pattern.match(lines[i])
				if (m != None):
					line = lines[i].rstrip()
					line_m = lines[i].split(" ")
					if all(c in string.hexdigits for c in line_m[0]):
						func_addr = int(line_m[0], 16)
						func_name = line_m[1][1:len(line_m[1]) - 2]
						plt_index = func_name.find("@plt")
						extern_func[func_addr] = func_name[:plt_index]
				i += 1
			if 'Disassembly of section .text:' in lines[i]:
				text_addr_line = lines[i + 2]
				# print text_addr_line
				# print "text_line",text_addr_line
				m = func_name_pattern.match(text_addr_line)
				if (m != None):
					text_addr = int(text_addr_line.split(" ")[0], 16)
					break
		i += 1

	i = 0
	while i < len(lines):
		# print i
		# print lines[i-1]
		line = lines[i]
		m = func_name_pattern.match(line)
		if (m != None):
			index = 0
			line_m = line.split(" ")
			func_addr = int(line_m[0], 16)
			func_name = line_m[1][1:len(line_m[1]) - 3]
			i += 1
			inst_addr = 0
			while func_name_pattern.match(lines[i]) == None and i < len(lines) - 1:
				# print lines[i]
				index += 1

				line = lines[i]
				line = line.rstrip()
				line_list = line.split()
				if len(line_list) > 1:
					addr = line_list[0][:len(line_list[0]) - 1]
					if all(c in string.hexdigits for c in addr):
						inst_addr = int(addr, 16)

				i += 1

			if func_name_pattern.match(lines[i]) != None:
				next_func_addr = int(lines[i].split()[0], 16)
				func_range[func_addr] = next_func_addr

		else:

			i += 1

def get_read_arg_nums(read_offset_info,addr):
	arg_nums = 16
	for index in range(len(read_offset_info[addr])):
		read_offset_list = read_offset_info[addr][index]
		if not all([v == 0 for v in read_offset_list]) and index < 6:
			arg_nums = index +1
	return arg_nums





def execute_typearmor(bin_path,target_dir):
	cwd = os.getcwd()
	home = expanduser("~")
	type_armor_path = "../static-analysis/typearmor-master-insert-ins/server-bins"
	os.chdir(type_armor_path)

	os.environ["DYNINST_ROOT"] = home+"/dyninst-9.3.1"
	os.environ["DYNINST_LIB"] = os.environ["DYNINST_ROOT"] + '/install/pwd/lib'
	os.environ["DYNINSTAPI_RT_LIB"] = os.environ["DYNINST_LIB"] + "/libdyninstAPI_RT.so"
	os.environ["LD_LIBRARY_PATH"] = os.getcwd()
	os.environ["LD_LIBRARY_PATH"] += os.environ["DYNINST_LIB"]

	opt_path = home+"/llvm-toolchain/llvm-7.0.0.build/bin"



	orig_bin = os.path.basename(bin_path)
	typearmor_path = orig_bin+"_typearmor.txt"

	cmd = "cp " + bin_path + " " + orig_bin
	os.system(cmd)

	cmd = "bash ../run-ta-static.sh " + orig_bin
	os.system(cmd)

	'''
	if os.path.isfile("../out/" + "binfo." + orig_bin):
		cmd = "mv " + "../out/" + "binfo." + orig_bin + " " + cwd + "/" + typearmor_path
		os.system(cmd)

	os.chdir(cwd)
	'''
	read_ins_info = defaultdict(list)
	if os.path.isfile("../out/" + "binfo." + orig_bin):
		read_ins_info = get_read_ins("../out/" + "binfo." + orig_bin)

	return read_ins_info
def get_read_ins(typearmor_file):
	print("reading "+ typearmor_file)
	#func_name_pattern = re.compile("[0-9a-fA-F]{1,16}\s=\s[0-9]{1,2}\s(\S*):")
	read_inst_info = defaultdict(list)
	read_inst_count = dict()

	with open(typearmor_file, "r") as f:
		lines = f.readlines()
		if len(lines) == 0:
			return read_inst_info
		line_count = 0
		line = lines[line_count]

		while "[args]" not in line and line_count < len(lines)-1:
			line_count += 1
			line = lines[line_count]

		if "[args]" in line:
			line_count += 1
			next_line = lines[line_count]
			while ("[icall-args]" not in next_line and line_count < len(lines)):
				#print(next_line)
				if "=" in next_line:
					#print("find "+next_line)
					splitted_next_line = next_line.split()
					if len(splitted_next_line) > 1:
						function_addr = int(splitted_next_line[0], 16)
						parameter_number = int(splitted_next_line[2])
						line_count += 1
						next_processed_line = line_count
						read_count = 0
						while next_processed_line < line_count + 14 and line_count+14 < len(lines)  :
							next_line = lines[next_processed_line]
							next_line = next_line.rstrip()
							next_line_list = next_line.split(":")
							read_offset_list = list()
							if len(next_line_list) > 1:
								if next_line_list[1] != '':
									offset_list = next_line_list[1].split(' ')
									for i in offset_list:
										if len(i) != 0:
											read_offset = int(i,16)
											read_offset_list.append(read_offset)
									read_inst_info[function_addr].append(read_offset_list)
								else:
									read_offset = 0
									read_offset_list.append(read_offset)
									read_inst_info[function_addr].append(read_offset_list)
							else:
								read_offset_list.append(0)
								read_inst_info[function_addr].append(read_offset_list)
							next_processed_line += 1

						line_count += 14
						if line_count < len(lines):
							next_line = lines[line_count]
				else:
					line_count += 1
					if line_count < len(lines):
						next_line = lines[line_count]


	return read_inst_info


def get_config():
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--binary_folder', dest='binary_folder', help='The binary folder to be processed.',
						type=str, required=True)

	parser.add_argument('-o', '--output_dir', dest='output_dir',
						help='The directory to saved the pickle file.', type=str, required=True)

	parser.add_argument('-r', '--replace_call', dest='replace_call', help='The flag to indicate whether a call instruction should be replaced.', type=int,
						required=True)

	parser.add_argument('-i', '--insert_ins', dest='insert_ins',
						help='The flag to indicate whether special instructions are inserted.', type=int,
						required=True)

	parser.add_argument('-oi', '--only_integer', dest='only_integer',
						help='The flag to indicate whether only use functions with integer arguments.', type=int,
						required=True)

	parser.add_argument('-filter', '--filer_out', dest='filter_out',
						help='The flag to indicate whether filter out some noise data in the training.', type=int,
						required=True)

	parser.add_argument('-pd', '--pickle_folder', dest='pickle_folder',
						help='The pickle folder to be processed.', type=str,
						required=True)

	args = parser.parse_args()

	config_info = {
		'binary_folder': args.binary_folder,
		'output_dir': args.output_dir,
		'replace_call': args.replace_call,
		'insert_ins': args.insert_ins,
		'only_integer':args.only_integer,
		'filter_out': args.filter_out,
		'pickle_folder': args.pickle_folder
	}

	return config_info


def process_bin(bin_path,output_folder,replace_call_flag,insert_ins_flag,only_integer_flag,filter_out_flag,train_flag,pickle_folder):
	global value_list, struct_info, ret_type_dict, arg_type_dict, num_arg, entry2name,external_func_arg_types,external_func_arg_nums
	global entry2inst_bytes, entry2inst_strings, entry2end, snaitized_inst_strings, extern_func, uninsert_entry2inst_bytes
	global func_range, addr2ins, function_info, funcName2addr, offset2die, function_call_dict

	function_dict = dict()
	value_list = list()
	struct_info = dict()
	function_call_dict = defaultdict(list)

	ret_type_dict = dict()  # func_addr:ret_type
	arg_type_dict = dict()  # func_addr:[arg_type]
	num_arg = dict()  # func_addr:num_arg
	external_func_arg_types = dict()
	external_func_arg_nums = dict()

	entry2name = dict()
	entry2inst_bytes = defaultdict(list)
	uninsert_entry2inst_bytes = defaultdict(list)
	entry2inst_strings = defaultdict(list)
	entry2end = dict()
	snaitized_inst_strings = defaultdict(list)

	extern_func = dict()  # key: function address; value: function name

	func_range = dict()
	addr2ins = dict()
	function_info = dict()
	funcName2addr = dict()
	# plt = dict()
	offset2die = dict()
	#function_start2end = dict()

	ori_bin = os.path.basename(bin_path)

	cmd = "mkdir -p " + output_folder
	os.system(cmd)

	pickle_name = ori_bin + ".pkl"



	#if (not os.path.isfile(output_folder + "/" + pickle_name)):
	try:
		fd_bin = open(bin_path, "rb")
	except IOError as err:
		print("IOError:" + str(err))
		exit(1)
	bin_raw = fd_bin.read()
	fd_bin.close()

	elfparse = Elf64_Parse(bin_raw)

	shdr = elfparse.GetShdr()



	dwarf_info = ori_bin + ".dwarf.txt"
	asm_info = ori_bin + ".dis.txt"


	'''

	os.system("mkdir -p " + target_dir)

	cmd = "mkdir -p " + target_dir + "/" + ori_bin
	os.system(cmd)


	os.chdir(target_dir + "/" + ori_bin)

	# get llvm info
	cmd = "cp " + bin_path + " " + ori_bin
	os.system(cmd)


	cmd = "llvm-dwarfdump " + bin_path + " > " + dwarf_info
	os.system(cmd)

	cmd = "objdump -M intel -d " + bin_path + " > " + asm_info
	os.system(cmd)
	'''

	typearmor_path = ori_bin + "_typearmor.txt"

	if os.path.isfile(pickle_folder+"/"+pickle_name) and not os.path.isfile(output_folder+"/"+pickle_name):

		read_ins_info = defaultdict(list)
		if insert_ins_flag:
			read_ins_info = execute_typearmor(bin_path, target_dir)
			'''
			if os.path.isfile(typearmor_path):
				read_ins_info = get_read_ins(typearmor_path)
			'''


		assembly = disassemble_binary(shdr,elfparse)


		function_start2end = get_function_info(bin_path)
		#get_functionGT(dwarf_info)
		# read_dwarfInfo(output)
		#process_file(bin_path)
		#parseAsm(asm_info)


		if insert_ins_flag and len(read_ins_info) == 0:
			#os.chdir("../../")
			return


		#for i in function_start2end:
			#parse_function(shdr, elfparse, i, function_start2end[i],replace_call_flag,insert_ins_flag,read_ins_info,assembly,only_integer_flag,filter_out_flag)

		#print(function_start2end)

		new_function_dict = dict()
		with open(pickle_folder+"/"+pickle_name, 'r') as f:
			data = pickle.load(f)
			function_dict = data['functions']
			for name in function_dict:
				(start_addr,end_addr) = function_dict[name]['boundaries']
				num_floats = 0
				args_types = function_dict[name]['args_type']
				for i in args_types:
					if i in ['float','double','long double' ]:
						num_floats += 1
				if  start_addr in function_start2end:
					print("start_addr:",hex(start_addr))
					parse_function(shdr, elfparse, start_addr, function_start2end[start_addr],replace_call_flag,insert_ins_flag,read_ins_info,assembly,only_integer_flag,filter_out_flag,num_floats)
			
				new_function_dict[name] = {'ret_type': function_dict[name]['ret_type'], 'args_type': function_dict[name]['args_type'],
							'inst_bytes': entry2inst_bytes[start_addr],
							'boundaries': function_dict[name]['boundaries'], 'num_args': function_dict[name]['num_args'],
							'inst_strings': function_dict[name]['inst_strings']} 

			new_info={'functions':new_function_dict,'binary_filename':data['binary_filename'],'structures':data['structures'],'arch':data['arch'],
				'text_addr':data['text_addr'],'function_calls':data['function_calls'],'extern_functions':data['extern_functions'],'bin_raw_bytes':data['bin_raw_bytes']}


			with open(output_folder+"/"+pickle_name,"wb") as f:
					pickle.dump(new_info, f) 

	#os.chdir("../../")




if __name__ == '__main__':

	#bin_directory = sys.argv[1]
	config_info = get_config()
	bin_directory = config_info['binary_folder']
	output_folder = config_info['output_dir']
	replace_call_flag = int(config_info["replace_call"])
	insert_ins_flag = int(config_info["insert_ins"])
	only_integer_flag = int(config_info["only_integer"])
	fliter_out_flag = int(config_info["filter_out"])
	pickle_folder = config_info['pickle_folder']


	'''
	train_app = ['addr2line-gcc-O2']
	test_app = []
	'''


	'''
	#train_app =['addr2line']
	#clean_pickle_directory = sys.argv[3]
	start = time.time()

	files = list()

	#p = Pool(4)
	train_app = ['addr2line', 'as',
				 'consumer-jpeg',
				 'lencod', 'lua',
				  'gprof', 'ar', 'cjpeg', 'vorbiscomment']
	'''

	for filename in os.listdir(pickle_folder):
		#bin_path = bin_directory + "/" + filename
		#files.append(bin_path)

		if 'inetutils-ftp' not in filename and 'inetutils-tftp' not in filename and 'utillinux-login' not in filename:
			train_flag = 1
			print(filename)
			#if not os.path.isfile(output_folder+"/"+filename+".pkl"):
			bin_name = filename[:filename.find('.pkl')]
			bin_path = bin_directory+"/" + bin_name 
			process_bin(bin_path, output_folder, replace_call_flag, insert_ins_flag, only_integer_flag, fliter_out_flag,
							train_flag,pickle_folder)