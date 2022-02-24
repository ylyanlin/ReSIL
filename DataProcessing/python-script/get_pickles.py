"""
extract instruction bytes from compiled binary
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
from collections import namedtuple
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
from elftools.dwarf.ranges import RangeEntry

sys.setrecursionlimit(100000)

target_dir = "./target_info"

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
funcStart2End = dict()
# plt = dict()
offset2die = dict()
info_binfunc = dict()


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


def process_file(filename):
	print('Processing file:', filename)
	with open(filename, 'rb') as f:
		elffile = ELFFile(f)
		if not elffile.has_dwarf_info():
			print('  file has no DWARF info')
			return

		# get_dwarf_info returns a DWARFInfo context object, which is the
		# starting point for all DWARF-based processing in pyelftools.
		dwarfinfo = elffile.get_dwarf_info()
		range_lists = dwarfinfo.range_lists()
		decode_func(dwarfinfo,range_lists)


def check_attr(attributes, attr_name):
	for attr in itervalues(attributes):
		if attr.name == attr_name:
			return True
	return False


def decode_type_parameter(dwarfinfo, die, attr_name, cu,func_name, source_info):
	s = ''
	t = ''
	name = ''
	is_array = 0
	while die and check_attr(die.attributes, attr_name):
		# print("decodeing type %s"%(die.tag))
		if die.tag == "DW_TAG_pointer_type":
			if is_array:
				s = '*' + s
			else:
				s += '*'
		elif die.tag == "DW_TAG_reference_type":
			s += '&'
		# elif die.tag == "DW_TAG_const_type":
		# t = 'const'
		elif die.tag == 'DW_TAG_array_type':
			is_array = 1
			for child in die.iter_children():
				if child.tag == "DW_TAG_subrange_type":
					if check_attr(child.attributes, 'DW_AT_count'):
						count = child.attributes['DW_AT_count'].value
						temp = ' [' + str(count) + ']'
						s += temp
					elif check_attr(child.attributes, 'DW_AT_upper_bound'):
						count = child.attributes['DW_AT_upper_bound'].value + 1
						temp = ' [' + str(count) + ']'
						s += temp

		elif die.tag == "DW_TAG_typedef":
			if check_attr(die.attributes, 'DW_AT_name'):
				name = die.attributes['DW_AT_name'].value
				offset = die.attributes['DW_AT_type'].value
				if (offset + cu.cu_offset) in offset2die:
					# print("offset in offset2die %x"%(offset+cu.cu_offset))
					die = offset2die[offset + cu.cu_offset]
					if die.tag == "DW_TAG_structure_type":

						t = "struct"
						# print("structure type")
						if check_attr(die.attributes, 'DW_AT_name'):
							s = t + ' ' + die.attributes['DW_AT_name'].value + s
							# print(s)
							return s
						else:
							s = t + ' ' + name + s
							return s
					
					elif die.tag == "DW_TAG_enumeration_type":
						t = "enum"
						if check_attr(die.attributes, 'DW_AT_name'):
							s = t + ' ' + die.attributes['DW_AT_name'].value + s
							return s
						else:
							s = t + ' ' + name + s
							return s
					
					elif die.tag == "DW_TAG_union_type":
						t = "union"
						if check_attr(die.attributes, 'DW_AT_name'):
							s = t + ' ' + die.attributes['DW_AT_name'].value + s
							return s
						else:
							if name:
								s = t + ' ' + name + s
							else:
								s = t + ' ' + 'void'
							return s

					continue


		elif die.tag == "DW_TAG_structure_type":
			t = "struct"
			# print("structure type")
			if check_attr(die.attributes, 'DW_AT_name'):
				s = t + ' ' + die.attributes['DW_AT_name'].value + s
				# print(s)
				return s
			else:
				s = t + ' ' + name + s
				if s == 'struct *':
					s = 'struct void*'
				return s
			'''
			elif die.tag == "DW_TAG_enumeration_type":
	
				offset = die.attributes['DW_AT_type'].value
				if (offset + cu.cu_offset) in offset2die:
					die = offset2die[offset + cu.cu_offset]
			'''

		elif die.tag == "DW_TAG_enumeration_type":
			t = "enum"
			if check_attr(die.attributes, 'DW_AT_name'):
				s = t + ' ' + die.attributes['DW_AT_name'].value + s
				return s
			else:
				s = t + ' ' + name + s
				return s

		elif die.tag == "DW_TAG_union_type":
			t = "union"
			if check_attr(die.attributes, 'DW_AT_name'):
				s = t + ' ' + die.attributes['DW_AT_name'].value + s
				return s
			else:
				if name:
					s = t + ' ' + name + s
				else:
					s = t + ' ' + 'void'
				return s

		elif die.tag == "DW_TAG_subroutine_type":
			s = 'func_ptr'
			return s


		# die = get_die_by_offset(dwarfinfo,die.attributes['DW_AT_type'].value)
		offset = die.attributes['DW_AT_type'].value
		# print("offset %x"%(offset))
		if (offset + cu.cu_offset) in offset2die:
			# print("offset in offset2die %x"%(offset+cu.cu_offset))
			die = offset2die[offset + cu.cu_offset]

			# param is struct
			if die.tag == "DW_TAG_structure_type":
				t = "struct"
				# print("structure type")
				if check_attr(die.attributes, 'DW_AT_name'):
					s = t + ' ' + die.attributes['DW_AT_name'].value + s
					# print(s)
					return s
				else:
					s = t + ' ' + name + s
					if s == 'struct *':
						s = 'struct void*'
						return s
				'''
				elif die.tag == "DW_TAG_enumeration_type":
					t = "enum"
					if check_attr(die.attributes, 'DW_AT_name'):
						s = t + ' ' + die.attributes['DW_AT_name'].value + s
						return s
					else:
						s = t + ' ' + name + s
						return s
				'''
			elif die.tag == "DW_TAG_union_type":
				t = "union"
				if check_attr(die.attributes, 'DW_AT_name'):
					s = t + ' ' + die.attributes['DW_AT_name'].value + s
					return s
				else:
					if name:
						s = t + ' ' + name + s
					else:
						s = t + ' ' + 'void'
					return s

			elif die.tag == "DW_TAG_subroutine_type":
				s = 'func_ptr'
				return s

		else:
			return s

	if die:
		if check_attr(die.attributes, 'DW_AT_name'):
			if t:
				s = t + ' ' + die.attributes['DW_AT_name'].value + s;
			else:
				s = die.attributes['DW_AT_name'].value + s;
		elif die.tag == "DW_TAG_pointer_type":
			s = 'void*'

	if s == '*':
		s = 'void*'
	if s == 'struct *':
		s = 'struct void*'
	# print('tyep: '+s)
	return s


def decode_type(dwarfinfo, die, attr_name, cu):
	s = ''
	t = ''
	name = ''
	is_array = 0
	while die and check_attr(die.attributes, attr_name):
		# print("decodeing type %s"%(die.tag))
		if die.tag == "DW_TAG_pointer_type":
			if is_array:
				s = '*' + s
			else:
				s += '*'
		elif die.tag == "DW_TAG_reference_type":
			s += '&'
		# elif die.tag == "DW_TAG_const_type":
		# t = 'const'
		elif die.tag == 'DW_TAG_array_type':
			is_array = 1
			for child in die.iter_children():
				if child.tag == "DW_TAG_subrange_type":
					if check_attr(child.attributes, 'DW_AT_count'):
						count = child.attributes['DW_AT_count'].value
						temp = ' [' + str(count) + ']'
						s += temp
					elif check_attr(child.attributes, 'DW_AT_upper_bound'):
						count = child.attributes['DW_AT_upper_bound'].value + 1
						temp = ' [' + str(count) + ']'
						s += temp

		elif die.tag == "DW_TAG_typedef":
			if check_attr(die.attributes, 'DW_AT_name'):
				name = die.attributes['DW_AT_name'].value
				offset = die.attributes['DW_AT_type'].value
				if (offset + cu.cu_offset) in offset2die:
					# print("offset in offset2die %x"%(offset+cu.cu_offset))
					die = offset2die[offset + cu.cu_offset]
					if die.tag == "DW_TAG_structure_type":
						t = "struct"
						# print("structure type")
						if check_attr(die.attributes, 'DW_AT_name'):
							s = t + ' ' + die.attributes['DW_AT_name'].value + s
							# print(s)
							return s
						else:
							s = t + ' ' + name + s
							return s

					elif die.tag == "DW_TAG_enumeration_type":
						t = "enum"
						if check_attr(die.attributes, 'DW_AT_name'):
							s = t + ' ' + die.attributes['DW_AT_name'].value + s
							return s
						else:
							s = t + ' ' + name + s
							return s
					elif die.tag == "DW_TAG_union_type":
						t = "union"
						if check_attr(die.attributes, 'DW_AT_name'):
							s = t + ' ' + die.attributes['DW_AT_name'].value + s
							return s
						else:
							if name:
								s = t + ' ' + name + s
							else:
								s = t + ' ' + 'void'
							return s

					continue



		elif die.tag == "DW_TAG_structure_type":
			t = "struct"
			# print("structure type")
			if check_attr(die.attributes, 'DW_AT_name'):
				s = t + ' ' + die.attributes['DW_AT_name'].value + s
				# print(s)
				return s
			else:
				s = t + ' ' + name + s
				if s == 'struct *':
					s = 'struct void*'
				return s

		elif die.tag == "DW_TAG_enumeration_type":
			t = "enum"
			if check_attr(die.attributes, 'DW_AT_name'):
				s = t + ' ' + die.attributes['DW_AT_name'].value + s
				return s
			else:
				s = t + ' ' + name + s
				return s
		elif die.tag == "DW_TAG_union_type":
			t = "union"
			if check_attr(die.attributes, 'DW_AT_name'):
				s = t + ' ' + die.attributes['DW_AT_name'].value + s
				return s
			else:
				if name:
					s = t + ' ' + name + s
				else:
					s = t + ' ' + 'void'
				return s

		elif die.tag == "DW_TAG_subroutine_type":
			s = 'func_ptr'
			return s

		# die = get_die_by_offset(dwarfinfo,die.attributes['DW_AT_type'].value)
		offset = die.attributes['DW_AT_type'].value
		# print("offset %x"%(offset))
		if (offset + cu.cu_offset) in offset2die:
			# print("offset in offset2die %x"%(offset+cu.cu_offset))
			die = offset2die[offset + cu.cu_offset]

			# param is struct
			if die.tag == "DW_TAG_structure_type":
				t = "struct"
				# print("structure type")
				if check_attr(die.attributes, 'DW_AT_name'):
					s = t + ' ' + die.attributes['DW_AT_name'].value + s
					# print(s)
					return s
				else:
					s = t + ' ' + name + s
					if s == 'struct *':
						s = 'struct void*'
					return s

			elif die.tag == "DW_TAG_enumeration_type":
				t = "enum"
				if check_attr(die.attributes, 'DW_AT_name'):
					s = t + ' ' + die.attributes['DW_AT_name'].value + s
					return s
				else:
					s = t + ' ' + name + s
					return s
			elif die.tag == "DW_TAG_union_type":
				t = "union"
				if check_attr(die.attributes, 'DW_AT_name'):
					s = t + ' ' + die.attributes['DW_AT_name'].value + s
					return s
				else:
					if name:
						s = t + ' ' + name + s
					else:
						s = t + ' ' + 'void'
					return s

			elif die.tag == "DW_TAG_subroutine_type":
				s = 'func_ptr'
				return s

		else:
			return s

	if die:
		if check_attr(die.attributes, 'DW_AT_name'):
			if t:
				s = t + ' ' + die.attributes['DW_AT_name'].value + s;
			else:
				s = die.attributes['DW_AT_name'].value + s;
		elif die.tag == "DW_TAG_pointer_type":
			s = 'void*'

	if s == '*':
		s = 'void*'
	if s == 'struct *':
		s = 'struct void*'
	# print('tyep: '+s)
	return s


def decode_parameter(dwarfinfo, child_die, cu,func_name,source_info):
	
	if check_attr(child_die.attributes, 'DW_AT_abstract_origin'):
		offset = child_die.attributes['DW_AT_abstract_origin'].value
		if (offset+cu.cu_offset) in offset2die:
			die = offset2die[offset+cu.cu_offset]
			while check_attr(die.attributes, 'DW_AT_abstract_origin'):
				offset = die.attributes['DW_AT_abstract_origin'].value
				if (offset+cu.cu_offset) in offset2die:
					die = offset2die[offset+cu.cu_offset]

		if check_attr(die.attributes, 'DW_AT_type'):
			s = decode_type_parameter(dwarfinfo, die, 'DW_AT_type', cu,func_name,source_info)
			return s

	elif check_attr(child_die.attributes, 'DW_AT_type'):

		s = decode_type_parameter(dwarfinfo, child_die, 'DW_AT_type', cu,func_name,source_info)
		return s
		'''
		offset = child_die.attributes['DW_AT_type'].value
		#print(param_type)
		#die = get_die_by_offset(dwarfinfo,offset)
		if (offset+cu.cu_offset) in offset2die:
			die = offset2die[offset+cu.cu_offset]

			if die:
				s = decode_type(dwarfinfo,die,'DW_AT_type',cu)
				return s
		'''
	elif check_attr(child_die.attributes, 'DW_AT_name'):
		s = child_die.attributes['DW_AT_name'].value
		return s

	return None


def get_offset2die(dwarfinfo):
	for CU in dwarfinfo.iter_CUs():
		# offset_cu = CU.cu_offset
		for DIE in CU.iter_DIEs():
			offset2die[DIE.offset] = DIE


def get_die_by_offset(dwarfinfo, offset):
	for CU in dwarfinfo.iter_CUs():
		for DIE in CU.iter_DIEs():
			if DIE.offset == offset:
				return DIE

	return None


def attribute_has_range_list(attr):
	""" Only some attributes can have range list values, if they have the
		required DW_FORM (rangelistptr "class" in DWARF spec v3)
	"""
	if attr.name == 'DW_AT_ranges':
		if attr.form in ('DW_FORM_data4', 'DW_FORM_data8'):
			return True
	return False

def getGroundTruth(lp_header,CU,dwarfinfo,attr, DIE, range_lists,at_name,extern_at_name):
	arg_list = list()
	arg_count = 0
	extern_func_arg_count = 0
	extern_func_arg_list = list()
	arg_count_temp = 0
	entry = 0
	source_file = ''
	line_no = ''
	struct_arg = 0
	struct_arg_extern = 0
	source_info = ''

	func_name = attr.value
	print(func_name)

	#for i in itervalues(DIE.attributes):
		#print(i.name)

	#line info
	'''
	if check_attr(DIE.attributes, "DW_AT_decl_file"):
		source_file = DIE.attributes["DW_AT_decl_file"].value
	if check_attr(DIE.attributes, "DW_AT_decl_line"):
		line_no = DIE.attributes["DW_AT_decl_line"].value

	print(source_file, line_no)
	'''

	# functions in shared libraries
	if check_attr(DIE.attributes, "DW_AT_external") \
		and check_attr(DIE.attributes, "DW_AT_linkage_name"):
		extern_at_name[func_name] = 1
		print("find external")
		for child in DIE.iter_children():
			if child.tag == 'DW_TAG_formal_parameter':
				extern_func_arg_count += 1
				s = decode_parameter(dwarfinfo, child, CU, func_name, source_info)
				if s:
					extern_func_arg_list.append(s)

		external_func_arg_nums[func_name] = extern_func_arg_count
		external_func_arg_types[func_name] = extern_func_arg_list

	if check_attr(DIE.attributes, "DW_AT_ranges"):
		print("find range")
		if range_lists is None:
			print('  file has no .debug_ranges section')
		else:
			at_name[func_name] = 1 
			rangelist = range_lists.get_range_list_at_offset(DIE.attributes['DW_AT_ranges'].value)
			#print('   DIE %s. attr %s.\n%s' % (
			#DIE.tag,
			#DIE.attributes['DW_AT_ranges'].name,
			#rangelist))

			item = rangelist[0]
			entry = getattr(item,'begin_offset')
			#print("entry addr ", hex(entry))



	if check_attr(DIE.attributes, "DW_AT_low_pc"):

		entry = DIE.attributes['DW_AT_low_pc'].value
		print("find low pc", hex(entry))
		at_name[func_name] = 1

	if entry:
		print(hex(entry))
		
		if check_attr(DIE.attributes,"DW_AT_decl_file"):
			decl_file_idx = DIE.attributes["DW_AT_decl_file"].value - 1
			decl_file = lp_header['file_entry'][decl_file_idx].name
			#print(decl_file)
			if check_attr(DIE.attributes,"DW_AT_decl_line"):
				line_no = DIE.attributes["DW_AT_decl_line"].value

				source_info = decl_file+":"+str(line_no)
				
				print(source_info)

		if check_attr(DIE.attributes, "DW_AT_type"):
			ret_type = decode_type(dwarfinfo, DIE, 'DW_AT_type', CU)
		else:
			ret_type = 'void'

		for child in DIE.iter_children():
			if child.tag == 'DW_TAG_formal_parameter':
				# print("param")
				arg_count += 1
				s = decode_parameter(dwarfinfo, child, CU,func_name, source_info)
				if s:
					if "struct" in s and "*" not in s:
						print("find struct " + s)
					arg_list.append(s)

		
		arg_type_dict[entry] = arg_list
		num_arg[entry] = arg_count
		ret_type_dict[entry] = ret_type
		entry2name[entry] = func_name
	

def decode_func(dwarfinfo,range_lists):
	# Go over all DIEs in the DWARF information, looking for a subprogram
	get_offset2die(dwarfinfo)
	# print("len of offset2die %d"%len(offset2die))
	at_name = dict()
	extern_at_name = dict()
	for CU in dwarfinfo.iter_CUs():
		print('  Found a compile unit at offset %s, length %s' % (
			CU.cu_offset, CU['unit_length']))

		lp_header = dwarfinfo.line_program_for_CU(CU)
		#files = lp_header["file_entry"]
		for DIE in CU.iter_DIEs():
			if DIE.tag == 'DW_TAG_subprogram':
				arg_list = list()
				arg_count = 0
				extern_func_arg_count = 0
				extern_func_arg_list = list()
				arg_count_temp = 0
				entry = 0
				source_file = ''
				line_no = ''
				struct_arg = 0
				struct_arg_extern = 0
				source_info = ''

				# if not check_attr(DIE.attributes,"DW_AT_linkage_name"):
				
				if check_attr(DIE.attributes, "DW_AT_abstract_origin"):
					print("DW_AT_abstract_origin")
					getGroundTruth(lp_header,CU,dwarfinfo,DIE.attributes["DW_AT_abstract_origin"], DIE, range_lists,at_name,extern_at_name)

				elif check_attr(DIE.attributes, "DW_AT_name"):
					print("DW_AT_name")
					getGroundTruth(lp_header,CU,dwarfinfo,DIE.attributes["DW_AT_name"], DIE, range_lists,at_name,extern_at_name)

				elif check_attr(DIE.attributes, "DW_AT_linkage_name"):
					linkage_name = DIE.attributes['DW_AT_linkage_name'].value
					if linkage_name not in at_name:
						getGroundTruth(lp_header,CU,dwarfinfo,DIE.attributes["DW_AT_linkage_name"], DIE, range_lists,at_name,extern_at_name)

			if DIE.tag == "DW_TAG_typedef":
				if check_attr(DIE.attributes, 'DW_AT_name') and check_attr(DIE.attributes, 'DW_AT_type'):
					offset = DIE.attributes['DW_AT_type'].value
					name = DIE.attributes['DW_AT_name'].value

					if (offset + CU.cu_offset) in offset2die:
						die = offset2die[offset + CU.cu_offset]

						if die.tag == "DW_TAG_structure_type":
							if not check_attr(die.attributes, 'DW_AT_name'):
								# print("stuct: " + name)
								struct_list = list()
								for child in die.iter_children():
									if child.tag == "DW_TAG_member":
										# print("member of struct")
										type_s = decode_type(dwarfinfo, child, 'DW_AT_type', CU)
										# print('tyep: '+type_s)
										if type_s:
											struct_list.append(type_s)

								if name not in struct_info:
									struct_info[name] = struct_list
								else:
									if len(struct_info[name]) == 0:
										struct_info[name] = struct_list

			if DIE.tag == "DW_TAG_structure_type":
				if check_attr(DIE.attributes, 'DW_AT_name'):
					struct_list = list()
					name = DIE.attributes['DW_AT_name'].value
					# print("stuct: " + str(name))
					for child in DIE.iter_children():
						if child.tag == "DW_TAG_member":
							# print("member of struct")
							type_s = decode_type(dwarfinfo, child, 'DW_AT_type', CU)
							# print('type: '+str(type_s))
							if type_s:
								struct_list.append(type_s)

					if name not in struct_info:
						struct_info[name] = struct_list
					else:
						if len(struct_info[name]) == 0:
							struct_info[name] = struct_list


def tohex(val, nbits):
	value = hex((val + (1 << nbits)) % (1 << nbits))
	return value

'''
def disassembling(shdr, elfparse):
	disassm = Dissamble(elfparse.elf, shdr)
	i = 0
	# ins_array = dict()
	for key in disassm.dissamble_dict:
		for ins in disassm.dissamble_dict[key]:
			if key != ".plt":
				# self.SearchVtable(ins)
				addr2ins[i] = [ins.address, ins]
				# addr2ins[ins.address] = ins
				i += 1
'''

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
			# print func_start,func_end
			if (func_start > 0 and func_start != func_end):
				# function_info[func_name] = (func_start,func_end)
				function_info[func_start] = func_name
				funcStart2End[func_start] = func_end
	# print(funcName2addr)


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

def insert_ins(addr, end_addr, read_ins_info,assembly):

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
						elif opcode_size == 2:
							inserted_ins_bytes.append(0x0f)
							if 'xmm' not in ins.op_str:
								inserted_ins_bytes.append(0x25)
							else:
								print("find xmm")
								inserted_ins_bytes.append(0x27)
						elif opcode_size == 3:
							inserted_ins_bytes.append(0x0f)
							inserted_ins_bytes.append(0x38)
							if 'xmm' not in ins.op_str:
								inserted_ins_bytes.append(0x51)
							else:
								inserted_ins_bytes.append(0x53)

						for i in range(opcode_index+opcode_size,ins_size):
							inserted_ins_bytes.append(inst_bytes[i])

						#print("new ins bytes",inserted_ins_bytes)

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



def parse_function(shdr, elfparse, start_addr, end_addr,replace_call_flag,insert_ins_flag,read_ins_info,assembly,only_integer_flag,filter_out_flag):
	index = 0
	#print("function",hex(start_addr), hex(end_addr))
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
			if filter_out_flag:
				if ins.id != X86_INS_NOP:
					inst_bytes = list()
					sanitized_s = list()
					s = ''
			else:
				inst_bytes = list()
				sanitized_s = list()
				s = ''
			if ins.id != X86_INS_CALL and not (ins.id >= X86_INS_JA and ins.id <= X86_INS_JS):
				if filter_out_flag:
					if ins.id != X86_INS_NOP:
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
				else:
					s = ins.mnemonic + " " + ins.op_str
					for byte in ins.bytes:
						#print("byte "+str(hex(byte)))
						inst_bytes.append(byte)
						sanitized_s.append(byte)



			#sanitized_s = ins.mnemonic+" "+ins.op_str
			#print(s)

			# for a direct call instruction, transform the target to the name of the function
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

						if insert_ins_flag:
							inserted_ins = insert_ins(start_addr, end_addr,read_ins_info,assembly)
							if len(inserted_ins) != 0:
								for inserted_ins_bytes in inserted_ins:
									entry2inst_bytes[start_addr].append(inserted_ins_bytes)


						s = ins.mnemonic + " " + name
						# sanitized_s = ins.mnemonic+" "+name
						for i in range(len(sanitized_s) - 1, len(sanitized_s) - 4, -1):
							sanitized_s[i] = 0

						if start_addr in function_info:
							caller_name = function_info[start_addr]
							function_call_dict[(caller_name, name)].append(index-1)

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
			if ins.op_count(X86_OP_MEM) > 0:
				if filter_out_flag:
					if find_interested_reg:
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
				else:
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
	#[addr_end, ins] = addr2inst[len(addr2inst) - 1]
	entry2end[start_addr] = end_addr
			#break


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


def get_functionGT(filename):
	with open(filename, "r") as file:
		for line in file:
			dwarf.append(line)
		# print line


def read_dwarfInfo(output):
	output.write("{'function': ")
	for i in range(len(dwarf) - 1):
		'''
		if "DW_TAG_subprogram" in dwarf[i]:
			i = i +1;
			arg_count = 0
			linkage_name = ''
			while "DW_AT_name" not in dwarf[i] and i < len(dwarf) -1:
				if "DW_AT_linkage_name" in dwarf[i]:
					linkage_name_line = dwarf[i].split()
					linkage_name = linkage_name_line[1][2:len(linkage_name_line[1])-2]
					#break
				i += 1

			#print dwarf[i]
			func_name_line = dwarf[i].split()
			func_name = func_name_line[1][2:len(func_name_line[1])-2]
			#entry2name[entry] = func_name
			entry = -1
			if func_name in funcName2addr:
				entry = funcName2addr[func_name]
				entry2name[entry] = func_name
			if linkage_name in funcName2addr:
				entry = funcName2addr[linkage_name]
				entry2name[entry] = linkage_name

			#print "entry %lx"%entry
			output.write("{'" +func_name+"': ")
			if entry:

				while "DW_AT_type" not in dwarf[i] and i < len(dwarf) -1 and dwarf[i]!="\n":
					i += 1
				if i < len(dwarf):
					if dwarf[i] == "\n":
						ret_type = 'void'
					else:
						line = dwarf[i].rstrip()
						ret_type_index = line.find('"')
						ret_type = line[ret_type_index+1:len(line)-2]
					#print ret_type

					ret_type_dict[entry] = ret_type
					arg_list=list()
					while not("DW_TAG_variable" in dwarf[i] or "DW_TAG_subprogram" in dwarf[i] \
							or "NULL" in dwarf[i]):

						i += 1
						if "DW_TAG_formal_parameter" in dwarf[i]:
							arg_count += 1
							i += 1
							while "DW_AT_type" not in dwarf[i] and i < len(dwarf) -1:
								i += 1
							line = dwarf[i].rstrip()
							arg_type_index = line.find('"')
							arg_type = line[arg_type_index+1:len(line)-2]
							arg_list.append(arg_type)
							#print arg_type

					#if arg_count > 0:
					arg_type_dict[entry] = arg_list
					num_arg[entry] = arg_count
		'''
		# for structure dictionary
		if "DW_TAG_structure_type" in dwarf[i]:

			while "DW_AT_name" not in dwarf[i] and i < len(dwarf) - 1:
				i += 1
				if dwarf[i] == "\n":
					break

			if 'DW_AT_name' in dwarf[i]:
				structur_name_line = dwarf[i].split()
				structure_name = structur_name_line[1][2:len(structur_name_line[1]) - 2]
				struct_list = list()
				while "NULL" not in dwarf[i] and i < len(dwarf) - 1:
					i += 1
					if "DW_TAG_member" in dwarf[i]:
						i += 1
						while "DW_AT_type" not in dwarf[i] and i < len(dwarf) - 1:
							i += 1
							line = dwarf[i].rstrip()
							struct_type_index = line.find('"')
							struct_type = line[struct_type_index + 1:len(line) - 2]
							struct_list.append(struct_type)

				struct_info[structure_name] = struct_list

def read_llvm_file(file_name):
	llvm_func_count_info = dict()
	llvm_func_type_info = defaultdict(list)
	llvm_ind_count_info = dict()
	llvm_ind_type_info = defaultdict(list)

	with open(file_name, "r") as f:
		lines = f.readlines()
		for line_count in range(len(lines)):
			line = lines[line_count]
			line_count += 1
			if "Function:" in line:
				type_list = list()
				line = line.rstrip('\n')
				line = line.split()
				if len(line) > 1:
					function_name = line[1]
					source_file = line[len(line) - 1]
					parameter_count = int(line[len(line) - 2])
					llvm_func_count_info[(function_name,source_file)] = parameter_count
					for j in range(len(line) - 2):
						width_str = line[2 + j]
						#llvm_func_type_info[(function_name,source_file)]
						type_list.append(width_str)

					llvm_func_type_info[(function_name,source_file)] = type_list

	return llvm_func_count_info, llvm_func_type_info

def get_read_arg_nums(read_offset_info,addr):
	arg_nums = 16
	for index in range(len(read_offset_info[addr])):
		read_offset_list = read_offset_info[addr][index]
		if not all([v == 0 for v in read_offset_list]) and index < 6:
			arg_nums = index +1
	return arg_nums


def process_bin(bin_path,output_folder,replace_call_flag,insert_ins_flag,only_integer_flag,filter_out_flag,train_flag):
	global value_list, struct_info, ret_type_dict, arg_type_dict, num_arg, entry2name,external_func_arg_types,external_func_arg_nums
	global entry2inst_bytes, entry2inst_strings, entry2end, snaitized_inst_strings, extern_func, uninsert_entry2inst_bytes
	global func_range, addr2ins, function_info, funcStart2End, offset2die, function_call_dict

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
	funcStart2End = dict()
	# plt = dict()
	offset2die = dict()

	ori_bin = os.path.basename(bin_path)

	cmd = "mkdir -p " + output_folder
	os.system(cmd)

	pickle_name = ori_bin + ".pkl"



	if (not os.path.isfile(output_folder + "/" + pickle_name)):
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

		typearmor_path = ori_bin + "_typearmor.txt"

		read_ins_info = defaultdict(list)
		if insert_ins_flag:
			execute_typearmor(bin_path, target_dir)
			if os.path.isfile(typearmor_path):
				read_ins_info = get_read_ins(typearmor_path)


		assembly = disassemble_binary(shdr,elfparse)


		get_function_info(bin_path)
		#get_functionGT(dwarf_info)
		# read_dwarfInfo(output)
		process_file(bin_path)
		#parseAsm(asm_info)


		if insert_ins_flag and len(read_ins_info) == 0:
			os.chdir("../../")
			return


		for i in funcStart2End:
			parse_function(shdr, elfparse, i, funcStart2End[i],replace_call_flag,insert_ins_flag,read_ins_info,assembly,only_integer_flag,filter_out_flag)

		for i in function_info:
			func_name = function_info[i]
			index = func_name.find(".constprop")
			if index != -1:
				func_name = func_name[:index]

			if i in ret_type_dict and i in arg_type_dict and i in entry2inst_bytes and i in entry2inst_strings \
					and i in entry2end and i in num_arg:

				
				if  func_name:
					function_dict[func_name] = {'ret_type': ret_type_dict[i], 'args_type': arg_type_dict[i],
												'inst_bytes': entry2inst_bytes[i],
												'boundaries': (i, entry2end[i]), 'num_args': num_arg[i],
												'inst_strings': entry2inst_strings[i]}

		# print function_dict

		# for i in struct_info:
		# structure_dict['structures'].append()
		# print struct_info
		arch = 'amd64'
		# info = {'functions':function_dict,'binary_filename':ori_bin,'structures':struct_info,'arch':arch,
		# 'text_addr':str(hex(text_addr))}

		caller_info = list()
		# print function_call_dict
		
		function_call = dict()
		for (caller,callee) in function_call_dict:

			caller_index = function_call_dict[(caller,callee)]
			caller_dict = {'caller':caller,'caller_indices':caller_index}
			
			function_call.setdefault(callee, []).append(caller_dict)


		exter_func_name2addr = dict()
		for i in extern_func:
			name = extern_func[i]
			exter_func_name2addr[unicode(name)] = i

		# bin_raw_bytes['bin_raw_bytes'] = bytearray(bin_raw)

		info = {'functions': function_dict, 'binary_filename': ori_bin, 'structures': struct_info, 'arch': arch,
				'text_addr': str(hex(text_addr)), 'function_calls': function_call, 'extern_functions': exter_func_name2addr,
				'bin_raw_bytes': str(bin_raw)}

		# print info

		info_binfunc[ori_bin] = info

		pickle.dump(info, open(os.path.join(output_folder,pickle_name), "w"))


		os.chdir("../../")


def safe_run(*args, **kwargs):
	"""Call run(), catch exceptions."""
	try: process_bin(*args, **kwargs)
	except Exception as e:
		print("error: %s run(*%r, **%r)" % (e, args, kwargs))


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

	args = parser.parse_args()

	config_info = {
		'binary_folder': args.binary_folder,
		'output_dir': args.output_dir,
		'replace_call': args.replace_call,
		'insert_ins': args.insert_ins,
		'only_integer':args.only_integer,
		'filter_out': args.filter_out
	}

	return config_info


def execute_typearmor(bin_path,target_dir):
	cwd = os.getcwd()
	home = expanduser("~")
	type_armor_path = home+"/typearmor-master-insert-ins/server-bins"
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

	if os.path.isfile("../out/" + "binfo." + orig_bin):
		cmd = "mv " + "../out/" + "binfo." + orig_bin + " " + cwd + "/" + typearmor_path
		os.system(cmd)

	os.chdir(cwd)


def get_read_ins(typearmor_file):
	#func_name_pattern = re.compile("[0-9a-fA-F]{1,16}\s=\s[0-9]{1,2}\s(\S*):")
	read_inst_info = defaultdict(list)
	read_inst_count = dict()

	with open(typearmor_file, "r") as f:
		lines = f.readlines()
		if len(lines) == 0:
			return read_inst_info
		line_count = 0
		line = lines[line_count]

		while "[args]" not in line:
			line_count += 1
			line = lines[line_count]

		if "[args]" in line:
			line_count += 1
			next_line = lines[line_count]
			while ("[icall-args]" not in next_line):
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
						while next_processed_line < line_count + 14:
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
						next_line = lines[line_count]
				else:
					line_count += 1
					next_line = lines[line_count]


	return read_inst_info





if __name__ == '__main__':

	#bin_directory = sys.argv[1]
	config_info = get_config()
	bin_directory = config_info['binary_folder']
	output_folder = config_info['output_dir']
	replace_call_flag = int(config_info["replace_call"])
	insert_ins_flag = int(config_info["insert_ins"])
	only_integer_flag = int(config_info["only_integer"])
	fliter_out_flag = int(config_info["filter_out"])

	os.system('mkdir -p '+output_folder)
	for filename in os.listdir(bin_directory):
		bin_path = os.path.join(bin_directory,filename)
		#files.append(bin_path)
		train_flag = 1
		#print(filename)
		#if not os.path.isfile(output_folder+"/"+filename+".pkl"): 
		process_bin(bin_path, output_folder, replace_call_flag, insert_ins_flag, only_integer_flag, fliter_out_flag,
					train_flag)





