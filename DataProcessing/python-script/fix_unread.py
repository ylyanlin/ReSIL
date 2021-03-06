"""
Correct the label for callees which do not use some of the arguments.
e.g., A(int a, int b, __attribute__(unused) int c), the label for callee A 
would be 2 arguments rather than 3.
"""



import re
import os
import sys
import commands
#import openpyxl
import subprocess
import re
import pickle

from collections import defaultdict
from capstone import *
from capstone.x86 import *
from ctypes import *
from typedef import *
from elf import *
from dissamble import *
from collections import Counter


target_dir = "../typearmor_out"


typearmor_info = dict()  #info for each function, address of the function as the key, value is the number of arguments
typearmor_ind_info = dict() #address of indirect call as the key, value is the number of argument for the indirect call


ParaWidthOB = defaultdict(list)

ArgWidthOB = defaultdict(list)


ParaWidthGT = defaultdict(list)

ArgWidthGT = defaultdict(list)

icall_in_wrapper_taken = list()
icall_in_wrapper_dcall = list()

icall_argPointer = defaultdict(list) #indirect call whose argument is pointer to .data section
icall_argImm = defaultdict(list) #indirect call whose argument is immediate value

icall_xor = defaultdict(list)

icall_R13 = defaultdict(list) #indirect call whose argument read 16-bit to 32-bit register
icall_R36 = defaultdict(list) #indirect call whose argument read 32-bit to 64-bit register


unread  = list()
wrapper = list()
temp = list()
Imm = list()
Xor = list()
Pointer = list()
wrapper_over = list()

Imm_under = list()
Xor_under = list()
Pointer_under = list()
unread_unfixed = list()



def read_llvm_file(file_name, func_name):
	print("reading ", file_name)
	llvm_ind_count_info = dict()
	llvm_ind_type_info = defaultdict(list)
	#icall_line2count = dict()
	#icall_line2type = defaultdict(list)
	type_list = list()

	if os.path.isfile(file_name):
		with open(file_name,"r") as f:
			lines = f.readlines()
			#print(lines)
			for line_count in range(len(lines)):
				line = lines[line_count]
				line_count +=1
				if "Function:" in line:
					line = line.rstrip('\n')
					line = line.split()
					if len(line) > 1:
						function_name = line[1]

						if func_name == function_name and "clang" in function_name:
						
							source_file = line[len(line)-1]

							arg_count = int(line[len(line)-2])

							for j in range(2,arg_count+1):
								width_str = line[j]
								type_list.append(width_str)
							return type_list
	return type_list

#parse info generated by typearmor
def read_typearmor_file(file_name):
	print("reading " + file_name)
	with open(file_name,"r") as f:
		lines = f.readlines() 
		line_count = 0
		#for line_count in range(len(lines)):
		

		if len(lines) > 0:
			line = lines[line_count]

			while ("[varargs]" not in line) and line_count < len(lines)-1:
				line_count += 1
				if line_count < len(lines):
					line = lines[line_count]
				else:
					break
			
			if "[varargs]" in lines[line_count] and line_count < len(lines):
				line_count += 1
				next_line = lines[line_count]

				while ("[args]" not in next_line):
					splitted_next_line = next_line.split()
					if len(splitted_next_line) > 3:
						function_addr = splitted_next_line[0]
						function_name = splitted_next_line[3]
						parameter_number = splitted_next_line[2]

						#typearmor_info[int(function_addr,16)] = int(parameter_number)

					line_count += 1
					next_line = lines[line_count]

			if "[args]" in lines[line_count]:
				#line_count += 1
				next_line = lines[line_count]
				while ("[icall-args]" not in next_line):
					splitted_next_line = next_line.split()
					#print next_line
					if len(splitted_next_line) > 3:
						function_addr = int(splitted_next_line[0],16)
						#function_name = splitted_next_line[3]
						parameter_number = int(splitted_next_line[2])

						function_name_start_index = next_line.find('(')
						function_name_end_index = next_line.rfind(')')

						width_info = list()

						if function_name_end_index != -1:

							width_info = next_line[function_name_end_index+1:].split()

						#if len(width_info) >= parameter_number:
						for i in range(parameter_number):
							if i < len(width_info):
								parameterWidth = int(width_info[i])
								ParaWidthOB[function_addr].append(parameterWidth)


						if function_addr not in typearmor_info:
							typearmor_info[function_addr]=parameter_number

					line_count += 1
					if line_count < len(lines):
						next_line = lines[line_count]
					else:
						line_count = line_count - 1
						break
						
			if "[icall-args]" in lines[line_count]:
				#line_count += 1
				next_line = lines[line_count]
				while ("[plts]" not in next_line ):
					splitted_next_line = next_line.split()
					if len(splitted_next_line) > 3:
						indirect_addr = int(splitted_next_line[0],16)
						function_name = splitted_next_line[3][::-1]
						argument_number = int(splitted_next_line[2])


						function_name_start_index = next_line.find('(')
						function_name_end_index = next_line.rfind(')')


						width_info = list()

						if function_name_end_index != -1:

							width_info = next_line[function_name_end_index+1:].split()


						typearmor_ind_info[indirect_addr] = argument_number

						for i in range(argument_number):
							if len(width_info) >= argument_number:
								if width_info[i].isdigit():
									argumentWidth = int(width_info[i])
									ArgWidthOB[indirect_addr].append(argumentWidth)

						if len(width_info) > (argument_number):
							for i in range(argument_number,len(width_info)):
								if "Icall" in width_info[i]:
									icall_in_wrapper_taken.append(indirect_addr)
								if "Dcall" in width_info[i]:
									icall_in_wrapper_dcall.append(indirect_addr)
								#if "bet" in width_info[i]:
									#icall_bet.append(indirect_addr)
								
								if "ImmArg" in width_info[i]:
									immargs= width_info[i].split('{')
									immarg = immargs[1]
									immarg_index = immarg.split(',')
									for j in range(len(immarg_index)-1):
										index = int(immarg_index[j])
										if index not in icall_argImm[indirect_addr]:
											icall_argImm[indirect_addr].append(index)
								
								if "PointerArg" in width_info[i]:
									pointerargs= width_info[i].split('{')
									pointerarg = pointerargs[1]
									pointerarg_index = pointerarg.split(',')
									for j in range(len(pointerarg_index)-1):
										index = int(pointerarg_index[j])
										if index not in icall_argPointer[indirect_addr]:
											icall_argPointer[indirect_addr].append(index)
								
								if "13Arg" in width_info[i]:
									args13= width_info[i].split('{')
									arg13 = args13[1]
									arg13_index = arg13.split(',')
									for j in range(len(arg13_index)-1):
										index = int(arg13_index[j])
										if index not in icall_R13[indirect_addr]:
											icall_R13[indirect_addr].append(index)
								
								if "36Arg" in width_info[i]:
									args36= width_info[i].split('{')
									arg36 = args36[1]
									arg36_index = arg36.split(',')
									for j in range(len(arg36_index)-1):
										index = int(arg36_index[j])
										if index not in icall_R36[indirect_addr]:
											icall_R36[indirect_addr].append(index)

								if "Xor" in width_info[i]:
									argsxor= width_info[i].split('{')
									argxor = argsxor[1]
									argxor_index = argxor.split(',')
									for j in range(len(argxor_index)-1):
										index = int(argxor_index[j])
										if index not in icall_xor[indirect_addr]:
											icall_xor[indirect_addr].append(index)

					line_count += 1
					if line_count < len(lines):
						next_line = lines[line_count]
					else:
						line_count = line_count - 1
						break

def all_the_same(elements):
	if len(elements) < 1:
		return True
	return len(elements) == elements.count(elements[0])



def fix_unread(widthOB, widthGT, typeString):
	size = len(widthOB)
	sublist = list()

	if all_the_same(widthGT):
		if size == 0:
			return True
		for i in range(size):
			width = widthGT[i]
			sublist.append(width)
			return True
	else:
		if len(widthOB) == 0:
			print("zero")
			return True
		for i in range(size):
			OB = widthOB[i]
			GT = widthGT[i]

			if OB != GT:
				return False
		return True
		'''
		counterGT = Counter(widthGT)
		counterOB = Counter(widthOB)
		for key in counterOB:
			value = counterOB[key]
			if key in counterGT:
				valueGT = counterGT[key]
				if value <= valueGT:

			else:
		'''

		'''
		for i in range(size):
			OB = widthOB[i]
			GT = widthGT[i]
		'''

	#for i in range(size):
		#width = widthGT[i]
		#sublist.append(width)






def read_pickle(file_name,binary_folder,filename):

	pickle_file = os.path.basename(file_name)
	index = pickle_file.find(".pkl")
	binary = pickle_file[:index]
	print(binary)

	type_armor_path = "../static-analysis/typearmor-master/server-bins"
	os.chdir(type_armor_path)

	os.environ["DYNINST_ROOT"] = os.path.expanduser('~') + '/dyninst-9.3.1'
	os.environ["DYNINST_LIB"] = os.environ["DYNINST_ROOT"] + '/install/pwd/lib'
	os.environ["DYNINSTAPI_RT_LIB"] = os.environ["DYNINST_LIB"] + "/libdyninstAPI_RT.so"
	os.environ["LD_LIBRARY_PATH"] = os.getcwd()
	os.environ["LD_LIBRARY_PATH"] += os.environ["DYNINST_LIB"]

	

	typearmor_path = binary + "-typearmor.txt"

	bin_path = binary_folder+"/"+binary

	cmd = "cp " + bin_path + " " + binary
	os.system(cmd)

	#if "binfo."+binary
	cmd = "bash ../run-ta-static.sh " + binary
	os.system(cmd)


	cmd = "mv " +"../out/" + "binfo."+binary +" " +target_dir + "/"  + typearmor_path
	os.system(cmd)


	#os.chdir(target_dir + "/" + binary)

	read_typearmor_file(target_dir + "/"  + typearmor_path)
	fixed = 0

	if not os.path.isfile(fixed_pickle_directory+"/"+pickle_file):

		with open(file_name,'r') as f:
			data = pickle.load(f)
			#read_typearmor_file(binary)

			function_dict = data['functions']
			new_function_dict = dict()
			#new_function_dict = function_dict
			for name in function_dict:
				#print(name)
				new_function_dict[name] = function_dict[name]
				func_name = binary + "#" + name
				num_args = function_dict[name]['num_args']
				args_types = function_dict[name]['args_type']
				(startAddr, endAddr) = function_dict[name]['boundaries']
				int_count = 0
				float_count = 0
				int_type = list()
				para_widthGT = list()
				for type_str in args_types:
					if type_str in ['float','double','long double' ]:
						float_count += 1
					else:
						paraType = approximate_type_string(type_str)
						int_type.append(paraType)

						widthGT = approximate_type(type_str)
						para_widthGT.append(widthGT)

				int_count = num_args - float_count

				if startAddr in typearmor_info:
					num_argsOB = typearmor_info[startAddr]
					para_widthOB = ParaWidthOB[startAddr]
					if name == "_bfd_real_fopen":
						print(para_widthOB)
					#print(num_args, int_count)
					if num_argsOB < int_count:
						#print(num_argsOB, int_count)
						if num_argsOB < 6:
							#print("find")
							#for i in range(len(num_argsOB)):
							unread.append((func_name,int_type))
							if fix_unread(para_widthOB,para_widthGT, int_type):
								#unread(())
								#unread.append((func_name+"-fixed",int_type))
								num_args = num_argsOB
								args_typeList = list()
								for i in range(num_argsOB):
									args_typeList.append(int_type[i])
								fixed = 1

								new_function_dict[name] = {'ret_type': function_dict[name]['ret_type'], 'args_type': args_typeList,
								'inst_bytes': function_dict[name]['inst_bytes'],
								'boundaries': function_dict[name]['boundaries'], 'num_args': num_args,
								'inst_strings': function_dict[name]['inst_strings']}

							else:
								fixed = 0
								#fix using clang info
								type_list = read_llvm_file(filename, func_name)
								if len(type_list) != 0:
									print("fix using clang")
									new_function_dict[name] = {'ret_type': function_dict[name]['ret_type'], 'args_type': type_list,
									'inst_bytes': function_dict[name]['inst_bytes'],
									'boundaries': function_dict[name]['boundaries'], 'num_args': num_args,
									'inst_strings': function_dict[name]['inst_strings']}
								else:
									#new_function_dict[func_name] = function_dict[func_name]
									unread_unfixed.append((func_name,int_type,para_widthOB))
									#unread.append((func_name,int_type))
						else:
							new_function_dict[name] = {'ret_type': function_dict[name]['ret_type'], 'args_type': function_dict[name]['args_type'],
								'inst_bytes': function_dict[name]['inst_bytes'],
								'boundaries': function_dict[name]['boundaries'], 'num_args': num_args,
								'inst_strings': function_dict[name]['inst_strings']}
					else:
						new_function_dict[name] = {'ret_type': function_dict[name]['ret_type'], 'args_type': function_dict[name]['args_type'],
								'inst_bytes': function_dict[name]['inst_bytes'],
								'boundaries': function_dict[name]['boundaries'], 'num_args': num_args,
								'inst_strings': function_dict[name]['inst_strings']}
			#if fixed:
			new_info={'functions':new_function_dict,'binary_filename':data['binary_filename'],'structures':data['structures'],'arch':data['arch'],
				'text_addr':data['text_addr'],'function_calls':data['function_calls'],'extern_functions':data['extern_functions'],
				'bin_raw_bytes':data['bin_raw_bytes']}

			with open(fixed_pickle_directory+"/"+pickle_file,"wb") as f:
					pickle.dump(new_info, f)

def disassembling(shdr,elfparse,start_addr,end_addr):
	disassm = Dissamble(elfparse.elf,shdr,start_addr,end_addr)
	#disassm.Output()
	i = 0
	addr2ins = dict()
	#ins_array = dict()

	for ins in disassm.dissambled_ins:
		addr2ins[ins.address] = ins
	'''
	for key in disassm.dissamble_dict:
		for ins in disassm.dissamble_dict[key]:
			addr2ins[ins.address] = ins
			#if key != ".plt":
				#self.SearchVtable(ins)
				#addr2ins[i]=[ins.address,ins]
				#i += 1
	'''

	return addr2ins


def get_icall_addr(shdr,elfparse,start_addr,end_addr,icall_index):
	index = 0
	
	'''
	for addr in sorted(addr2ins):
		if addr < end_addr and addr >= start_addr:
			ins = addr2ins[addr]
			if ins.id == X86_INS_CALL and icall_index == index:
				return addr
	'''

	addr2ins = disassembling(shdr,elfparse,start_addr,end_addr)
	x = start_addr
	#print("get icall address")
	while x <= end_addr and x >=start_addr and x in addr2ins:
		ins = addr2ins[x]
		index += 1
		if ins.id == X86_INS_CALL and icall_index == index:
			return (x,ins)
		ins_size = ins.size
		x = x+ins_size

	return (0,ins)

def read_icall_pickle(file_name,shdr,elfparse):
	addr2indice = dict()
	icall_dict = dict()
	with open(file_name,'r') as f:
		data = pickle.load(f)
		icall_info = data['icall']
		function_dict = data['functions']
		for (func_name, indice) in icall_info:
			(start_addr,end_addr) = function_dict[func_name]['boundaries']
			args_types = icall_info[(func_name, indice)]['args_type']
			args_num = icall_info[(func_name, indice)]['num_args']

			icall_addr, ins = get_icall_addr(shdr,elfparse,start_addr,end_addr,indice)

			addr2indice[icall_addr] = (func_name, indice)
			icall_dict[icall_addr] = (args_num, args_types)

	return addr2indice, icall_dict


def collect_insert_uninsert(file_uninsert, file_insert):
	caller_uninsert = defaultdict(list)
	caller_insert = defaultdict(list)

	with open(file_uninsert,'r') as f:
		data = pickle.load(f)
		icall_info = data['icall']
		for (func_name, indice) in icall_info:
			caller_uninsert[func_name].append(indice)

	with open(file_insert,'r') as f:
		data = pickle.load(f)
		icall_info = data['icall']
		for (func_name, indice) in icall_info:
			caller_insert[func_name].append(indice)

	uninsert2insert = dict()
	#return caller_uninsert, caller_insert
	for name in caller_uninsert:
		caller_uninsert[name].sort()
		if name in caller_insert:
			caller_insert[name].sort()

	for name in caller_uninsert:
		indices = caller_uninsert[name]
		if name in caller_insert:
			indices_insert = caller_insert[name]
			for i in range(len(indices_insert)):
						uninsert2insert[(name,indices[i])] = (name,indices_insert[i])
	return uninsert2insert


def approximate_type_string(type_str):
	int_list = ['_Bool', 'unsigned int', 'int', 'long long int', 'long long unsigned int', 'unsigned short',
				'short unsigned int', 'short', 'long unsigned int', 'short int', 'long int']
	char_list = ['char', 'unsigned char', 'signed char']
	if type_str[-1] == '*' or type_str == 'func_ptr' or type_str.split()[0][-1] == '*':
		return 'pointer'
	elif type_str in int_list:
		return 'int'
	elif type_str[:5] == 'enum ':
		return 'enum'
	elif type_str in char_list:
		return 'char'
	elif type_str[:7] == 'struct ':
		return 'struct'
	elif type_str[:6] == 'union ':
		return 'union'
	elif type_str == 'double' or type_str == 'long double':
		return 'float'
	else:
		return type_str

def approximate_type(type_str):
	int8_list = ['_Bool','bool','char','unsigned char','signed char']

	int16_list =['short','unsigned short','short unsigned int']

	int32_list = ['int','signed int','unsigned int']

	int64_list = ['long int','long unsigned int','long long int','long long unsigned int','long']

	if type_str[-1] == "*" or type_str == 'func_ptr' or type_str.split()[0][-1] == '*':
		return 8

	elif type_str in int8_list:
		return 1

	elif type_str in int16_list:
		return 2

	elif type_str in int32_list:
		return 4

	elif type_str in int64_list:
		return 8
	else:
		return type_str


if __name__ == '__main__':

	#uninsert_pickle_folder = sys.argv[1]
	#insert_pickle_folder = sys.argv[2]

	binary_folder = sys.argv[1]

	fileName = sys.argv[2]

	fixed_pickle_directory = sys.argv[3]

	llvm_folder = sys.argv[4]

	cmd = 'mkdir -p ' + fixed_pickle_directory
	os.system(cmd)

	cmd = "mkdir -p " + target_dir
	os.system(cmd)

	addr2Name = dict()
	#for fileName in os.listdir(function_pickle_folder):	
	if 'inetutils-ftp' not in fileName and 'inetutils-tftp' not in fileName:
		typearmor_info = dict()  #info for each function, address of the function as the key, value is the number of arguments
		typearmor_ind_info = dict() #address of indirect call as the key, value is the number of argument for the indirect call


		ParaWidthOB = defaultdict(list)

		ArgWidthOB = defaultdict(list)


		ParaWidthGT = defaultdict(list)

		ArgWidthGT = defaultdict(list)

		icall_in_wrapper_taken = list()
		icall_in_wrapper_dcall = list()

		icall_argPointer = defaultdict(list) #indirect call whose argument is pointer to .data section
		icall_argImm = defaultdict(list) #indirect call whose argument is immediate value

		icall_xor = defaultdict(list)

		icall_R13 = defaultdict(list) #indirect call whose argument read 16-bit to 32-bit register
		icall_R36 = defaultdict(list) #indirect call whose argument read 32-bit to 64-bit register

		llvm_name = fileName[:fileName.find(".pkl")] + "-llvm-info.txt"

		read_pickle(fileName, binary_folder, llvm_folder+"/"+ llvm_name)



		'''
		if fileName in os.listdir(insert_pickle_folder):

			index = fileName.find('.pkl')
			binary=fileName[:index]

			try:
				fd_bin = open(binary_folder+"/"+binary, "rb")
			except IOError as err:
				print("IOError:" + str(err))
				exit(1)

			bin_raw = fd_bin.read()
			fd_bin.close()

			elfparse = Elf64_Parse(bin_raw)
			shdr = elfparse.GetShdr()

			uninsert2insert = collect_insert_uninsert(uninsert_pickle_folder+"/"+fileName, insert_pickle_folder+"/"+fileName)
			addr2indice, icall_dict = read_icall_pickle(uninsert_pickle_folder+"/"+fileName, shdr, elfparse)

			for icall_addr in addr2indice:
				if icall_addr in icall_dict:
					(args_num, args_types) = icall_dict[icall_addr]
					(func_name, indice) = addr2indice[icall_addr]
					int_args = list()

					for type_str in args_types:
						if type_str not in ['float','double','long double']: 
							#print(type_str)
							int_args.append(type_str)

					if (func_name, indice) in uninsert2insert:
						(name, insert_indice) = uninsert2insert[func_name, indice]
						inputName = fileName+"#"+name+"#"+str(insert_indice)

						addr2Name[icall_addr] = inputName

						if icall_addr in icall_in_wrapper_taken:
							wrapper.append((inputName,icall_addr))

						if icall_addr in icall_in_wrapper_dcall:
							wrapper.append((inputName,icall_addr))

						if icall_addr in icall_argPointer:
							
							#print(int_args)
							for index in icall_argPointer[icall_addr]:
								if index  < args_num:
									#print(index)
									Pointer.append((inputName,icall_addr,index))
									arg_typeGT = int_args[index-1]
									arg_widthGT = approximate_type(arg_typeGT)
									arg_widthOB = ArgWidthOB[icall_addr][index-1]

									if arg_widthOB < ArgWidthGT:
										Pointer_under.append((inputName,icall_addr,index)) 


						if icall_addr in icall_argImm:
							
							#print(int_args, hex(icall_addr),inputName)
							for index in icall_argImm[icall_addr]:
								#print(index)
								if index  < args_num:
									Imm.append((inputName,icall_addr,index))
									arg_typeGT = int_args[index-1]
									arg_widthGT = approximate_type(arg_typeGT)
									arg_widthOB = ArgWidthOB[icall_addr][index-1]

									if arg_widthOB < ArgWidthGT:
										Imm_under.append((inputName,icall_addr,index)) 

						if icall_addr in icall_xor:
							
							for index in icall_xor[icall_addr]:
								if index  < args_num:
									Xor.append((inputName,icall_addr,index))
									arg_typeGT = int_args[index-1]
									arg_widthGT = approximate_type(arg_typeGT)
									arg_widthOB = ArgWidthOB[icall_addr][index-1]

									if arg_widthOB < ArgWidthGT:
										Xor_under.append((inputName,icall_addr,index)) 


						if icall_addr in typearmor_ind_info:
							args_numOB = typearmor_ind_info[icall_addr]

							if args_numOB > args_num:
								if icall_addr not in wrapper:
									temp.append((inputName,icall_addr))
								else:
									wrapper_over.append((inputName,icall_addr))
		'''
	outFile = "unread-big-data.txt"
	unfixedFile = "unread-unfixed-big-data.txt"
	unfixed_out = open(unfixedFile,'a+')

	out = open(outFile,'a+')

	#unfixed_out.write("unread unfixed ")

	for (i,j,k) in unread_unfixed:
		unfixed_out.write(i+" ")
		unfixed_out.write('[')
		for item in j:
			unfixed_out.write(item + ' ')
		unfixed_out.write(']\n')

		unfixed_out.write('[')
		for item in k:
			
			unfixed_out.write(str(item) + ' ')
		unfixed_out.write(']\n')

	if len(unread) > 0:
		#out.write("unread\n")
		for (i,j) in unread:
			out.write(i+" ")
			for item in j:
				out.write(str(item)+" ")
			out.write("\n")

	if len(wrapper) >0:
		out.write("wrapper\n")
		for (i,addr) in wrapper:
			out.write(i + " " +str(hex(addr))+'\n')

	if len(Imm) > 0:
		out.write("imm\n")
		for (i,addr,ind) in Imm:
			out.write(i + " " +str(hex(addr))+" " +str(ind) + '\n')

	if len(Pointer) > 0:
		out.write("pointer\n")
		for (i,addr,ind) in Pointer:
			out.write(i + " " +str(hex(addr))+" " +str(ind)+ '\n')

	if len(Xor) > 0:
		out.write("xor\n")
		for (i,addr,ind) in Xor:
			out.write(i + " " +str(hex(addr)) +" " +str(ind)+ '\n')

	if len(temp) > 0:
		out.write("temp\n")
		for (i,addr) in temp:
			out.write(i + " " +str(hex(addr)) + '\n')

	if len(Pointer_under) > 0:
		out.write("pointer_under\n")
		for (i,addr,ind) in Pointer_under:
			out.write(i + " " +str(hex(addr))+" " +str(ind) + '\n')


	if len(Imm_under) > 0:
		out.write("imm_under\n")
		for (i,addr,ind) in Imm_under:
			out.write(i + " " +str(hex(addr))+" " +str(ind) + '\n')

	if len(Xor_under) > 0:
		out.write("xor_under\n")
		for (i,addr,ind) in Xor_under:
			out.write(i + " " +str(hex(addr))+" " +str(ind) + '\n')

	out.close()



