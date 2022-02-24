import pickle
import os
import numpy as np
import random
from multiprocessing import Pool
from collections import defaultdict

embed_info = {}
extract_vector = {}
extract_vector_test = {}
extract_pickle = {}
extracted_pickle = {}
extract_icall = {}
package2whole = defaultdict(list)
type_info = {
	#'char': 0,
	'int8':0,
	'int16':1,
	'int32':2,
	'int64':3,
	#'pointer':4
	'float': 4,
	'pointer': 5,
	'enum': 6,
	'struct': 7,
	'union': 8
}


def approximate_type(type_str):
	int8_list = ['_Bool', 'bool', 'char', 'unsigned char', 'signed char']
	int16_list = ['short', 'unsigned short','short unsigned int', 'short int']
	int32_list = ['int','signed int', 'unsigned int']
	int64_list = ['long int','long unsigned int', 'long long int', 'long long unsigned int','long']
	#int_list = ['_Bool', 'unsigned int', 'int', 'long long int', 'long long unsigned int', 'unsigned short',
				#'short unsigned int', 'short', 'long unsigned int', 'short int', 'long int']
	#char_list = ['char', 'unsigned char', 'signed char']
	if type_str[-1] == '*' or type_str == 'pointer'or type_str == 'func_ptr' or type_str.split()[0][-1] == '*':
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
	#elif type_str in char_list:
		#return 'char'
	elif type_str[:7] == 'struct ':
		return 'struct'
	elif type_str[:6] == 'union ':
		return 'union'
	elif type_str == 'double' or type_str == 'long double' or type_str == 'float':
		return 'float'
	else:
		return type_str


def one_hot_encoding(label_id, class_num):
	temp = np.zeros(class_num)
	temp[label_id] = 1
	return temp


def load_all_pickles(folder_path):
	extracted_pickle = {}
	for file_name in os.listdir(folder_path):
		file_path = os.path.join(folder_path, file_name)
		#print(file_name)

		with open(file_path,'rb') as f:
			data = pickle.load(f,encoding='latin1')
			#function_info = file_info
			#extracted_pickle[file_name] = function_info
			function_info = data['functions']
			extracted_pickle[file_name] = function_info

	print("loaded all pickle file")

	return extracted_pickle


def get_dcall_vector(folder_path, func_list, embed_dim, max_length, class_num, embed_info):
	extract_info = {}

	

	for whole_func_name in func_list:
		'''callee_name#caller_name#indice'''
		'''ours filename#callee_name#caller_name#indice'''
		'''
		temp = whole_func_name.split('#')
		file_name =  temp[0]
		callee_name = temp[1]
		indice = int(temp[2])
		func_tag = whole_func_name'''
		temp = whole_func_name.split('#')
		file_name = temp[0]
		callee_name = temp[1]
		caller_name = temp[2]
		indice = int(temp[3])

		func_tag = whole_func_name
		extract_info[func_tag] = {}

		function_info = extracted_pickle[file_name]

		temp_data = []
		indice_list = list()
		if indice != 0:
			indice_list = sorted(range(indice), reverse=True)
		else:
			indice_list.append(indice)
		if callee_name in function_info and caller_name in function_info:
			#print(whole_func_name,indice_list)
			if indice_list[0] < len(function_info[caller_name]['inst_bytes']):
				for indice_id in indice_list:
					#print(indice_id, len(file_info['functions'][callee_name]['inst_bytes']))
						inst = function_info[caller_name]['inst_bytes'][indice_id]
						if str(inst) in embed_info:
							temp_data.append(embed_info[str(inst)]['vector'])
						else:
							temp_data.append([0.0] * embed_dim)
						if len(temp_data) >= max_length:
							break

				temp_data = np.asarray(temp_data)

				if temp_data.shape[0] < max_length:
					extract_info[func_tag]['length'] = temp_data.shape[0]
					temp_zero = np.zeros((max_length - temp_data.shape[0], embed_dim))
					temp_data = np.concatenate((temp_data, temp_zero), axis=0)
				else:
					extract_info[func_tag]['length'] = temp_data.shape[0]

				extract_info[func_tag]['data'] = temp_data

				extract_info[func_tag]['label'] = one_hot_encoding(function_info[callee_name]['num_args'],
																   class_num)

	return extract_info
def get_vector(folder_path, func_list, embed_dim, max_length, class_num, embed_info):
	extract_info = {}

	extracted_pickle = {}
	for file_name in os.listdir(folder_path):
		file_path = os.path.join(folder_path, file_name)
		print(file_name)

		with open(file_path,'rb') as f:
			data = pickle.load(f,encoding="latin1")
			#function_info = file_info
			#extracted_pickle[file_name] = function_info
			function_info = data
			extracted_pickle[file_name] = function_info

	print("loaded all pickle file")

	for whole_func_name in func_list:
		'''callee_name#caller_name#indice'''
		'''ours filename#caller_name#indice#addr'''
		'''
		temp = whole_func_name.split('#')
		file_name =  temp[0]
		callee_name = temp[1]
		indice = int(temp[2])
		func_tag = whole_func_name'''
		temp = whole_func_name.split('#')
		file_name = temp[0]
		#callee_name = temp[1]
		caller_name = temp[1]
		indice = int(temp[2])
		addr = int(temp[3],16)
		func_tag = whole_func_name
		extract_info[func_tag] = {}

		function_info = extracted_pickle[file_name]

		#print(function_info)
		temp_data = []
		indice_list = sorted(range(indice), reverse=True)
		if caller_name in function_info['functions']:
			#print(whole_func_name)
			if indice_list[0] < len(function_info['functions'][caller_name]['inst_bytes']):
				for indice_id in indice_list:
					#print(indice_id, len(file_info['functions'][callee_name]['inst_bytes']))
						inst = function_info['functions'][caller_name]['inst_bytes'][indice_id]
						#print(inst)
						if str(inst) in embed_info:
							temp_data.append(embed_info[str(inst)]['vector'])
						else:
							temp_data.append([0.0] * embed_dim)
						if len(temp_data) >= max_length:
							break

				temp_data = np.asarray(temp_data)

				if temp_data.shape[0] < max_length:
					extract_info[func_tag]['length'] = temp_data.shape[0]
					temp_zero = np.zeros((max_length - temp_data.shape[0], embed_dim))
					temp_data = np.concatenate((temp_data, temp_zero), axis=0)
				else:
					extract_info[func_tag]['length'] = temp_data.shape[0]

				extract_info[func_tag]['data'] = temp_data

				extract_info[func_tag]['label'] = one_hot_encoding(function_info['icall'][(caller_name, indice, addr)]['num_args'],
																   class_num)

	return extract_info

def get_vector_type(folder_path, func_list, embed_dim, max_length, class_num, embed_info, arg_no):
	#extract_info = {}
	'''

	extracted_pickle = {}
	for file_name in os.listdir(folder_path):
		file_path = os.path.join(folder_path, file_name)
		print(file_name)

		with open(file_path) as f:
			file_info = pickle.load(f)
			function_info = file_info
			extracted_pickle[file_name] = function_info
	'''
	extract_info = {}

	extracted_pickle = {}
	for file_name in os.listdir(folder_path):
		file_path = os.path.join(folder_path, file_name)
		print(file_name)

		with open(file_path,'rb') as f:
			data = pickle.load(f,encoding="latin1")
			#function_info = file_info
			#extracted_pickle[file_name] = function_info
			function_info = data
			extracted_pickle[file_name] = function_info

	print("loaded all pickle file")

	for whole_func_name in func_list:
		'''callee_name#caller_name#indice'''
		'''ours filename#caller_name#indice#addr'''
		'''
		temp = whole_func_name.split('#')
		file_name = temp[0]
		callee_name = temp[1]
		indice = int(temp[2])
		func_tag = whole_func_name'''

		temp = whole_func_name.split('#')
		file_name = temp[0]
		#callee_name = temp[1]
		caller_name = temp[1]
		indice = int(temp[2])
		addr = int(temp[3],16)
		func_tag = whole_func_name
		extract_info[func_tag] = {}

		function_info = extracted_pickle[file_name]
		#icall_info = extract_icall[file_name]

		temp_data = []
		indice_list = sorted(range(indice), reverse=True)
		if caller_name in function_info['functions']:
			# print(whole_func_name)
			if indice_list[0] < len(function_info['functions'][caller_name]['inst_bytes']):
				for indice_id in indice_list:
					# print(indice_id, len(file_info['functions'][callee_name]['inst_bytes']))
					inst = function_info['functions'][caller_name]['inst_bytes'][indice_id]
					#print(inst)
					if str(inst) in embed_info:
						temp_data.append(embed_info[str(inst)]['vector'])
					else:
						temp_data.append([0.0] * embed_dim)
					if len(temp_data) >= max_length:
						break

				temp_data = np.asarray(temp_data)

				if temp_data.shape[0] < max_length:
					extract_info[func_tag]['length'] = temp_data.shape[0]
					temp_zero = np.zeros((max_length - temp_data.shape[0], embed_dim))
					temp_data = np.concatenate((temp_data, temp_zero), axis=0)
				else:
					extract_info[func_tag]['length'] = temp_data.shape[0]

				extract_info[func_tag]['data'] = temp_data
				temp_type = approximate_type(function_info['icall'][(caller_name, indice, addr)]['args_type'][arg_no])
				extract_info[func_tag]['label'] = one_hot_encoding(type_info[temp_type], class_num)

	return extract_info


def get_single_num_args(folder_path, file_name, func_list, embed_dim, max_length, class_num):
	file_path = os.path.join(folder_path, file_name)
	extract_info = {}
	with open(file_path) as f:
		file_info = pickle.load(f)
	for whole_func_name in func_list:
		'''callee_name#caller_name#indice'''
		temp = whole_func_name.split('#')
		callee_name = temp[0]
		caller_name = temp[1]
		indice = int(temp[2])
		func_tag = '%s#%s' % (file_name, whole_func_name)
		extract_info[func_tag] = {}
		# inst_bytes = file_info['functions'][caller_name]['inst_bytes'][:indice]
		temp_data = []
		indice_list = sorted(range(indice), reverse=True)
		for indice_id in indice_list:
			inst = file_info['functions'][caller_name]['inst_bytes'][indice_id]
			if str(inst) in embed_info:
				temp_data.append(embed_info[str(inst)]['vector'])
			else:
				temp_data.append([0.0] * embed_dim)
			if len(temp_data) >= max_length:
				break
		temp_data = np.asarray(temp_data)
		if temp_data.shape[0] < max_length:
			extract_info[func_tag]['length'] = temp_data.shape[0]
			temp_zero = np.zeros((max_length - temp_data.shape[0], embed_dim))
			temp_data = np.concatenate((temp_data, temp_zero), axis=0)
		else:
			extract_info[func_tag]['length'] = temp_data.shape[0]
		extract_info[func_tag]['data'] = temp_data
		extract_info[func_tag]['label'] = one_hot_encoding(file_info['functions'][callee_name]['num_args'], class_num)
	return extract_info


def get_single_args_type(folder_path, file_name, func_list, embed_dim, max_length, class_num, arg_no):
	file_path = os.path.join(folder_path, file_name)
	extract_info = {}
	with open(file_path) as f:
		file_info = pickle.load(f)
	for whole_func_name in func_list:
		'''callee_name#caller_name#indice'''
		temp = whole_func_name.split('#')
		callee_name = temp[0]
		caller_name = temp[1]
		indice = int(temp[2])
		func_tag = '%s#%s' % (file_name, whole_func_name)
		extract_info[func_tag] = {}
		# inst_bytes = file_info['functions'][caller_name]['inst_bytes'][:indice]
		temp_data = []
		indice_list = sorted(range(indice), reverse=True)
		for indice_id in indice_list:
			inst = file_info['functions'][caller_name]['inst_bytes'][indice_id]
			if str(inst) in embed_info:
				temp_data.append(embed_info[str(inst)]['vector'])
			else:
				temp_data.append([0.0] * embed_dim)
			if len(temp_data) >= max_length:
				break
		temp_data = np.asarray(temp_data)
		if temp_data.shape[0] < max_length:
			extract_info[func_tag]['length'] = temp_data.shape[0]
			temp_zero = np.zeros((max_length - temp_data.shape[0], embed_dim))
			temp_data = np.concatenate((temp_data, temp_zero), axis=0)
		else:
			extract_info[func_tag]['length'] = temp_data.shape[0]
		extract_info[func_tag]['data'] = temp_data
		temp_type = approximate_type(file_info['functions'][callee_name]['args_type'][arg_no])
		extract_info[func_tag]['label'] = one_hot_encoding(type_info[temp_type], class_num)
	return extract_info

def find_slash(name):
		slash_index=set()
		for i in range(len(name)):
			if name[i] == '-':
				slash_index.add(i)
			if len(slash_index) == 3:
				return i

def find_package(name):

	package_begin = find_slash(name) + 1
	package_bin = name[package_begin:]
	package_end_index = package_bin.find('-')
	if package_end_index != -1:
		#print package_bin
		package_name = package_bin[:package_end_index]
		return package_name
	return None

def shuffle_package(train_func_list):
	package2whole = defaultdict(list)
	#shuffled_package = defaultdict(list)
	for whole_func_name  in train_func_list:
		filename = whole_func_name.split("#")[0]
		package_name = find_package(filename)
		package2whole[package_name].append(whole_func_name)

	for package in package2whole:
		random.shuffle(package2whole[package])

	return package2whole


class Dataset(object):
	def __init__(self, data_folder, func_path, embed_path, thread_num, embed_dim, max_length, class_num, tag):
		global embed_info,package2whole,extract_vector, extract_vector_test,extracted_pickle

		self.data_folder = data_folder
		self.tag = tag #num_args or type#0
		if self.tag == 'num_args':
			pass
		else:
			self.arg_no = int(self.tag.split('#')[-1])
		self.thread_num = thread_num
		self.embed_dim = embed_dim
		self.max_length = max_length
		self.class_num = class_num

		with open(func_path,'rb') as f:
			func_info = pickle.load(f,encoding="latin1")
		self.train_func_list = np.asarray(func_info['train'])
		self.test_func_list = np.asarray(func_info['test'])
		self.train_num = len(self.train_func_list)

		self.func_list = np.asarray(func_info['train']+ func_info['test'])
		print('Loaded train function information ... %s' % func_path)
		print('Train Function Number: %d' % self.train_num)

		with open(embed_path,'rb') as f:
			embed_info = pickle.load(f,encoding="latin1")
		print('Loaded embed information ... %s' % embed_path)

		self._index_in_epoch = 0
		self._complete_epochs = 0
		self._current_fold = 0

		self.test_tag = True
		self._index_in_test = 0

		self.actual_train_func_list = []
		self.val_func_list = []


		self._train_batches = {}
		self._end_index = 0
		self._start_index = 0
		self._next_batch = 0


		extracted_pickle = load_all_pickles(data_folder)

		#extract_pickle = load_pickle_file(data_folder)
		# self.batch_info = get_batch_data(self.train_func_list)
		#extract_vector = get_vector(data_folder,self.train_func_list,self.embed_dim,self.max_length,self.class_num,embed_info)

		if self.tag == 'num_args':
			#extract_vector = get_dcall_vector(self.data_folder, self.func_list, self.embed_dim, self.max_length, self.class_num,
									#embed_info)
			extract_vector_test = get_dcall_vector(self.data_folder, self.test_func_list, self.embed_dim, self.max_length, self.class_num,
																										embed_info)
		else:
			extract_vector = get_vector_type(self.data_folder, self.train_func_list, self.embed_dim, self.max_length, self.class_num,
										 embed_info, self.arg_no)
			extract_vector_test = get_vector_type(self.data_folder, self.test_func_list, self.embed_dim, self.max_length, self.class_num,
																												  embed_info, self.arg_no)
		package2whole = shuffle_package(self.train_func_list)

	def find_slash(name):
		slash_index=set()
		for i in range(len(name)):
			if name[i] == '-':
				slash_index.add(i)
			if len(slash_index) == 3:
				return i

	def find_package(name):

		package_begin = find_slash(name) + 1
		package_bin = name[package_begin:]
		package_end_index = package_bin.find('-')
		if package_end_index != -1:
			#print package_bin
			package_name = package_bin[:package_end_index]
			return package_name
		return None

	def split(self):
		current = self._current_fold
		
		#10 fold cross validation
		#package2whole = defaultdict(list)
		val_func_list = list()
		actual_train_func_list = list()
		#split according to package
		'''
		for whole_func_name  in self.train_func_list:
			filename = whole_func_name.split("#")[0]
			package_name = find_package(filename)
			package2whole[package_name].append(whole_func_name)
		'''
		'''
		for package in package2whole:
			size = len(package2whole[package])
			#random.shuffle(package2whole[package])
			val_size = int(round(size * 0.2))
			for i in range(size):
				if i >= current*val_size and i < (current + 1)*val_size:
					val_func_list.append(package2whole[package][i])
				else:
					#train_data[keys[i]] = extract_vector[keys[i]]
					actual_train_func_list.append(package2whole[package][i])

		self.val_func_list = np.array(val_func_list)
		self.train_func_list = np.array(actual_train_func_list)
		'''
		self.val_func_list = self.test_func_list
		self.train_num = len(self.train_func_list)
		print("size of train and val %d, %d"%(len(self.train_func_list),len(self.val_func_list)))

		'''
		#keys = extract_vector.keys()
		val_func_list = list()



		actual_train_func_list = list()
		size = int(round(len(self.train_func_list) * 0.1))

		for i in range(len(self.train_func_list)):
			if i >= current*size and i < (current + 1)*size:
				#cv_data[keys[i]] = extract_vector[keys[i]]
				val_func_list.append(self.train_func_list[i])
			else:
				#train_data[keys[i]] = extract_vector[keys[i]]
				actual_train_func_list.append(self.train_func_list[i])

		self.val_func_list = np.array(val_func_list)
		self.train_func_list = np.array(actual_train_func_list)
		self.self.train_num = len(self.train_func_list)
		print("size of train and val %d, %d"%(len(self.actual_train_func_list),len(self.val_func_list)))
		#print("train and val %d, %d"%(len(train_data),len(cv_data)))
		'''

		self._current_fold += 1
		return (self.train_func_list, self.val_func_list)

		

	def get_batch_data(self, batch_func_list):

		
		func_list = sorted(batch_func_list)
		if self.tag == 'num_args':
			batch_info = get_dcall_vector(self.data_folder, func_list, self.embed_dim, self.max_length, self.class_num,
									embed_info)
		else:
			batch_info = get_vector_type(self.data_folder, func_list, self.embed_dim, self.max_length, self.class_num,
									embed_info,self.arg_no)
		
		"""
		func_list = sorted(batch_func_list)
		#binary_name = ''
		#input_func_list = []
		batch_info = {}
		for whole_func_name in func_list:
			if whole_func_name in extract_vector:
				batch_info[whole_func_name] = extract_vector[whole_func_name]
		
		"""

		'''
		pool = Pool(self.thread_num)
		if self.tag == 'num_args':
			for whole_func_name in func_list:
				if binary_name == '':
					binary_name = whole_func_name.split('#')[0]
					input_func_list.append('#'.join(whole_func_name.split('#')[1:]))
				else:
					if binary_name == whole_func_name.split('#')[0]:
						input_func_list.append('#'.join(whole_func_name.split('#')[1:]))
					else:
						pool.apply_async(
							get_single_num_args,
							args=(self.data_folder, binary_name, input_func_list, self.embed_dim, self.max_length,
								  self.class_num),
							callback=batch_info.update
						)
						binary_name = whole_func_name.split('#')[0]
						input_func_list = ['#'.join(whole_func_name.split('#')[1:])]
			if len(input_func_list) == 0:
				pass
			else:
				pool.apply_async(
					get_single_num_args,
					args=(
					self.data_folder, binary_name, input_func_list, self.embed_dim, self.max_length, self.class_num),
					callback=batch_info.update
				)
		else:  # self.tag == 'type#0'
			for whole_func_name in func_list:
				if binary_name == '':
					binary_name = whole_func_name.split('#')[0]
					input_func_list.append('#'.join(whole_func_name.split('#')[1:]))
				else:
					if binary_name == whole_func_name.split('#')[0]:
						input_func_list.append('#'.join(whole_func_name.split('#')[1:]))
					else:
						pool.apply_async(
							get_single_args_type,
							args=(self.data_folder, binary_name, input_func_list, self.embed_dim, self.max_length,
								  self.class_num, self.arg_no),
							callback=batch_info.update
						)
						binary_name = whole_func_name.split('#')[0]
						input_func_list = ['#'.join(whole_func_name.split('#')[1:])]
			if len(input_func_list) == 0:
				pass
			else:
				pool.apply_async(
					get_single_args_type,
					args=(
					self.data_folder, binary_name, input_func_list, self.embed_dim, self.max_length, self.class_num,
					self.arg_no),
					callback=batch_info.update
				)
		pool.close()
		pool.join()
		'''

		'''
		new_batch_data = {
			'data': [],
			'label': [],
			'length': []
		}
		for full_func_name in batch_info:
			if 'data' in batch_info[full_func_name]:
				new_batch_data['data'].append(batch_info[full_func_name]['data'])
				new_batch_data['label'].append(batch_info[full_func_name]['label'])
				new_batch_data['length'].append(batch_info[full_func_name]['length'])
		batch_info = {
			'data': np.asarray(new_batch_data['data'], dtype=np.float32),
			'label': np.asarray(new_batch_data['label'], dtype=np.float32),
			'length': np.asarray(new_batch_data['length'], dtype=np.float32)
		}
		'''
		return batch_info
		

	def get_batch(self, batch_size):
		#global train_batches
		start = self._index_in_epoch

		# shuffle for the first round
		if self._complete_epochs == 0 and self._index_in_epoch == 0:
			perm0 = np.arange(self.train_num)
			np.random.shuffle(perm0)
			self.train_func_list = self.train_func_list[perm0]

			end = self._index_in_epoch + batch_size * 120
			self._end_index = end
			func_list_batch = self.train_func_list[start:end]
			self._train_batches = self.get_batch_data(func_list_batch)


		# go to the next epoch
		if start + batch_size > self.train_num:
			self._complete_epochs += 1
			rest_example_num = self.train_num - start
			rest_func_list = self.train_func_list[start:self.train_num]
			# shuffle for the new epoch
			perm = np.arange(self.train_num)
			np.random.shuffle(perm)
			self.train_func_list = self.train_func_list[perm]
			# start a new epoch
			start = 0
			self._index_in_epoch = batch_size - rest_example_num
			end = self._index_in_epoch
			new_func_list = self.train_func_list[start:end]
			func_list_batch = np.concatenate((rest_func_list, new_func_list), axis=0)
			batch_info = self.get_batch_data(func_list_batch)
			#return train_batch

			new_batch_data = {
				'data': [],
				'label': [],
				'length': []
			}
			for full_func_name in batch_info:
				if 'data' in batch_info[full_func_name]:
					new_batch_data['data'].append(batch_info[full_func_name]['data'])
					new_batch_data['label'].append(batch_info[full_func_name]['label'])
					new_batch_data['length'].append(batch_info[full_func_name]['length'])
			batch_info = {
				'data': np.asarray(new_batch_data['data'], dtype=np.float32),
				'label': np.asarray(new_batch_data['label'], dtype=np.float32),
				'length': np.asarray(new_batch_data['length'], dtype=np.float32)
			}
			#self._next_batch = 1
			end = self._index_in_epoch + batch_size * 120
			self._end_index = end
			func_list_batch = self.train_func_list[self._index_in_epoch:end]
			self._train_batches = self.get_batch_data(func_list_batch)
			self._start_index = 0
			return batch_info

		else:  # process current epoch
			'''
			if self._complete_epochs != 0 and self._next_batch:
				end = self._index_in_epoch + batch_size * 128
				self._end_index = end
				func_list_batch = self.train_func_list[start:end]
				self._train_batches = self.get_batch_data(func_list_batch)
				self._next_batch = 0
			'''

			'''
			self._index_in_epoch += batch_size
			end = self._index_in_epoch
			func_list_batch = self.train_func_list[start:end]
			train_batch = self.get_batch_data(func_list_batch)
			return train_batch
			'''

			if self._index_in_epoch < self._end_index:
				#print("len of batches %d"%len(self._train_batches))
				batch_info = dict(list(self._train_batches.items())[self._start_index:(self._start_index + batch_size)])
				#print(batch_info)
				if len(batch_info) != 0:
					new_batch_data = {
						'data': [],
						'label': [],
						'length': []
					}
					for full_func_name in batch_info:
						if 'data' in batch_info[full_func_name]:
							new_batch_data['data'].append(batch_info[full_func_name]['data'])
							new_batch_data['label'].append(batch_info[full_func_name]['label'])
							new_batch_data['length'].append(batch_info[full_func_name]['length'])
					batch_info = {
						'data': np.asarray(new_batch_data['data'], dtype=np.float32),
						'label': np.asarray(new_batch_data['label'], dtype=np.float32),
						'length': np.asarray(new_batch_data['length'], dtype=np.float32)
					}
				else:
					end = self._index_in_epoch + batch_size * 120
					self._end_index = end
					func_list_batch = self.train_func_list[start:end]
					self._train_batches = self.get_batch_data(func_list_batch)
					self._start_index = 0
					#print("len of batches in another group %d" % len(self._train_batches))
					batch_info = dict(
						list(self._train_batches.items())[self._start_index:(self._start_index + batch_size)])

					new_batch_data = {
						'data': [],
						'label': [],
						'length': []
					}
					for full_func_name in batch_info:
						if 'data' in batch_info[full_func_name]:
							new_batch_data['data'].append(batch_info[full_func_name]['data'])
							new_batch_data['label'].append(batch_info[full_func_name]['label'])
							new_batch_data['length'].append(batch_info[full_func_name]['length'])
					batch_info = {
						'data': np.asarray(new_batch_data['data'], dtype=np.float32),
						'label': np.asarray(new_batch_data['label'], dtype=np.float32),
						'length': np.asarray(new_batch_data['length'], dtype=np.float32)
					}


				self._index_in_epoch += batch_size
				self._start_index += batch_size
				return batch_info

			else:
				end = self._index_in_epoch + batch_size *120
				self._end_index = end
				self._start_index = 0
				func_list_batch = self.train_func_list[start:end]
				self._train_batches = self.get_batch_data(func_list_batch)
				#print("len of batches in another group %d" % len(self._train_batches))
				batch_info = dict(list(self._train_batches.items())[self._start_index:(self._start_index + batch_size)])

				new_batch_data = {
					'data': [],
					'label': [],
					'length': []
				}
				for full_func_name in batch_info:
					if 'data' in batch_info[full_func_name]:
						new_batch_data['data'].append(batch_info[full_func_name]['data'])
						new_batch_data['label'].append(batch_info[full_func_name]['label'])
						new_batch_data['length'].append(batch_info[full_func_name]['length'])
				batch_info = {
					'data': np.asarray(new_batch_data['data'], dtype=np.float32),
					'label': np.asarray(new_batch_data['label'], dtype=np.float32),
					'length': np.asarray(new_batch_data['length'], dtype=np.float32)
				}

				self._index_in_epoch += batch_size
				self._start_index += batch_size
				return batch_info
		"""
		start = self._index_in_epoch
		# shuffle for the first round
		if self._complete_epochs == 0 and self._index_in_epoch == 0:
			perm0 = np.arange(self.train_num)
			np.random.shuffle(perm0)
			self.train_func_list = self.train_func_list[perm0]

		# go to the next epoch
		if start + batch_size > self.train_num:
			self._complete_epochs += 1
			rest_example_num = self.train_num - start
			rest_func_list = self.train_func_list[start:self.train_num]
			# shuffle for the new epoch
			perm = np.arange(self.train_num)
			np.random.shuffle(perm)
			self.train_func_list = self.train_func_list[perm]
			# start a new epoch
			start = 0
			self._index_in_epoch = batch_size - rest_example_num
			end = self._index_in_epoch
			new_func_list = self.train_func_list[start:end]
			func_list_batch = np.concatenate((rest_func_list, new_func_list), axis=0)
			train_batch = self.get_batch_data(func_list_batch)
			return train_batch
		else:  # process current epoch
			self._index_in_epoch += batch_size
			end = self._index_in_epoch
			func_list_batch = self.train_func_list[start:end]
			train_batch = self.get_batch_data(func_list_batch)
			return train_batch

		
		"""

	def get_batch_cv(self, batch_size):
		start = self._index_in_test
		if start + batch_size >= len(self.val_func_list):
			self.test_tag = False
			func_list_batch = self.val_func_list[start:]
			test_batch = self.get_batch_data_cv(func_list_batch)
			
			return test_batch
		else:
			self._index_in_test += batch_size
			end = self._index_in_test
			func_list_batch = self.val_func_list[start: end]
			test_batch = self.get_batch_data_cv(func_list_batch)
			return test_batch


	def get_batch_data_cv(self, batch_func_list):

		func_list = sorted(batch_func_list)
		
		#print("func",func_list)
		batch_info = {}
		for whole_func_name in func_list:
			if whole_func_name in extract_vector_test:
				print("in",whole_func_name,extract_vector_test[whole_func_name])
				batch_info[whole_func_name] = extract_vector_test[whole_func_name]

			else:
				print("func",whole_func_name)
		'''
		if self.tag == 'num_args':
			batch_info = get_vector(self.data_folder, func_list, self.embed_dim, self.max_length, self.class_num,
									embed_info)
		else:
			batch_info = get_vector_type(self.data_folder, func_list, self.embed_dim, self.max_length, self.class_num,
										 embed_info, self.arg_no)		
		'''
		new_batch_data = {
			'data': [],
			'label': [],
			'length': [],
			'func_name':[]
		}

		for full_func_name in batch_info:
			if 'data' in batch_info[full_func_name]:
				new_batch_data['data'].append(batch_info[full_func_name]['data'])
				new_batch_data['label'].append(batch_info[full_func_name]['label'])
				new_batch_data['length'].append(batch_info[full_func_name]['length'])
				new_batch_data['func_name'].append(full_func_name)
		batch_info = {
			'data': np.asarray(new_batch_data['data'], dtype=np.float32),
			'label': np.asarray(new_batch_data['label'], dtype=np.float32),
			'length': np.asarray(new_batch_data['length'], dtype=np.float32),
			'func_name': np.asarray(new_batch_data['func_name'])
		}
		return batch_info
