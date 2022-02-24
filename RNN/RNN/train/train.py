from __future__ import division
from __future__ import print_function
import argparse
import functools
import inspect
import os
os.environ['TF_DETERMINISTIC_OPS'] = '1'
import sys
#import tflearn
import time
import pickle

import dataset
import dataset_caller
import tensorflow as tf
#from tfdeterminism import patch
#patch()
import pickle
import numpy as np
import random

SEED = 123
random.seed(SEED)
np.random.seed(SEED)
#tf.set_random_seed(SEED)
tf.compat.v1.set_random_seed(SEED)
os.environ['PYTHONHASHSEED'] = str(SEED)

from multiprocessing import Pool

from capstone import *
from capstone.x86 import *
from ctypes import *
from typedef import *
from elf import *
from dissamble import *


def disassembling(shdr,elfparse,start_addr,end_addr):
	disassm = Dissamble(elfparse.elf,shdr,start_addr,end_addr)
	#disassm.Output()
	i = 0
	addr2ins = dict()
	#ins_array = dict()

	for ins in disassm.dissambled_ins:
		addr2ins[ins.address] = ins
	

	return addr2ins


def get_icall_addr(shdr, elfparse, start_addr, end_addr, icall_index):
	index = 0

	addr2ins = disassembling(shdr, elfparse, start_addr, end_addr)
	x = start_addr
	print("get icall address")
	while x <= end_addr and x >= start_addr and x in addr2ins:
		ins = addr2ins[x]
		index += 1
		if ins.id == X86_INS_CALL and icall_index == index:
			return (x, ins)
		ins_size = ins.size
		x = x + ins_size

	return (0, ins)


def compute_inaccuracy(total_result,config_info):
	overestimation = dict()
	underestimation = dict()
	correct = dict()

	object_type  = config_info['data_tag']  #caller or callee
	pickle_folder = config_info['data_folder']
	tag = config_info['tag']   #arg_type or arg_nums

	disassembled_bin = dict()
	loaded_bin = dict()

	icall_addr = -1

	#print(total_result)
	pred_list_dict = total_result['pred']
	#print(pred_list)
	function_info = total_result['func_name']
	incorrect = dict()

	for i in range(0, len(pred_list_dict)):
		pred_label = pred_list_dict[i]
		predicted = pred_label['pred']
		groundTruth = pred_label['label']
		#print(predicted)
		for j in range(len(predicted.values)):
			function_name = function_info[i][j]
			predicted_posibility = predicted.values[j]

			predicted_label = predicted.indices[j]
			groundTruth_label = groundTruth.indices[j]
			
			max_label = -1
			min_label = 11

			for t in range(0,1):
				#if predicted_posibility[t] > 0.045:
				if predicted_label[0] == groundTruth_label[0]:
					correct[function_name] = (predicted_label[t], groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
					break
			if 	function_name not in correct:
				incorrect[function_name] = (predicted_label[0], groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)




			"""
			if object_type == 'caller':
				for t in range(0,len(predicted_label)):
					if predicted_posibility[t] > 0.045:
						if predicted_label[t] >= max_label:
							max_label = predicted_label[t]
				final_label = max_label
			else:
				for t in range(0,len(predicted_label)):
					if predicted_posibility[t] > 0.045:
						if tag == "num_args":
							if predicted_label[t] <= min_label:
								min_label = predicted_label[t]
						else:
							if predicted_label[t] == 10:
								min_label = predicted_label[t]
								break
							elif predicted_label[t] <= min_label:
								min_label = predicted_label[t]
				final_label = min_label
			
			if final_label != -1:
				if final_label > groundTruth_label[0]:
					if tag == 'num_args':
						overestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
					else:
						overestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
						'''
						if final_label == 10:
							underestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
						elif final_label == 5 and  groundTruth_label[0] == 3:
							correct[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr) 
						else:
							overestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
						'''
				if final_label < groundTruth_label[0]:
					if groundTruth_label[0] == 10:
					   overestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr) 
					else:

						if tag == 'num_args':
							underestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
						else:
							overestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
							'''
							if final_label == 3 and groundTruth_label[0] == 5:
								correct[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
							else:
								underestimation[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
							'''
				if final_label == groundTruth_label[0]:
					correct[function_name] = (final_label, groundTruth_label[0],predicted_posibility,predicted_label,icall_addr)
			"""

	return correct,incorrect



def lazy_property(function):
	attribute = '_' + function.__name__

	@property
	@functools.wraps(function)
	def wrapper(self):
		if not hasattr(self, attribute):
			setattr(self, attribute, function(self))
		return getattr(self, attribute)
	return wrapper


def placeholder_inputs(class_num, max_length= 500, embedding_dim= 256):
	data_placeholder = tf.placeholder(tf.float32, [None, max_length, embedding_dim])
	label_placeholder = tf.placeholder(tf.float32, [None, class_num])
	length_placeholder = tf.placeholder(tf.int32, [None,])
	keep_prob_placeholder = tf.placeholder(tf.float32) # dropout (keep probability)
	return data_placeholder, label_placeholder, length_placeholder, keep_prob_placeholder




def fill_feed_dict(data_set, batch_size, keep_prob, data_pl, label_pl, length_pl, keep_prob_pl,data):

	#start = time.time()
	data_batch = data_set.get_batch(batch_size)
	#end = time.time()
	#print("time in getting batch data %s seconds" % (end - start))

	#data_batch = data_set.next_batch(batch_size=batch_size)
	feed_dict = {
		data_pl: data_batch['data'],
		label_pl: data_batch['label'],
		length_pl: data_batch['length'],
		keep_prob_pl: keep_prob
	}
	#end = time.time()
	#print("time in get batch data %s seconds" % (end - start))
	return feed_dict


def fill_feed_dict_cv(data_set, batch_size,  data_tag, keep_prob, data_pl, label_pl, length_pl, keep_prob_pl):

	#start = time.time()
	data_batch = data_set.get_batch_cv(batch_size)
	#end = time.time()
	#print("time in getting batch data %s seconds" % (end - start))

	#data_batch = data_set.next_batch(batch_size=batch_size)
	feed_dict = {
		data_pl: data_batch['data'],
		label_pl: data_batch['label'],
		length_pl: data_batch['length'],
		keep_prob_pl: keep_prob
	}
	#end = time.time()
	#print("time in get batch data %s seconds" % (end - start))
	return feed_dict,  data_batch['func_name']




class DeviceCellWrapper(tf.nn.rnn_cell.GRUCell):
	def __init__(self, cell, device):
		self._cell = cell
		self._device = device

	@property
	def state_size(self):
		return self._cell.state_size

	@property
	def output_size(self):
		return self._cell.output_size

	def __call__(self, inputs, state, scope=None):
		with tf.device(self._device):
			return self._cell(inputs, state, scope)

class Model(object):
	def __init__(self, session, my_data, config_info, data_pl, label_pl, length_pl, keep_prob_pl):
		self.session = session
		self.datasets = my_data
		self.emb_dim = int(config_info['embed_dim'])
		self.dropout = float(config_info['dropout'])
		self.num_layers = int(config_info['num_layers'])
		self.num_classes = int(config_info['num_classes'])
		self.max_to_save = int(config_info['max_to_save'])
		self.output_dir = config_info['log_path']
		self.batch_size = int(config_info['batch_size'])
		self.summary_frequency = int(config_info['summary_frequency'])

		self._data = data_pl
		self._label = label_pl
		self._length = length_pl
		self._keep_prob = keep_prob_pl

		self.run_count = 0

		self.build_graph()

	@lazy_property
	def probability(self):

		def lstm_cell():
			devices = ["/gpu:1", "/gpu:5", "/cpu:0"]
			if 'reuse' in inspect.getargspec(tf.nn.rnn_cell.GRUCell.__init__).args:
				return tf.nn.rnn_cell.GRUCell(self.emb_dim, reuse=tf.get_variable_scope().reuse)

			else:
				return tf.nn.rnn_cell.GRUCell(self.emb_dim)

		attn_cell = lstm_cell
		if self.dropout < 1:
			def attn_cell():
				return tf.nn.rnn_cell.DropoutWrapper(
					lstm_cell(), output_keep_prob=self._keep_prob)



		single_cell = tf.nn.rnn_cell.MultiRNNCell([attn_cell() for _ in range(self.num_layers)], state_is_tuple=True)

		output, state = tf.nn.dynamic_rnn(single_cell, self._data, dtype=tf.float32,
										  sequence_length=self._length)
		weight = tf.Variable(tf.truncated_normal([self.emb_dim, self.num_classes], stddev=0.01))
		bias = tf.Variable(tf.constant(0.1, shape=[self.num_classes]))

		self.output = output
		probability = tf.matmul(self.last_relevant(output, self._length), weight) + bias
		return probability

	def last_relevant(self, output, length):
		batch_size = tf.shape(output)[0]
		max_len = int(output.get_shape()[1])
		output_size = int(output.get_shape()[2])
		index = tf.range(0, batch_size) * max_len + (length - 1)
		flat = tf.reshape(output, [-1, output_size])
		#revised by yanlin
		partitions = tf.reduce_sum(tf.one_hot(index, tf.shape(flat)[0], dtype='int32'), 0)

		relevant= tf.dynamic_partition(flat, partitions, 2)
		relevant=relevant[1]
		#end of revision
		#relevant = tf.gather(flat, index)
		return relevant

	@lazy_property
	def cost_list(self):
		prediction = self.probability
		target = self._label
		cross_entropy = tf.nn.softmax_cross_entropy_with_logits(logits=prediction, labels=target)
		return cross_entropy

	@lazy_property
	def cost(self):
		cross_entropy = tf.reduce_mean(self.cost_list)
		tf.summary.scalar('cross_entropy', cross_entropy)
		return cross_entropy

	@lazy_property
	def optimize(self):

		global_step = tf.Variable(0, name='global_step', trainable=False)
		train_op = tf.train.AdamOptimizer().minimize(self.cost, global_step)

		return train_op

	@lazy_property
	def calc_accuracy(self):
		true_probability = tf.nn.softmax(self.probability)
		correct_pred = tf.equal(tf.argmax(true_probability, 1), tf.argmax(self._label, 1))
		accuracy = tf.reduce_mean(tf.cast(correct_pred, tf.float32))
		tf.summary.scalar('acc', accuracy)
		return accuracy

	@lazy_property
	def pred_label(self):
		true_probability = tf.nn.softmax(self.probability)
		pred_output = tf.argmax(true_probability, 1)
		label_output = tf.argmax(self._label, 1)
		output_result = {
			'pred': pred_output,
			'label': label_output
		}
		return output_result

	@lazy_property
	def pred_label_val(self):
		true_probability = tf.nn.softmax(self.probability)
		#print("prob",true_probability)
		#pred_output = tf.argmax(true_probability, 1)
		pred_output = tf.nn.top_k(true_probability, k=5, sorted=True)
		#pred_output = (values,indices)
		#print("prob2", pred_output)
		#label_output = tf.argmax(self._label, 1)
		label_output = tf.nn.top_k(self._label, k=5, sorted=True)
		#output_result = {
		   # 'pred': pred_output,
			#'label': label_output
		#}
		output_result = {
		 'pred': pred_output,
		'label': label_output
		 }
		return output_result


	def build_graph(self):
		self.optimize
		self.calc_accuracy
		self.pred_label
		self.pred_label_val

		self.merged = tf.summary.merge_all()
		self.train_writer = tf.summary.FileWriter(self.output_dir + '/train', self.session.graph)
		self.test_writer = tf.summary.FileWriter(self.output_dir + '/test')

		self.saver = tf.train.Saver(tf.trainable_variables(),
									max_to_keep=self.max_to_save)

		tf.global_variables_initializer().run()

	def train(self,train_data,cv_data):

		#start = time.time()
		feed_dict = fill_feed_dict(self.datasets, self.batch_size, self.dropout,
					   self._data, self._label, self._length, self._keep_prob,train_data)


		#end = time.time()
		#print("time in getting feed_dict %s seconds"%(end -start))

		#for d in ['/device:GPU:5', '/device:GPU:1']:
		#with tf.device('/device:GPU:5'):
		if self.run_count % self.summary_frequency == 0:
			cost, acc, summary, _ = self.session.run(
			[self.cost, self.calc_accuracy, self.merged, self.optimize],
			feed_dict = feed_dict)
			self.train_writer.add_summary(summary, self.run_count)



			print('[Batch %d][Epoch %d] cost: %.3f; accuracy: %.3f' % (self.run_count,
														   self.datasets._complete_epochs,
														   cost,
														   acc))

		else:
			#start = time.time()
			self.session.run(self.optimize, feed_dict = feed_dict)
			end = time.time()
			#print("time in training one batch %s seconds"%(end - start))

		self.run_count += 1


	def test(self):
		total_result = {
			'cost': [],
			'pred': [],
			'func_name': []
		}
		while self.datasets.test_tag:
			feed_dict, func_name_list = fill_feed_dict_cv(self.datasets, self.batch_size, 'test', 1.0,
													   self._data, self._label, self._length, self._keep_prob)
			cost_result, pred_result = self.session.run(
				[self.cost_list, self.pred_label_val],
				feed_dict = feed_dict
			)
			total_result['cost'].append(cost_result)
			total_result['pred'].append(pred_result)
			total_result['func_name'].append(func_name_list)

		return total_result

def get_model_id_list(folder_path):
	file_list = os.listdir(folder_path)
	model_id_set = set()
	for file_name in file_list:
		if file_name[:6] == 'model-':
			model_id_set.add(int(file_name.split('.')[0].split('-')[-1]))
		else:
			pass
	model_id_list = sorted(list(model_id_set))
	return model_id_list


def training(config_info):
	data_folder = config_info['data_folder']
	func_path = config_info['func_path']
	embed_path = config_info['embed_path']
	tag = config_info['tag']
	data_tag = config_info['data_tag']
	process_num = int(config_info['process_num'])
	embed_dim = int(config_info['embed_dim'])
	max_length = int(config_info['max_length'])
	num_classes = int(config_info['num_classes'])
	epoch_num = int(config_info['epoch_num'])
	save_batch_num = int(config_info['save_batchs'])
	output_dir = config_info['output_dir']

	'''create model & log folder'''
	if os.path.exists(output_dir):
		pass
	else:
		os.mkdir(output_dir)
	model_basedir = os.path.join(output_dir, 'model')
	if os.path.exists(model_basedir):
		pass
	else:
		os.mkdir(model_basedir)
	log_basedir = os.path.join(output_dir, 'log')
	if tf.gfile.Exists(log_basedir):
		tf.gfile.DeleteRecursively(log_basedir)
	tf.gfile.MakeDirs(log_basedir)
	config_info['log_path'] = log_basedir
	print('Created all folders!')

	'''load dataset'''
	if data_tag == 'callee':
		my_data = dataset.Dataset(data_folder, func_path, embed_path, process_num, embed_dim, max_length, num_classes, tag)
	else: #caller
		my_data = dataset_caller.Dataset(data_folder, func_path, embed_path, process_num, embed_dim, max_length, num_classes, tag)
	
	print('Created the dataset!')

	session_config = tf.ConfigProto(log_device_placement=True)
	#,allow_soft_placement=True)
	#inter_op_parallelism_threads=80,
	#intra_op_parallelism_threads=80)
	#session_config.gpu_options.per_process_gpu_memory_fraction = 0.8


   
	# generate placeholder
	#data_pl, label_pl, length_pl, keep_prob_pl = placeholder_inputs(num_classes, max_length, embed_dim)

	#model = Model(session, my_data, config_info, data_pl, label_pl, length_pl, keep_prob_pl)
	#print('Created the model!')

	#cross validation
	for i in range(5):
		with tf.Graph().as_default(), tf.Session(config=session_config) as session:
			data_pl, label_pl, length_pl, keep_prob_pl = placeholder_inputs(num_classes, max_length, embed_dim)

			model = Model(session, my_data, config_info, data_pl, label_pl, length_pl, keep_prob_pl)
			print('Created the model!')

			#my_data._complete_epochs = 99
			my_data._current_fold = i
			model.run_count = 0 
			#elf.run_count = 0
			#if i == 6:
			#graph_directory = "../utils_train_output/callee_uninsert/num_args/1/model/1/model-epoch-84"
			#model.saver.restore(session,graph_directory)
			my_data._complete_epochs = 100
			save_mode_dir = model_basedir + '/' + str(my_data._current_fold + 1)
			
			cmd = "mkdir -p " + save_mode_dir
			os.system(cmd)

			print('Current fold: {}\n'.format(my_data._current_fold + 1))
			(train_input, cv_input) = my_data.split()
			start = time.time()
			previs_epoch = my_data._complete_epochs
			previs_cv_acc = 0
			#cv_info = save_mode_dir + "/cv-info.txt"
			#out_handler = open(cv_info, 'w')
			while my_data._complete_epochs < epoch_num:
				model.train(train_input,cv_input)
				if my_data._complete_epochs - previs_epoch == 1:
					#total_result = model.test(cv_input)
					#cv_cost = np.array(total_result['cost']).mean()
					#cv_acc = np.array(total_result['pred']).mean()
					my_data._index_in_test = 0
					my_data.test_tag = True
					#print('cross validation accuracy: %.3f' % (cv_acc))

					#if cv_acc < previs_cv_acc:
						#out_handler.write("possible overfitting epoch %d"%my_data._complete_epochs)
						#out_handler.write("\t prev_acc-current_acc (%s,%s)" % (previs_cv_acc,cv_acc))

					#previs_cv_acc = cv_acc

					previs_epoch = my_data._complete_epochs
					#if my_data._complete_epochs - previs_epoch  == 0:


					model.saver.save(session, os.path.join(save_mode_dir, 'model-epoch'), global_step = my_data._complete_epochs)
					print('Saved the model ... %d' % my_data._complete_epochs)

			
			#perfrom the test
			if my_data._complete_epochs == epoch_num:
				test_output_dir = os.path.join(save_mode_dir, 'train_output') 
				if os.path.exists(test_output_dir):
					pass
				else:
					os.mkdir(test_output_dir)
				model_finaldir = os.path.join(save_mode_dir, 'final')
				if os.path.exists(model_finaldir):
					pass
				else:
					os.mkdir(model_finaldir)
				cmd = "cp " + save_mode_dir +"/model-epoch-"+str(epoch_num)+".* " + model_finaldir
				os.system(cmd)

				model_id_list = sorted(get_model_id_list(model_finaldir))
				for model_id in model_id_list:
					result_path = os.path.join(test_output_dir, 'test_result_%d.pkl' % model_id)
					inaccuracy_path = os.path.join(test_output_dir, 'accuracy_%d.txt'% model_id)
					pickle_path = os.path.join(test_output_dir, 'dataset_%d.pkl'%my_data._current_fold)
					model_path = os.path.join(model_finaldir, 'model-epoch-%d' % model_id)
					model.saver.restore(session, model_path)

					splitFuncDict ={'train':train_input,'test':cv_input} 	
					with open(pickle_path,'wb') as f:
						pickle.dump(splitFuncDict, f)

					total_result = model.test()

					my_data._index_in_test = 0
					my_data.test_tag = True

					correct,incorrect= compute_inaccuracy(total_result,config_info)

					
			
					with open(inaccuracy_path,'w') as f:
						#print >> f,"correct",correct
						#print >>f,"overestimation",overestimation
						#print >>f,"underestimation",underestimation
						#print >> f, "correct"
						#f.write("correct")
						print("correct",file=f)
						correct_O0 = 0
						correct_O1 = 0
						correct_O2 = 0
						correct_O3 = 0
						for func_name in correct:
							if "O0" in func_name:
								correct_O0 += 1
							elif "O1" in func_name:
								correct_O1 += 1
							elif "O2" in func_name:
								correct_O2 += 1
							elif "O3" in func_name:
								correct_O3 += 1
							(correct_label, groundTruth, predicted_posibility, predicted_label, icall_addr) = correct[func_name]
							if icall_addr == -1:
															#f.write(func_name)
								print(func_name, correct_label, groundTruth, predicted_posibility, predicted_label,file=f)

							#elif icall_addr != 0:
								#print >> f, func_name, correct_label, groundTruth, predicted_posibility, predicted_label, hex(icall_addr))

						print("incorrect",file=f)
						incorrect_O0 = 0
						incorrect_O1 = 0
						incorrect_O2 = 0
						incorrect_O3 = 0
						for func_name in incorrect:
							if "O0" in func_name:
								incorrect_O0 += 1
							elif "O1" in func_name:
								incorrect_O1 += 1
							elif "O2" in func_name:
								incorrect_O2 += 1
							elif "O3" in func_name:
								incorrect_O3 += 1
							(correct_label, groundTruth, predicted_posibility, predicted_label, icall_addr) = incorrect[func_name]
							if icall_addr == -1:
								print( func_name, correct_label, groundTruth, predicted_posibility, predicted_label,file=f)

							#elif icall_addr != 0:
								#print >> f, func_name, correct_label, groundTruth, predicted_posibility, predicted_label,hex(icall_addr)

						'''
						print >> f, "underestimation"

						for func_name in underestimation:
							(correct_label, groundTruth, predicted_posibility, predicted_label, icall_addr) = underestimation[func_name]
							if icall_addr == -1:
								print >> f, func_name, correct_label, groundTruth, predicted_posibility, predicted_label

							elif icall_addr != 0:
								print >> f, func_name, correct_label, groundTruth, predicted_posibility, predicted_label,hex(icall_addr)

						'''
						total_num = len(correct)+len(incorrect)
						

						correct_percent = len(correct)/total_num
						#over_percent = len(overestimation)/total_num
						#under_percent = len(underestimation)/total_num
						correct_O0_percent = correct_O0/(correct_O0+incorrect_O0)
						correct_O1_percent = correct_O1/(correct_O1+incorrect_O1)
						correct_O2_percent = correct_O2/(correct_O2+incorrect_O2)
						correct_O3_percent = correct_O3/(correct_O3+incorrect_O3)

						print("total_accuracy", correct_percent,file=f)
						print("O0", correct_O0_percent,file=f)
						print("O1", correct_O1_percent,file=f)
						print("O2", correct_O2_percent,file=f)
						print("O3", correct_O3_percent,file=f)
						#print >> f, over_percent
					with open(result_path, 'w') as f:
						print(total_result,file=f)
						#print(total_result,f)
						#pickle.dump(total_result, f)
					print('Save the test result !!! ... %s' % result_path)

			end = time.time()
			print("time in training one epoch %s seconds"%(end-start))
			model.train_writer.close()
			model.test_writer.close()



		'''
		start = time.time()
		while my_data._complete_epochs < epoch_num:
			model.train()
			if model.run_count % save_batch_num == 0:
				model.saver.save(session, os.path.join(model_basedir, 'model'), global_step = model.run_count)
				print('Saved the model ... %d' % model.run_count)

		end = time.time()
		print("time in training one epoch %s seconds"%(end-start))
		model.train_writer.close()
		model.test_writer.close()
		'''


def get_config():
	'''
	get config information from command line
	'''
	parser = argparse.ArgumentParser()

	parser.add_argument('-d', '--data_folder', dest='data_folder', help='The data folder of training dataset.', type=str, required=True)
	parser.add_argument('-o', '--output_dir', dest='output_dir', help='The directory to saved the log information & models.', type=str, required=True)
	parser.add_argument('-f', '--split_func_path', dest='func_path', help='The path of file saving the training & testing function names.', type=str, required=True)
	parser.add_argument('-e', '--embed_path', dest='embed_path', help='The path of saved embedding vectors.', type=str, required=True)
	parser.add_argument('-t', '--label_tag', dest='tag', help='The type of labels. Possible value: num_args, type#0, type#1, ...', type=str, required=False, default='num_args')
	parser.add_argument('-dt', '--data_tag', dest='data_tag', help='The type of input data.', type=str, required=False, choices=['caller', 'callee'], default='callee')
	parser.add_argument('-pn', '--process_num', dest='process_num', help='Number of processes.', type=int, required=False, default=40)
	parser.add_argument('-ed', '--embedding_dim', dest='embed_dim', help='The dimension of embedding vector.', type=int, required=False, default=256)
	parser.add_argument('-ml', '--max_length', dest='max_length', help='The maximum length of input sequences.', type=int, required=False, default=500)
	parser.add_argument('-nc', '--num_classes', dest='num_classes', help='The number of classes', type=int, required=False, default=16)
	parser.add_argument('-en', '--epoch_num', dest='epoch_num', help='The number of epoch.', type=int, required=False, default=50)
	parser.add_argument('-s', '--save_frequency', dest='save_batchs', help='The frequency for saving the trained model.', type=int, required=False, default=100)
	parser.add_argument('-do', '--dropout', dest='dropout', help='The dropout value.', type=float, required=False, default=0.8)
	parser.add_argument('-nl', '--num_layers', dest='num_layers', help='Number of layers in RNN.', type=int, required=False, default=3)
	parser.add_argument('-ms', '--max_to_save', dest='max_to_save', help='Maximum number of models saved in the directory.', type=int, required=False, default=100)
	parser.add_argument('-b', '--batch_size', dest='batch_size', help='The size of batch.', type=int, required=False, default=256)
	parser.add_argument('-p', '--summary_frequency', dest='summary_frequency', help='The frequency of showing the accuracy & cost value.', type=int, required=False, default=20)
	parser.add_argument('-ts', '--temperature scaling', dest='summary_frequency', help='Using tempeature scaling to get the confidence.', type=int, required=True, default=1)

	args = parser.parse_args()
	
	config_info = {
		'data_folder': args.data_folder,
		'output_dir': args.output_dir,
		'func_path': args.func_path,
		'embed_path': args.embed_path,
		'tag': args.tag,
		'data_tag': args.data_tag,
		'process_num': args.process_num,
		'embed_dim': args.embed_dim,
		'max_length': args.max_length,
		'num_classes': args.num_classes,
		'epoch_num': args.epoch_num,
		'save_batchs': args.save_batchs,
		'dropout': args.dropout,
		'num_layers': args.num_layers,
		'max_to_save': args.max_to_save,
		'batch_size': args.batch_size,
		'summary_frequency': args.summary_frequency,
		'temperature scaling': args.temperature scaling
	}

	return config_info


def main():
	config_info = get_config()
	start = time.time()
	training(config_info)
	end = time.time()
	print("time %s seconds"%(end - start))


if __name__ == '__main__':
	main()
