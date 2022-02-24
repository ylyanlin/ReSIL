from __future__ import division
import tensorflow as tf
#tf.enable_eager_execution()
import dataset
import dataset_caller
import os
import sys
import numpy
from numpy.linalg import norm
#import keras

import argparse
import functools
import pickle
import inspect
import heapq


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

			for t in range(0,len(predicted_label)):
				if predicted_posibility[t] > 0.045:
					if predicted_label[t] == groundTruth_label[0]:
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


def compute_saliency_map(total_result):
	



	function_info = total_result['func_name']
	gradients =  total_result['gradient']
	function_index = 0

	saliency_map = dict()

	print("len of gradients", len(gradients))
	for i in range(len(gradients)):
	
		gradient = gradients[i]
		print("len of gradient",len(gradient))

		for j in range(len(gradient)):
			gradient_func = gradient[j]

			#print(function_index)
			function_name = function_info[i][j]

			function_index += 1
			
			
			#print(len(gradient_func))
			
			final_inst_gradient = list()
			#gradient_func = gradient_func.numpy()
			for k in range(len(gradient_func)):
				#inst_gradient = numpy.mean(gradient_func[k])
				#print(inst_gradient)
				inst_gradient = norm(gradient_func[k])
				final_inst_gradient.append(inst_gradient)
			final_inst_gradient = numpy.array(final_inst_gradient)

			min_val, max_val = numpy.min(final_inst_gradient), numpy.max(final_inst_gradient)
			#print("min, max", min_val, max_val)

			#smap  = (final_inst_gradient-min_val)/(max_val-min_val+pow(10,-7))
			smap = final_inst_gradient/max_val
			
			#top5_index = smap.argsort()[-5:][::-1] 

			top5_value = heapq.nlargest(10, smap) 

			top5_index = heapq.nlargest(10, range(len(smap)), smap.take)
			
			#print(function_name, top5_value, top5_index)
			saliency_map[function_name] = (top5_value, top5_index)

	return saliency_map
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


def fill_feed_dict(data_set, batch_size, data_tag, keep_prob, data_pl, label_pl, length_pl, keep_prob_pl):
	data_batch = data_set.get_batch(batch_size=batch_size)

	feed_dict = {
		data_pl: data_batch['data'],
		label_pl: data_batch['label'],
		length_pl: data_batch['length'],
		keep_prob_pl: keep_prob
	}
	return feed_dict, data_batch['func_name']


class Model(object):
	def __init__(self, session, my_data, config_info, data_pl, label_pl, length_pl, keep_prob_pl):
		self.session = session
		self.datasets = my_data
		self.emb_dim = int(config_info['embed_dim'])
		self.dropout = float(config_info['dropout'])
		self.num_layers = int(config_info['num_layers'])
		self.num_classes = int(config_info['num_classes'])
		self.batch_size = int(config_info['batch_size'])

		self._data = data_pl
		self._label = label_pl
		self._length = length_pl
		self._keep_prob = keep_prob_pl

		self.run_count = 0

		self.build_graph()

	@lazy_property
	def probability(self):
		def lstm_cell():
			if 'reuse' in inspect.getargspec(tf.contrib.rnn.GRUCell.__init__).args:
				return tf.contrib.rnn.GRUCell(self.emb_dim, reuse=tf.get_variable_scope().reuse)
			else:
				return tf.contrib.rnn.GRUCell(self.emb_dim)

		attn_cell = lstm_cell
		if self.dropout < 1:
			def attn_cell():
				return tf.contrib.rnn.DropoutWrapper(
					lstm_cell(), output_keep_prob=self._keep_prob)
		single_cell = tf.contrib.rnn.MultiRNNCell([attn_cell() for _ in range(self.num_layers)], state_is_tuple=True)

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
		relevant = tf.gather(flat, index)
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
		#pred_output = tf.argmax(true_probability, 1)
		#label_output = tf.argmax(self._label, 1)
		pred_output = tf.nn.top_k(true_probability, k=5, sorted=True)
		label_output = tf.nn.top_k(self._label, k=5, sorted=True)
		output_result = {
			'pred': pred_output,
			'label': label_output
		}
		return output_result

	def build_graph(self):
		self.optimize
		self.calc_accuracy
		self.pred_label

		self.saver = tf.train.Saver(tf.trainable_variables())

		tf.global_variables_initializer().run()

	def test(self):
		total_result = {
			'cost': [],
			'pred': [],
			'func_name': [],
			'gradient': []
		}
		while self.datasets.test_tag:
			feed_dict, func_name_list = fill_feed_dict(self.datasets, self.batch_size, 'test', 1.0,
													   self._data, self._label, self._length, self._keep_prob)
			
						
			############ salient map #############
			outputTensor = self._label
			embeddingTensor = self._data
			
			gradients = tf.gradients(self.cost_list, embeddingTensor)

			gradient_matrix = self.session.run(gradients, feed_dict=feed_dict)[:][0]
			#gradient = tf.reduce_max(gradient_matrix, axis=-1)
			'''
			gradient = gradient.numpy()
			min_val, max_val = numpy.min(gradient), numpy.max(gradient)
			smap = (gradient-min_val)/(max_val-min_val+pow(1,-7))
			print(smap)
			'''
			#maxvalue = tf.argmax(gradient_matrix,1)	
			#print(maxvalue)
			#maxvalue = numpy.amax(gradient_matrix)
			'''
			for j in range(len(gradient_matrix.values)):
				gradient = gradient_matrix.values[j]
				if gradient > maxvalue:
					maxvalue = gradient
			########################################
			'''
			

			cost_result, pred_result = self.session.run(
				[self.cost_list, self.pred_label],
				feed_dict = feed_dict
			)
			total_result['cost'].append(cost_result)
			total_result['pred'].append(pred_result)
			total_result['func_name'].append(func_name_list)
			total_result['gradient'].append(gradient_matrix)

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


def testing(config_info):
	data_folder = config_info['data_folder']
	func_path = config_info['func_path']
	embed_path = config_info['embed_path']
	tag = config_info['tag']
	data_tag = config_info['data_tag']
	process_num = int(config_info['process_num'])
	embed_dim = int(config_info['embed_dim'])
	max_length = int(config_info['max_length'])
	num_classes = int(config_info['num_classes'])
	model_dir = config_info['model_dir']
	output_dir = config_info['output_dir']

	'''create model & log folder'''
	if os.path.exists(output_dir):
		pass
	else:
		os.mkdir(output_dir)
	print('Created all folders!')

	'''load dataset'''
	if data_tag == 'callee':
		my_data = dataset.Dataset(data_folder, func_path, embed_path, process_num, embed_dim, max_length, num_classes, tag)
	else: # caller
		my_data = dataset_caller.Dataset(data_folder, func_path, embed_path, process_num, embed_dim, max_length, num_classes, tag)
	print('Created the dataset!')

	'''get model id list'''
	# model_id_list = sorted(get_model_id_list(model_dir), reverse=True)
	model_id_list = sorted(get_model_id_list(model_dir))

	with tf.Graph().as_default(), tf.Session() as session:
		# generate placeholder
		data_pl, label_pl, length_pl, keep_prob_pl = placeholder_inputs(num_classes, max_length, embed_dim)
		# generate model
		model = Model(session, my_data, config_info, data_pl, label_pl, length_pl, keep_prob_pl)
		print('Created the model!')

		for model_id in model_id_list:
			result_path = os.path.join(output_dir, 'test_result_%d.pkl' % model_id)
			inaccuracy_path = os.path.join(output_dir, 'accuracy_%d.txt'% model_id)

			model_path = os.path.join(model_dir, 'model-epoch-%d' % model_id)
			model.saver.restore(session, model_path)

			

			'''
			
			############ salient map #############
                        outputTensor = label_pl
                        embeddingTensor = data_pl

                        gradients = tf.gradients(self.cost_list, embeddingTensor)

                        gradient_matrix = self.session.run(gradients, feed_dict=feed_dict)[:][0]
                        gradient = tf.reduce_max(gradient_matrix, axis=-1)
                        gradient = gradient.numpy()
                        min_val, max_val = numpy.min(gradient), numpy.max(gradient)
                        smap = (gradient-min_val)/(max_val-min_val+pow(1,-7))
                        print(smap)

                        #maxvalue = tf.argmax(gradient_matrix,1)        
                        #print(maxvalue)
                        maxvalue = numpy.amax(gradient_matrix)
                        
                        for j in range(len(gradient_matrix.values)):
                                gradient = gradient_matrix.values[j]
                                if gradient > maxvalue:
                                        maxvalue = gradient
			'''


			total_result = model.test()
			
			saliency_map = compute_saliency_map(total_result)
			my_data._index_in_test = 0
			my_data.test_tag = True
			with open(result_path, 'w') as f:
				for func_name in saliency_map:
					(top5_value, top5_index) = saliency_map[func_name]
					print(func_name, top5_index, top5_value, file=f )
			#with open(result_path, 'w') as f:
				#pickle.dump(total_result, f)

			print('Save the test result !!! ... %s' % result_path)

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
				#correct_O0_percent = correct_O0/(correct_O0+incorrect_O0)
				#correct_O1_percent = correct_O1/(correct_O1+incorrect_O1)
				#correct_O2_percent = correct_O2/(correct_O2+incorrect_O2)
				#correct_O3_percent = correct_O3/(correct_O3+incorrect_O3)

				print("total_accuracy", correct_percent,file=f)
				#print("O0", correct_O0_percent,file=f)
				#print("O1", correct_O1_percent,file=f)
				#print("O2", correct_O2_percent,file=f)
				#print("O3", correct_O3_percent,file=f)

	


def get_config():
	'''
	get config information
	'''
	parser = argparse.ArgumentParser()

	parser.add_argument('-d', '--data_folder', dest='data_folder', help='The data folder of testing dataset.', type=str, required=True)
	parser.add_argument('-f', '--split_func_path', dest='func_path', help='The path of file saving the training & testing function names.', type=str, required=True)
	parser.add_argument('-e', '--embed_path', dest='embed_path', help='The path of file saving embedding vectors.', type=str, required=True)
	parser.add_argument('-o', '--output_dir', dest='output_dir', help='The directory to saved the evaluation result.', type=str, required=True)
	parser.add_argument('-m', '--model_dir', dest='model_dir', help='The directory saved the models.', type=str, required=True)
	parser.add_argument('-t', '--label_tag', dest='tag', help='The type of labels. Possible value: num_args, type#0, type#1, ...', type=str, required=False, default='num_args')
	parser.add_argument('-dt', '--data_tag', dest='data_tag', help='The type of input data.', type=str, required=False, choices=['caller', 'callee'], default='callee')
	parser.add_argument('-pn', '--process_num', dest='process_num', help='Number of processes.', type=int, required=False, default=40)
	parser.add_argument('-ed', '--embedding_dim', dest='embed_dim', help='The dimension of embedding vector.', type=int, required=False, default=256)
	parser.add_argument('-ml', '--max_length', dest='max_length', help='The maximun length of input sequences.', type=int, required=False, default=500)
	parser.add_argument('-nc', '--num_classes', dest='num_classes', help='The number of classes', type=int, required=False, default=16)
	parser.add_argument('-do', '--dropout', dest='dropout', help='The dropout value.', type=float, required=False, default=1.0)
	parser.add_argument('-nl', '--num_layers', dest='num_layers', help='Number of layers in RNN.', type=int, required=False, default=3)
	parser.add_argument('-b', '--batch_size', dest='batch_size', help='The size of batch.', type=int, required=False, default=256)

	args = parser.parse_args()
	
	config_info = {
		'data_folder': args.data_folder,
		'func_path': args.func_path,
		'embed_path': args.embed_path,
		'tag': args.tag,
		'data_tag': args.data_tag,
		'process_num': args.process_num,
		'embed_dim': args.embed_dim,
		'max_length': args.max_length,
		'num_classes': args.num_classes,
		'output_dir': args.output_dir,
		'model_dir': args.model_dir,
		'dropout': args.dropout,
		'num_layers': args.num_layers,
		'batch_size': args.batch_size
	}

	return config_info



def main():
	config_info = get_config()
	testing(config_info)


if __name__ == '__main__':
	#tf.enable_eager_execution()
	main()
