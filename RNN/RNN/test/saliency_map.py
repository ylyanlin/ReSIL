import os
import sys
import pickle
import numpy
import heapq


def compute_saliency_map(filename):
	with open(filename,'rb') as f:
		total_result = pickle.load(f)

		function_info = total_result['func_name']
		gradients =  total_result['gradient']
		function_index = 0

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
					inst_gradient = numpy.mean(gradient_func[k])
					#print(inst_gradient)
					final_inst_gradient.append(inst_gradient)
				final_inst_gradient = numpy.array(final_inst_gradient)

				min_val, max_val = numpy.min(final_inst_gradient), numpy.max(final_inst_gradient)
				#print("min, max", min_val, max_val)

				smap  = (final_inst_gradient-min_val)/(max_val-min_val+pow(10,-7))
				
				#top5_index = smap.argsort()[-5:][::-1] 

				top5_value = heapq.nlargest(5, smap) 

				top5_index = heapq.nlargest(5, range(len(smap)), smap.take)
				
				print(function_name, top5_value, top5_index)

				'''
				max_smap = 0
				for t in final_inst_gradient:
					smap = (t-min_val)/(max_val-min_val+pow(10,-7))
					if smap > max_smap:
						max_smap = smap
				print("smap",max_smap)
				'''

				'''
				for k in range(len(gradient_func)):
					inst_gradient = gradient_func[k])[0]
					print('each instruction', len(gradient_func[k]) )
				'''

			'''
			gradient = gradient.numpy()
			min_val, max_val = numpy.min(gradient), numpy.max(gradient)
			smap = (gradient-min_val)/(max_val-min_val+pow(1,-7))
			print(smap)
			'''
			#for each instruction
			#for j  in range(len(gradient)):


if __name__ == '__main__':
	filename = sys.argv[1]
	compute_saliency_map(filename)