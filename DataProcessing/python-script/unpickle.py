import os
import sys
import pickle

filename = sys.argv[1]
with open(filename) as f:
	data = pickle.load(f)

	print(data)