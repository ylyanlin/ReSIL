"""
Obtain the ground truth for each function using LLVM
"""

import re
import os
import sys
import commands
import openpyxl

from collections import defaultdict



if __name__ == '__main__':
  
    bin_path = sys.argv[1]
    
    #target_dir = sys.argv[2]

    llvm_folder = "../gt"
    os.system("mkdir -p "+llvm_folder)
    orig_bin = os.path.basename(bin_path)
    llvm_path = orig_bin + "-llvm-info.txt"


    #opt_path = "/home/yanlin/llvm-toolchain/llvm-10.0.0.build/bin"
    cmd = "cp " + bin_path + " " + orig_bin
    os.system(cmd)

    
    cmd = "extract-bc " + orig_bin
    os.system(cmd)

    cmd = "llc  -g-truth " + " -filetype=obj " +  orig_bin+".bc" +" -o " +orig_bin+".o"  + " 2>" + llvm_path
    os.system(cmd)

    cmd = "cp " + llvm_path +" "   + llvm_folder +"/" + llvm_path
    os.system(cmd)



    
