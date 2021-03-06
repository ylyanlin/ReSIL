# ReSIL

This is the open-source component of our paper "ReSIL: Revivifying Function Signature Inference using Deep Learning with Domain-Specific Knowledge", published in the 12th ACM Conference on Data and Application Security and Privacy  (CODASPY) 2022. 
# Disclaimer
If, for some weird reason, you think running this code broke your device, you get to keep both pieces.

# There are three components:

# Ground Truth Collection
It is development as an LLVM pass, which will collect the groundtruth of the function signature, including the number and types if arguments for each function and indirect caller.
	# In order to collect the ground truth you need to use wllvm to compile the source code. Please go to https://github.com/travitch/whole-program-llvm to find how to compile source code with wllvm and get the whole bitcode.

	# Collect the ground truth based on the generated bitcode.

	* *Compile LLVM*

	cd ReSIL/GroundTruth
	mkdir install
	cd install

	-DCMAKE_BUILD_TYPE=Release cmake ../llvm-7.0.0.src
	make -j4
	make install

	* *Ground truth collection*
	you can use the following command to get the ground truth:

	llc -g-truth  -filetype=obj test.bc -o test.clang.o 2> test-llvm.txt

	Where test.bc is the bitcode file generated by wllvm and extract-bc; test-llvm.txt has the ground truth for each function and indirect caller.


# Data Processing to extract instruction bytes from a binary
This relies on the static binary analysis tool typearmor-master
## Installation
To build the static analysis pass, we first need to build Dyninst. 

Note that the following was tested in a Ubuntu Desktop 18.04 LTS. 

First install some packages:

    sudo apt-get install build-essential cmake 
    sudo apt-get install libboost-all-dev libelf-dev libiberty-dev

Next, download and build Dyninst. 

    cd
    wget https://github.com/dyninst/dyninst/archive/v9.3.1.tar.gz
    tar -zxvf v9.3.1.tar.gz
    cd dyninst-9.3.1
    mkdir install
    cd install
    cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`
    make -j2
    make install

Next, build TypeArmor:

	cd typearmor-master
    # update DYNINST_ROOT in ./envsetup.sh
    . build_envsetup
    cd static
    make
    make install
    cd ..
    cd di-opt
    make
    make install

## There are main four scripts in folder python-scripts which will extract information from a binary.
### get groundtruth collected by LLVM 
python extract-gt.py ../../example
### extract instruction bytes and function signature from a binary
python get_pickles.py --binary_folder ../example/  --output_dir ../clean_pickles --replace_call 0 --insert_ins 0 --only_integer 0 --filer_out 0
### Insert our special summarized instructions to the instruction bytes, it relies on the static analysis tool typearmor
python insert_ins.py --binary_folder ../example/ --output_dir ../insert_ins_pickles --replace_call 0 --insert_ins 1  --only_integer 0 --filer_out 0 --pickle-folder ../clean_pickles
### correct the label for callees which actually do not use all arguments, it relies on typearmor and the groundtruth obtained by LLVM
python fix_unread.py ../example/ ../insert_ins_pickles/cat-clang-O2.pkl ../final_pickles ../gt


# Use Deep learning to lean function Signature
Please refer to the ReadMe file in https://github.com/shensq04/EKLAVYA to run the code







