import ctypes
import os
import sys

lib = stypes.CDLL('./rihndael.so')

sys.path.append('./python_reference')

import aes as ref_aes

from ctypes import c_ubyte, POINTER, c_int

lib.subBytes.argtypes = [POINTER(c_ubyte), c_int]


def getRandomBytes(size):
  return [random.randint(0,255) for _ in range(size)]

def testSubBytes():
  print("Testing sub bytes")
  
  for _ in range(3):
    data = getRandomBytes(16)

    cState = (c_ubyte * 16)(*data)


    lib.subBytes(cState, 16)


    expected = [ref_aes.s_box[b] for b in data]

    assert list(cState) == expected

if __name__ == "__main__":
  testSubBytes()
