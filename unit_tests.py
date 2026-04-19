import ctypes
import os
import sys
import random

lib = ctypes.CDLL('./rijndael.so')

sys.path.append('./python_reference')

import aes as ref_aes

from ctypes import c_ubyte, POINTER, c_int

lib.subBytes.argtypes = [POINTER(c_ubyte), c_int]
lib.shiftRows.argtypes = [POINTER(c_ubyte), c_int]
lib.mixColumns.argtypes = [POINTER(c_ubyte), c_int]

def getRandomBytes(size):
  return [random.randint(0,255) for _ in range(size)]

def testSubBytes():
  print("Testing sub bytes")

  for _ in range(3):
    data = bytes(getRandomBytes(16))

    cState = (c_ubyte * 16)(*data)
    lib.subBytes(cState, 16)
    cOutput = list(cState)

    pyMatrix = ref_aes.bytes2matrix(data)
    ref_aes.sub_bytes(pyMatrix)

    expected = list(ref_aes.matrix2bytes(pyMatrix))

    assert cOutput == expected, f"Mismatch C output: {cOutput}, Python output: {expected}"

  print("Testing sub bytes successful")

def testShiftRows():
  print("Testing shift rows")

  for _ in range(3):
    data = getRandomBytes(16)
    cState = (c_ubyte * 16)(*data)

    lib.shiftRows(cState, 16)


if __name__ == "__main__":
  testSubBytes()
