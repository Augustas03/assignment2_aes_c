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
lib.addRoundKey.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]

lib.aes_encrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
lib.aes_encrypt_block.restype = POINTER(c_ubyte * 16)

lib.aes_decrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
lib.aes_decrypt_block.restype = POINTER(c_ubyte * 16)

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
    data = bytes(getRandomBytes(16))
    cState = (c_ubyte * 16)(*data)

    lib.shiftRows(cState, 16)
    cOutput = list(cState)

    pyMatrix = [[0]*4 for _ in range(4)]
    for i in range(16):
      pyMatrix[i % 4][i // 4] = data[i]

    ref_aes.shift_rows(pyMatrix)

    expected = [0] * 16

    for row in range(4):
      for col in range(4):
        expected[col * 4 + row] = pyMatrix[row][col]

    assert cOutput == expected

  print("Testing shift rows successful")

def testMixColumns():
  print("Testing mix columns")

  for _ in range(3):
    data = bytes(getRandomBytes(16))
    cState = (c_ubyte * 16)(*data)

    lib.mixColumns(cState, 16)

    pyMatrix = [[0]*4 for _ in range(4)]
    for i in range(16):
      pyMatrix[i % 4][i // 4] = data[i]

    ref_aes.mix_columns(pyMatrix)

    expected = [0] * 16
    for col in range(4):
      for row in range(4):
        expected[col + row * 4] = pyMatrix[col][row]

    assert list(cState) == expected

  print("Testing mix columns successful")

def testAddRoundKey():
  print("Testing add round key")
  for _ in range(3):
    data = bytes(getRandomBytes(16))
    key = bytes(getRandomBytes(16))

    cState = (c_ubyte * 16)(*data)
    cKey = (c_ubyte * 16)(*key)

    lib.addRoundKey(cState, cKey, 16)

    pyMatrix = ref_aes.bytes2matrix(data)
    keyMatrix = ref_aes.bytes2matrix(key)
    ref_aes.add_round_key(pyMatrix, keyMatrix)
    expected = list(ref_aes.matrix2bytes(pyMatrix))

    assert list(cState) == expected

  print("Testing add round key successful")

def testFullCycle128bit():
    print("Testing full cycle of 128 encryption/decryption")
    for _ in range(3):
        plaintext = bytes(getRandomBytes(16))
        key = bytes(getRandomBytes(16))

        cPt = (c_ubyte * 16)(*plaintext)
        cKey = (c_ubyte * 16)(*key)

        cCipherPointer = lib.aes_encrypt_block(cPt, cKey, 16)
        cCiphertext = list(cCipherPointer.contents)

        cCtInput = (c_ubyte * 16)(*cCiphertext)
        cDecPtr = lib.aes_decrypt_block(cCtInput, cKey, 16)
        cRecovered = list(cDecPtr.contents)

        assert cRecovered == list(plaintext)

    print("128-bit test encryption/decryption successful")

def testFullCycle256bit():
    print("Testing full cycle of 256 encryption/decryption")

    lib.aes_encrypt_block.restype = POINTER(c_ubyte * 32)
    lib.aes_decrypt_block.restype = POINTER(c_ubyte * 32)

    for _ in range(3):

        plaintext = bytes(getRandomBytes(32))
        key = bytes(getRandomBytes(32))

        cPt = (c_ubyte * 32)(*plaintext)
        cKey = (c_ubyte * 32)(*key)


        cCipherPointer = lib.aes_encrypt_block(cPt, cKey, 32)
        cCiphertext = list(cCipherPointer.contents)

        cCtInput = (c_ubyte * 32)(*cCiphertext)
        cDecPtr = lib.aes_decrypt_block(cCtInput, cKey, 32)
        cRecovered = list(cDecPtr.contents)

        assert cRecovered == list(plaintext)

    print("256-bit test encryption/decryption successful")

def testFullCycle512bit():
    print("Testing full cycle of 512 encryption/decryption")

    lib.aes_encrypt_block.restype = POINTER(c_ubyte * 64)
    lib.aes_decrypt_block.restype = POINTER(c_ubyte * 64)

    for _ in range(3):

        plaintext = bytes(getRandomBytes(64))
        key = bytes(getRandomBytes(64))

        cPt = (c_ubyte * 64)(*plaintext)
        cKey = (c_ubyte * 64)(*key)

        cCipherPointer = lib.aes_encrypt_block(cPt, cKey, 64)
        cCiphertext = list(cCipherPointer.contents)

        cCtInput = (c_ubyte * 64)(*cCiphertext)
        cDecPtr = lib.aes_decrypt_block(cCtInput, cKey, 64)
        cRecovered = list(cDecPtr.contents)

        assert cRecovered == list(plaintext)

    print("512-bit test encryption/decryption successful")

if __name__ == "__main__":
  testSubBytes()
  testShiftRows()
  testMixColumns()
  testAddRoundKey()
  testFullCycle128bit()
  testFullCycle256bit()
  testFullCycle512bit()
