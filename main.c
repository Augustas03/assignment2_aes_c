#include <stdio.h>
#include <stdlib.h>

#include "rijndael.h"

void print_block(unsigned char *block, aes_block_size_t block_size) {
int numOfColumns = (int)block_size / 4;

for (int i = 0; i < 4; i++) {
    for (int j = 0; j < numOfColumns; j++) {
      unsigned char value = block_access(block, i, j, block_size);

      // Print spaces before small numbers to ensure that everything is aligned
      // and looks nice
      if (value < 10) printf(" ");

      if (value < 100) printf(" ");

      printf("%02x ", (unsigned int)value);
    }
    printf("\n");
  }
}

int main() {
	unsigned char plaintext[64] = {
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
    };
	unsigned char key[64] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
    };
	printf("DEBUG: Starting Encrypt...\n");
  unsigned char *ciphertext = aes_encrypt_block(plaintext, key, AES_BLOCK_512);
	printf("DEBUG: Encrypt Finished.\n");
  unsigned char *recovered_plaintext = aes_decrypt_block(ciphertext, key, AES_BLOCK_512);

  printf("############ ORIGINAL PLAINTEXT ###########\n");
  print_block(plaintext, AES_BLOCK_512);

  printf("\n\n################ CIPHERTEXT ###############\n");
  print_block(ciphertext, AES_BLOCK_512);

  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_block(recovered_plaintext, AES_BLOCK_512);

  free(ciphertext);
  free(recovered_plaintext);

  return 0;
}
