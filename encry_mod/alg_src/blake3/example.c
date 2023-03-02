#include "blake3.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main() 
{
  // Initialize the hasher.
  blake3_hasher hasher;
  uint8_t key[BLAKE3_KEY_LEN]={
  0xb4,0xf5,0x92,0x04,0x96,0x00,0x29,0x0f,
  0x2c,0x50,0xa8,0x0f,0x8b,0xae,0x24,0x03,
  0x8d,0xcf,0xae,0x02,0x7a,0x63,0xeb,0x0c,
  0xd1,0x49,0x18,0x0e,0xd1,0x65,0xa8,0x09};
  blake3_hasher_init_keyed(&hasher，key);
  uint8_t output[BLAKE3_OUT_LEN] = {0};

  // Read input bytes from stdin.
  unsigned char buf[4];
  int cnt = 0;
  while (cnt <= 0xF) 
  {
      // ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
      // if (n > 0) 
      // {
        blake3_hasher_update(&hasher,&cnt , 4);
        blake3_hasher_finalize(&hasher, output, 2);
        for (size_t i = 0; i < 2; i++) 
        {
          printf("%02x", output[i]);
        }
        printf("\n");
      // } 
      // else if (n == 0) 
      // {
      //   break; // end of file
      // } else {
      //   fprintf(stderr, "read failed: %s\n", strerror(errno));
      //   exit(1);
      // }
      cnt++;
  }

  // Finalize the hash. BLAKE3_OUT_LEN is the default output length, 32 bytes.
  // blake3_hasher_finalize(&hasher, output, 2);

  // // Print the hash as hexadecimal.
  // for (size_t i = 0; i < 2; i++) 
  // {
  //   printf("%02x", output[i]);
  // }
  // printf("\n");
  return 0;
}
