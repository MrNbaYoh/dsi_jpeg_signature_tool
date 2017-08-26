#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <stdlib.h>
#include "dsi.h"

void weird_func(unsigned int block[4])
{
  unsigned int tmp = block[3];
  block[3] = *((uint64_t*)block+1) >> 31;
  block[2] = *(uint64_t*)(&block[1]) >> 31;
  block[1] = *(uint64_t*)block >> 31;
  block[0] *= 2;
  if(tmp >> 31)
    block[0] ^= 0x87;
}

void xor_block(unsigned int block[4], unsigned int xor_block[4])
{
    for(int i = 0; i < 4; i++)
        block[i] ^= xor_block[i];
}

int main(int argc, char** argv)
{
  printf(".::DSi JPEG Signature Tool by Nba_Yoh/MrNbaYoh - based on neimod's taddy tool::.\n");

  if(argc < 4 || argc > 5)
  {
    printf("Usage: dsi_sign_jpeg <in.jpg>  <out.jpg> <key.bin> [iv.bin]\n");
    return -1;
  }
  
  srand(time(0));

  dsi_context ctr_ctx;
  dsi_context ccm_ctx;
  
  unsigned char nonce[12];
  unsigned char key[16];

  FILE* f = 0;
  if(argc == 4)
    for(int i = 0; i < 3; i++)
	  ((unsigned int*)nonce)[i] = rand();
  else
  {
    f = fopen(argv[4], "rb");
    if(!f)
    {
      printf("Error while opening the IV file!\n");
      return -1;    
    }
    fread(nonce, 1, 12, f);
    fclose(f);
  }

  f = fopen(argv[3], "rb");
  if(!f)
  {
    printf("Error while opening the key file!\n");
    return -1;    
  }
  fread(key, 1, 16, f);
  fclose(f);

  f = fopen(argv[1], "rb");
  if(!f)
  {
    printf("Error while opening the input jpeg file!\n");
    return -1;
  }

  printf("IV: ");
  for(int i = 0; i < 12; i++)
    printf("%X ", nonce[i]); 
  printf("\n");
     
  fseek(f, 0, SEEK_END);
  unsigned int size = (unsigned int)ftell(f);
  printf("FILE SIZE: %x\n", size);
  unsigned int total_size = (size+0xF)&0xFFFFFFF0;
  printf("TOTAL SIZE: %x\n", total_size);

  unsigned char* in_buf = malloc(total_size);
  rewind(f);
  fread(in_buf, 1, size, f);
  memset(&in_buf[0x18A], 0, 0x1C);

  unsigned char block[16];
  memset(block, 0, 16);

  dsi_init_ctr(&ctr_ctx, key, block);
  dsi_crypt_ctr_block(&ctr_ctx, block, block);

  weird_func((unsigned int*)block);


  unsigned char final_bytes = ((size-1) & 0xF) + 1;   
  if(final_bytes == 0x10)
  {
    xor_block((unsigned int*)block, (unsigned int*)&in_buf[size-final_bytes]);
  }
  else  
  {
    unsigned char tmp_block[16];
    memset(tmp_block, 0, 16);
    memcpy(&tmp_block[16-final_bytes], &in_buf[size-final_bytes], final_bytes);
    tmp_block[15-final_bytes] = 0x80;
    weird_func((unsigned int*)block);
    xor_block((unsigned int*)block, (unsigned int*)tmp_block);    
  }

  memcpy(&in_buf[size-final_bytes], block, 16);
  dsi_init_ccm(&ccm_ctx, key, 16, 0, total_size, nonce);

  unsigned char* out_buf = malloc(total_size);
  unsigned char mac[16];
  memset(mac, 0, 16);
  dsi_encrypt_ccm(&ccm_ctx, in_buf, out_buf, total_size, mac);
  
  printf("MAC: ");
  for(int i = 0; i < 16; i++)
    printf("%X ", mac[i]);
  printf("\n");
  
  rewind(f);
  fread(in_buf, 1, size, f);
  fclose(f);
  
  f = fopen(argv[2], "wb");
  if(!f)
  {
    printf("Error while opening the output file!\n");
    free(in_buf);
    return -1;    
  }
  memcpy(&in_buf[0x18A], nonce, 0xC);
  memcpy(&in_buf[0x196], mac, 0x10);
  fwrite(in_buf, 1, size, f);
  fclose(f);
  free(in_buf);
}
