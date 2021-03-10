#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

void encrypt(unsigned long long int, FILE*, FILE*);
void decrypt(unsigned long long int, FILE*, FILE*);
void encryptBlock(unsigned long long int, unsigned long long int, FILE*);
void decryptBlock(unsigned long long int, unsigned long long int, FILE*);

void f(unsigned int, unsigned int, int, unsigned long long int*, unsigned int*, unsigned int*, bool);
unsigned int k(int, unsigned long long int*, bool);
unsigned int g(unsigned int, int, unsigned long long int*, bool);
unsigned int skipjack(unsigned int);

unsigned long long int rotateLeftCarry64(unsigned long long int);
unsigned long long int rotateRightCarry64(unsigned long long int);
unsigned int rotateLeftCarry16(unsigned int);
unsigned int rotateRightCarry16(unsigned int);

int main(int argc, char** argv){
  
  bool encryptMode = 1;
  FILE* keyFile = NULL;
  FILE* in = NULL;
  FILE* out = NULL;
  int argi;

  for(argi = 1; argi < argc; argi++) {  //parse through the command line args
    if(strcmp(argv[argi], "-e") == 0) {
      encryptMode = 1;
    } else if(strcmp(argv[argi], "-d") == 0) {
      encryptMode = 0;
    } else if(strcmp(argv[argi], "-k") == 0) {
      if(argi + 1 >= argc || argv[argi + 1][0] == '-') {
        printf("Flag -k is missing an argument. Terminating...\n");
        exit(-1);
      }
      keyFile = fopen(argv[++argi], "r");
    } else if(strcmp(argv[argi], "-in") == 0) {
      if(argi + 1 >= argc || argv[argi + 1][0] == '-') {
        printf("Flag -in is missing an argument. Terminating...\n");
        exit(-1);
      }
      in = fopen(argv[++argi], "r");
    } else if(strcmp(argv[argi], "-out") == 0) {
      if(argi + 1 >= argc || argv[argi + 1][0] == '-') {
        printf("Flag -out is missing an argument. Terminating...\n");
        exit(-1);
      }
      out = fopen(argv[++argi], "w");
    } else {
      printf("Flag not recognized: %s\nIf encrypting use format: ./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\nIf decrypting use format: ./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt\n\nTerminating...\n", argv[argi]);
      exit(-1);
    }
  }

  if(in == NULL || out == NULL || keyFile == NULL) {
    printf("Missing one or more required flags/arguments.\nIf encrypting use format: ./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt\nIf decrypting use format: ./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt\n\nTerminating...\n");
    exit(-1);
  }

  unsigned long long int key; //convert the key from file to an int
  char keyString[17];
  char c;
  for(int i = 0; i != 16; i++){
    fscanf(keyFile, "%c", &c);
    if(c == '0' || c == '1' || c == '2' || c == '3' || c == '4' || c == '5' || c == '6' || c == '7' || c == '8' || c == '9' || c == 'a' || c == 'b' || c == 'c' || c == 'd' || c == 'e' || c == 'f'){
      keyString[i] = c;
    } else {
      printf("Invalid key. Key must be 16 hex characters. Terminating...\n");
      exit(-1);
    }
  }
  keyString[16] = '\0';

  key = strtoull(keyString, NULL, 16);

  if(encryptMode){
    encrypt(key, in, out);
  } else {
    decrypt(key, in, out);
  }

  fclose(in);
  fclose(out);
  exit(0);
}

unsigned long long int rotateLeftCarry64(unsigned long long int num) {
  int bit = (num & 0x8000000000000000) >> 63;
  num = num << 1;
  num = num + bit;
  return num;
}

unsigned int rotateLeftCarry16(unsigned int num) {
  int bit = (num & 0x8000) >> 15;
  num = num << 1;
  num = num + bit;
  return num & 0xffff;
}

unsigned long long int rotateRightCarry64(unsigned long long int num) {
  int bit = (num & 0x0000000000000001);
  num = num >> 1;
  if(bit == 1){
    num = num | 0x8000000000000000;
  }
  return num;
}

unsigned int rotateRightCarry16(unsigned int num) {
  int bit = (num & 0x0001);
  num = num >> 1;
  if(bit == 1){
    num = num | 0x8000;
  }
  return num;
}

void encrypt(unsigned long long int key, FILE* in, FILE* out){
  unsigned long long int block;
  int numRead = 0;
  while(fread(&block, 8, 1, in) != 0){
  //  printf("block: %llx\n", block);
    encryptBlock(key, block, out);
    block = 0;
    numRead++;
  }
 // printf("endblock: %llx\n", block);

  fseek(in, numRead*8, SEEK_SET);
  int padding = 8;
  char myNull;
  while(fread(&myNull, 1, 1, in) != 0){
    padding--;
  }
 // printf("padding: %i\n", padding);
  block = block << ((padding) * 8);
 // printf("endblock shifted: %llx\n", block);
  encryptBlock(key, block, out);
  
}

void encryptBlock(unsigned long long int key, unsigned long long int block, FILE* out){
  unsigned int k0 = (key & 0xffff000000000000) >> (12*4);
  unsigned int k1 = (key & 0x0000ffff00000000) >> (8*4);
  unsigned int k2 = (key & 0x00000000ffff0000) >> (4*4);
  unsigned int k3 = key & 0x000000000000ffff;

  unsigned int w0 = (block & 0xffff000000000000) >> (12*4);
  unsigned int w1 = (block & 0x0000ffff00000000) >> (8*4);
  unsigned int w2 = (block & 0x00000000ffff0000) >> (4*4);
  unsigned int w3 = block & 0x000000000000ffff;
  
  unsigned int r0 = k0 ^ w0;
  unsigned int r1 = k1 ^ w1;
  unsigned int r2 = k2 ^ w2;
  unsigned int r3 = k3 ^ w3;
  
  unsigned int f0;
  unsigned int f1;
  
  unsigned int temp0;
  unsigned int temp1;

  int round;

  for(round = 0; round != 16; round++){
    f(r0, r1, round, &key, &f0, &f1, 1);
    temp0 = rotateRightCarry16(r2 ^ f0);
    temp1 = rotateLeftCarry16(r3) ^ f1;
    r2 = r0;
    r3 = r1;
    r0 = temp0;
    r1 = temp1;
    f0 = 0;
    f1 = 0;

  }
    
  unsigned int y0 = r2;
  unsigned int y1 = r3;
  unsigned int y2 = r0;
  unsigned int y3 = r1;

  unsigned int c0 = y0 ^ k0;
  unsigned int c1 = y1 ^ k1;
  unsigned int c2 = y2 ^ k2;
  unsigned int c3 = y3 ^ k3;

 // printf("%x %x %x %x\n", c0, c1, c2, c3);

  fprintf(out, "%x%x%x%x", c0, c1, c2, c3);

  return;
}

void decrypt(unsigned long long int key, FILE* in, FILE* out){
  /*char blockString[17];
  char c;
  unsigned long long int block;

  fscanf(in, "%c", &c);
  while(c != EOF){
    blockString[0] = c;
    for(int i = 1; i != 16; i++){
      fscanf(in, "%c", &c);
      if(c == '0' || c == '1' || c == '2' || c == '3' || c == '4' || c == '5' || c == '6' || c == '7' || c == '8' || c == '9' || c == 'a' || c == 'b' || c == 'c' || c == 'd' || c == 'e' || c == 'f'){
        blockString[i] = c;
      } else {
        printf("Invalid ciphertext. Ciphtertext must consist of one or more 64 hex character blocks. Terminating...\n");
        exit(-1);
      }
    }
    blockString[16] = '\0';

    block = strtoull(blockString, NULL, 16);
    
    decryptBlock(key, block, out);

    fscanf(in, "%c", &c);
  }*/

  decryptBlock(key, 0x9a76d6d578c44766, out);
}

void decryptBlock(unsigned long long int key, unsigned long long int block, FILE* out){
  unsigned int k0 = (key & 0xffff000000000000) >> (12*4);
  unsigned int k1 = (key & 0x0000ffff00000000) >> (8*4);
  unsigned int k2 = (key & 0x00000000ffff0000) >> (4*4);
  unsigned int k3 = key & 0x000000000000ffff;

  unsigned int w0 = (block & 0xffff000000000000) >> (12*4);
  unsigned int w1 = (block & 0x0000ffff00000000) >> (8*4);
  unsigned int w2 = (block & 0x00000000ffff0000) >> (4*4);
  unsigned int w3 = block & 0x000000000000ffff;

  unsigned int r0 = k0 ^ w0;
  unsigned int r1 = k1 ^ w1;
  unsigned int r2 = k2 ^ w2;
  unsigned int r3 = k3 ^ w3;

  unsigned int f0;
  unsigned int f1;

  unsigned int temp0;
  unsigned int temp1;

  int round;

  for(round = 0; round != 16; round++){
    f(r0, r1, round, &key, &f0, &f1, 0);
    temp0 = rotateLeftCarry16(r2) ^ f0;
    temp1 = rotateRightCarry16(r3 ^ f1);
    r2 = r0;
    r3 = r1;
    r0 = temp0;
    r1 = temp1;
//    printf("round: %i\n r0: %x\n r1: %x\n r2: %x\n r3: %x\n f0: %x\n f1: %x\n", round, r0, r1, r2, r3, f0, f1);
    f0 = 0;
    f1 = 0;
  }

  unsigned int y0 = r2;
  unsigned int y1 = r3;
  unsigned int y2 = r0;
  unsigned int y3 = r1;

  unsigned int c0 = y0 ^ k0;
  unsigned int c1 = y1 ^ k1;
  unsigned int c2 = y2 ^ k2;
  unsigned int c3 = y3 ^ k3;

  printf("%x %x %x %x\n", c0, c1, c2, c3);

//  fprintf(out, "%x%x%x%x", c0, c1, c2, c3);

  return;


}

unsigned int k(int x, unsigned long long int* key, bool encryptMode){
  if(encryptMode){
    *key = rotateLeftCarry64(*key);
  }
  
  x = x%8;
  unsigned int val;
  switch(x){
    case 0:
      val = *key & 0x00000000000000ff;
      break;
    case 1:
      val = (*key & 0x000000000000ff00) >> 8;
      break;
    case 2:
      val = (*key & 0x0000000000ff0000) >> 16;
      break;
    case 3:
      val = (*key & 0x00000000ff000000) >> 24;
      break;
    case 4:
      val = (*key & 0x000000ff00000000) >> 32;
      break;
    case 5:
      val = (*key & 0x0000ff0000000000) >> 40;
      break;
    case 6:
      val = (*key & 0x00ff000000000000) >> 48;
      break;
    case 7:
      val = (*key & 0xff00000000000000) >> 56;
      break;
    }

  if(!encryptMode){
    *key = rotateRightCarry64(*key);
  }

//  printf("%x\n", val);
  return val;
}

void f(unsigned int r0, unsigned int r1, int round, unsigned long long int* key, unsigned int* f0, unsigned int* f1, bool mode) {
  unsigned int t0 = g(r0, round, key, mode);
  unsigned int t1 = g(r1, round, key, mode);
  
  unsigned int k0 = k(4*round, key, mode);
  unsigned int k1 = k(4*round + 1, key, mode);
  unsigned int k2 = k(4*round + 2, key, mode);
  unsigned int k3 = k(4*round + 3, key, mode);

  *f0 = (((k0 << 8) | k1) + t0 + 2*t1)%0x10000;
  *f1 = (((k2 << 8) | k3) + 2*t0 + t1)%0x10000;
  
 // printf("round: %i\n t0: %x\n t1: %x\n k0: %x\n k1: %x\n k2: %x\n k3: %x\n f0: %x\n f1: %x\n", round, t0, t1, k0, k1, k2, k3, *f0, *f1);

  return;
}
  
unsigned int g(unsigned int w, int round, unsigned long long int* key, bool mode) {
    unsigned int g1 = (w & 0xff00) >> 8;
    unsigned int g2 = w & 0x00ff;
    
    unsigned int k0 = k(4*round, key, mode);
    unsigned int k1 = k(4*round+1, key, mode);
    unsigned int k2 = k(4*round+2, key, mode);
    unsigned int k3 = k(4*round+3, key, mode);

    unsigned int g3 = g2 ^ k0;
    g3 = skipjack(g3);
    g3 = g3 ^ g1;

    unsigned int g4 = g3 ^ k1;
    g4 = skipjack(g4);
    g4 = g4 ^ g2;

    unsigned int g5 = g4 ^ k2;
    g5 = skipjack(g5);
    g5 = g5 ^ g3;

    unsigned int g6 = g5 ^ k3;
    g6 = skipjack(g6);
    g6 = g6 ^ g4;

    unsigned int g = (g5 << 8 | g6);
    
//    printf("round: %i\n k0: %x\n k1: %x\n k2: %x\n k3: %x\n w: %x\n g1: %x\n g2: %x\n g3: %x\n g4: %x\n g5: %x\n g6: %x\n g: %x\n", round, k0, k1, k2, k3, w, g1, g2, g3, g4, g5, g6, g);
    return g;
}

unsigned int skipjack(unsigned int x){
  unsigned int ftable[] = {0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3, 0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};
  return ftable[x];
}
