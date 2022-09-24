#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGS_FILENAME_SZ 52 
#define SALT_SZ 32

typedef struct {
  unsigned char write;
  unsigned char type;
  char salt[SALT_SZ];
  char filename[ARGS_FILENAME_SZ];
} pwgen_args;

void function(int a, int b, int c) {
   char buffer1[5];
   char buffer2[10];
   int *ret;

   ret = buffer1 + 12;
   (*ret) += 8;
}

void main() {
  int x=0;
  pwgen_args args;
  int y=0;

  memset(&args, 0, sizeof(pwgen_args));
  strcpy(args.filename, "testtttttttttttttttttttttttttttttttttttttttttttttttttttk");
  printf("%d", sizeof(pwgen_args));
  // trying to cpy 56 chars in 52 space.
  // this leaks 2 chars to `x`'s address space.
  // 56-52 = 4 bytes overflow
  // question: why isn't all 4 bytes are leaked to `x?`
  // answer: struct pwgen_args is of size 86. 
  //         86%4 = 2
  //         since a word is 4 bytes, `args` has 2 bytes padding at the end.

  x = 123;
  // function(1,2,3);
  // x = 1;
  // printf("%d\n",x);
}