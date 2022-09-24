#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define THING "456"

int main(){
  char * str[2];
  str[0] = "define_test";
  str[1] = NULL;
  execve(str[0], str, NULL);

  return 0;
}