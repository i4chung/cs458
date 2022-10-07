#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
  
  char* dir;
  
  dir = getenv("HOME");

  printf("%s\n", dir);
  return 0;
}