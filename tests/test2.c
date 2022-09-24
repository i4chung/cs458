#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
  int x = 0;
  char buffer[5];

  memset(buffer, 0, sizeof(buffer));
  
  printf("%d:%s\n", x, buffer);
  
  snprintf(buffer,12,"%s", "1111111111111");

  printf("%d:%s\n",x, buffer);
  printf("%x:%x\n",x, *buffer);

  return 0;
}